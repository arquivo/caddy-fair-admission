package adaptiveadmission

import (
	"container/heap"
	"context"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func mustGrantWithin(t *testing.T, tk *Ticket, d time.Duration, msg string) {
	t.Helper()
	select {
	case <-tk.Granted():
	case <-time.After(d):
		t.Fatal(msg)
	}
}

func mustNotGrantWithin(t *testing.T, tk *Ticket, d time.Duration, msg string) {
	t.Helper()
	select {
	case <-tk.Granted():
		t.Fatal(msg)
	case <-time.After(d):
	}
}

// --- priority + FIFO ordering, and acquire-before-pop --------------------

func TestScheduler_AcquireBeforePop_HigherScoreArrivingLaterWinsOverEarlierLowerScore(t *testing.T) {
	c := NewFixedController(1)
	c.Acquire(1) // hold the only slot so nothing can be dispatched yet

	s := NewScheduler(QueueConfig{MaxSize: 10}, c)
	s.Start()
	defer s.Stop()

	low, reason := s.Enqueue(1)
	if reason != RejectNone {
		t.Fatalf("Enqueue(low) rejected: %v", reason)
	}
	high, reason := s.Enqueue(10)
	if reason != RejectNone {
		t.Fatalf("Enqueue(high) rejected: %v", reason)
	}

	// Both tickets are queued while capacity is still held; nothing should
	// be granted yet.
	mustNotGrantWithin(t, low, 50*time.Millisecond, "low-score ticket granted before capacity was freed")
	mustNotGrantWithin(t, high, 10*time.Millisecond, "high-score ticket granted before capacity was freed")

	// Freeing the one slot lets the dispatch loop acquire it and pop the
	// *current* head -- which by now is the higher-score ticket, even
	// though it arrived second.
	c.Release(1, time.Millisecond, 200, false)

	mustGrantWithin(t, high, time.Second, "higher-score ticket never granted after capacity freed")
	mustNotGrantWithin(t, low, 30*time.Millisecond, "lower-score ticket granted before its turn (only one slot was freed)")

	// Drain fully before Stop(): otherwise the dispatch loop is left parked
	// inside Controller.Acquire (waiting for a unit that will never free),
	// which Stop() cannot interrupt -- it only wakes the scheduler's own
	// empty-queue wait, not a capacity wait.
	c.Release(1, time.Millisecond, 200, false)
	mustGrantWithin(t, low, time.Second, "low-score ticket never granted after high's capacity freed")
	c.Release(1, time.Millisecond, 200, false)
}

func TestScheduler_FIFOWithinEqualScore(t *testing.T) {
	c := NewFixedController(1)
	c.Acquire(1)

	s := NewScheduler(QueueConfig{MaxSize: 10}, c)
	s.Start()
	defer s.Stop()

	first, reason := s.Enqueue(5)
	if reason != RejectNone {
		t.Fatalf("Enqueue(first) rejected: %v", reason)
	}
	second, reason := s.Enqueue(5)
	if reason != RejectNone {
		t.Fatalf("Enqueue(second) rejected: %v", reason)
	}

	c.Release(1, time.Millisecond, 200, false)
	mustGrantWithin(t, first, time.Second, "earlier-arriving same-score ticket never granted")
	mustNotGrantWithin(t, second, 30*time.Millisecond, "later same-score ticket granted out of FIFO order")

	c.Release(1, time.Millisecond, 200, false)
	mustGrantWithin(t, second, time.Second, "second same-score ticket never granted after its turn")

	// Drain fully before defer Stop() runs (see the comment in the
	// acquire-before-pop test above for why this is required).
	c.Release(1, time.Millisecond, 200, false)
}

// --- rejection reasons -----------------------------------------------------

func TestScheduler_RejectsQueueFull(t *testing.T) {
	c := NewFixedController(1)
	c.Acquire(1) // consume the only slot, permanently for this test

	// Deliberately never Start(): a real dispatch loop would block forever
	// inside Controller.Acquire since nothing ever Releases here, and
	// Stop() cannot interrupt an in-flight Acquire. This test only exercises
	// Enqueue's synchronous depth check.
	s := NewScheduler(QueueConfig{MaxSize: 2}, c)

	if _, reason := s.Enqueue(1); reason != RejectNone {
		t.Fatalf("1st Enqueue rejected: %v", reason)
	}
	if _, reason := s.Enqueue(1); reason != RejectNone {
		t.Fatalf("2nd Enqueue rejected: %v", reason)
	}
	if _, reason := s.Enqueue(1); reason != RejectQueueFull {
		t.Fatalf("3rd Enqueue reason = %v, want RejectQueueFull", reason)
	}
}

func TestScheduler_RejectsQueueWaitExceeded(t *testing.T) {
	c := NewFixedController(1)
	// Seed a mean latency of 100ms without touching inFlight bookkeeping --
	// ReleaseUnused would go negative, so drive it through the window
	// directly (package-internal test, same pattern as capacity_test.go's
	// fillWindow).
	fillWindow(c, 5, 100*time.Millisecond, false, false)

	// Projected wait at depth d = d * 100ms / limit(1): depth=0..3 -> 0,
	// 100, 200, 300ms (all under a 350ms timeout); depth=4 -> 400ms (over).
	// The dispatch loop is never started, so depth only grows via Enqueue.
	s := NewScheduler(QueueConfig{MaxSize: 100, WaitTimeout: 350 * time.Millisecond}, c)

	for i := 0; i < 4; i++ {
		if _, reason := s.Enqueue(1); reason != RejectNone {
			t.Fatalf("Enqueue #%d rejected: %v (depth-%d projected wait should not exceed timeout yet)", i, reason, i)
		}
	}
	if _, reason := s.Enqueue(1); reason != RejectQueueWaitExceeded {
		t.Fatalf("Enqueue at depth 4 reason = %v, want RejectQueueWaitExceeded", reason)
	}
}

func TestScheduler_NoRejectionWithoutLatencyData(t *testing.T) {
	// No Release() calls yet -> MeanLatency() is 0 -> the wait-projection
	// check must never reject (there's nothing to project from), even with
	// a very small WaitTimeout.
	c := NewFixedController(1)
	c.Acquire(1)

	s := NewScheduler(QueueConfig{MaxSize: 100, WaitTimeout: time.Nanosecond}, c)
	for i := 0; i < 10; i++ {
		if _, reason := s.Enqueue(1); reason != RejectNone {
			t.Fatalf("Enqueue #%d rejected (%v) despite no latency data yet", i, reason)
		}
	}
}

// --- composition with the capacity controller under concurrent load -------

func TestScheduler_ConcurrentLoad_NeverExceedsLimitAndServesEverything(t *testing.T) {
	const limit = 4
	const goroutines = 32
	const iterationsEach = 50

	c := NewFixedController(limit)
	s := NewScheduler(QueueConfig{MaxSize: goroutines * iterationsEach}, c)
	s.Start()
	defer s.Stop()

	var inFlight int64
	var maxObserved int64
	var served int64
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < iterationsEach; i++ {
				score := float64((seed + i) % 7)
				tk, reason := s.Enqueue(score)
				if reason != RejectNone {
					t.Errorf("unexpected rejection under bounded load: %v", reason)
					return
				}
				<-tk.Granted()

				n := atomic.AddInt64(&inFlight, 1)
				for {
					cur := atomic.LoadInt64(&maxObserved)
					if n <= cur || atomic.CompareAndSwapInt64(&maxObserved, cur, n) {
						break
					}
				}
				atomic.AddInt64(&inFlight, -1)
				atomic.AddInt64(&served, 1)

				c.Release(1, time.Microsecond, 200, false)
			}
		}(g)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("deadlock or lost wakeup: goroutines did not finish within 30s")
	}

	if got := atomic.LoadInt64(&maxObserved); got > limit {
		t.Errorf("observed %d concurrently-granted tickets, want <= limit (%d)", got, limit)
	}
	want := int64(goroutines * iterationsEach)
	if got := atomic.LoadInt64(&served); got != want {
		t.Errorf("served %d tickets, want %d (every enqueued request must eventually be granted)", got, want)
	}
}

// --- Start/Stop lifecycle --------------------------------------------------

func TestScheduler_Stop_ReleasesUnusedCapacityAndDrainsQueuedTickets(t *testing.T) {
	c := NewFixedController(2)
	s := NewScheduler(QueueConfig{MaxSize: 10}, c)
	s.Start()

	tk, reason := s.Enqueue(1)
	if reason != RejectNone {
		t.Fatalf("Enqueue rejected: %v", reason)
	}
	mustGrantWithin(t, tk, time.Second, "ticket never granted with spare capacity")
	c.Release(1, time.Millisecond, 200, false)

	s.Stop()
	if got := c.InFlight(); got != 0 {
		t.Errorf("InFlight() after Stop = %d, want 0 (unused acquired capacity must be released back)", got)
	}
}

func TestScheduler_Stop_SafeWithEmptyQueue(t *testing.T) {
	c := NewFixedController(1)
	s := NewScheduler(QueueConfig{MaxSize: 1}, c)
	s.Start()
	s.Stop()
	if got := c.InFlight(); got != 0 {
		t.Errorf("InFlight() after Stop with nothing enqueued = %d, want 0", got)
	}
}

// --- RejectReason.String() ---------------------------------------------------

func TestRejectReason_String(t *testing.T) {
	cases := []struct {
		r    RejectReason
		want string
	}{
		{RejectNone, "none"},
		{RejectQueueFull, "queue_full"},
		{RejectQueueWaitExceeded, "queue_wait_exceeded"},
		{RejectQueueTimedOut, "queue_timed_out"},
		{RejectClientGone, "client_gone"},
		{RejectEvicted, "evicted"},
	}
	for _, tc := range cases {
		if got := tc.r.String(); got != tc.want {
			t.Errorf("RejectReason(%d).String() = %q, want %q", tc.r, got, tc.want)
		}
	}
}

// --- aging -------------------------------------------------------------------

// fakeClock drives Scheduler.now so tests control each ticket's enqueue time.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) set(d time.Duration, base time.Time) {
	c.mu.Lock()
	c.t = base.Add(d)
	c.mu.Unlock()
}

func newSchedulerWithClock(cfg QueueConfig, c *Controller) (*Scheduler, *fakeClock) {
	s := NewScheduler(cfg, c)
	clock := &fakeClock{t: s.epoch}
	s.now = clock.now
	return s, clock
}

func TestScheduler_Aging_LongWaitingLowerScoreOvertakesFresherHigherScore(t *testing.T) {
	cases := []struct {
		name        string
		highArrival time.Duration
		wantFirst   string
	}{
		// Rate 5/s: the score-50 ticket gains 10 points (the gap) after 2s.
		{"high arrives after 1s: high still first", 1 * time.Second, "high"},
		{"high arrives after 3s: low has aged past it", 3 * time.Second, "low"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewFixedController(1)
			c.Acquire(1)
			s, clock := newSchedulerWithClock(QueueConfig{MaxSize: 10, AgingRate: 5}, c)
			s.Start()
			defer s.Stop()

			low, _ := s.Enqueue(50)
			clock.set(tc.highArrival, s.epoch)
			high, _ := s.Enqueue(60)

			first, second := high, low
			if tc.wantFirst == "low" {
				first, second = low, high
			}
			c.Release(1, time.Millisecond, 200, false)
			mustGrantWithin(t, first, time.Second, tc.wantFirst+" ticket not granted first")
			mustNotGrantWithin(t, second, 30*time.Millisecond, "second ticket granted with only one slot freed")
			c.Release(1, time.Millisecond, 200, false)
			mustGrantWithin(t, second, time.Second, "second ticket never granted")
			c.Release(1, time.Millisecond, 200, false)
		})
	}
}

// grantsBeforeLowScoreServed reproduces the p85 starvation scenario at the
// scheduler level: one score-50 ticket is queued, then a fresh score-60
// ticket arrives every 100ms (fake clock) for each of maxRounds single-slot
// dispatches. It returns the round at which the score-50 ticket was granted,
// or -1 if every round went to a score-60 ticket.
func grantsBeforeLowScoreServed(t *testing.T, agingRate float64, maxRounds int) int {
	t.Helper()
	c := NewFixedController(1)
	c.Acquire(1)
	s, clock := newSchedulerWithClock(QueueConfig{MaxSize: 10, AgingRate: agingRate}, c)
	s.Start()

	low, _ := s.Enqueue(50)
	var pending *Ticket
	defer func() {
		// Withdraw whatever is still queued, then free the held slot so the
		// dispatch loop's lookahead Acquire can return and Stop can finish.
		s.Cancel(low)
		if pending != nil {
			s.Cancel(pending)
		}
		c.Release(1, time.Millisecond, 200, false)
		s.Stop()
		if got := c.InFlight(); got != 0 {
			t.Errorf("InFlight() after Stop = %d, want 0", got)
		}
	}()

	for round := 1; round <= maxRounds; round++ {
		clock.set(time.Duration(round)*100*time.Millisecond, s.epoch)
		high, _ := s.Enqueue(60)
		pending = high
		c.Release(1, time.Millisecond, 200, false)
		select {
		case <-low.Granted():
			return round
		case <-high.Granted():
			pending = nil
		case <-time.After(time.Second):
			t.Fatalf("round %d: nothing granted after freeing a slot", round)
		}
	}
	return -1
}

func TestScheduler_Aging_PreventsStarvationUnderContinuousHigherScoreArrivals(t *testing.T) {
	// Gap 10 at 5 points/s: the score-50 ticket ties a fresh score-60 one
	// after 2s (round 20) and wins the tie on arrival order.
	if got := grantsBeforeLowScoreServed(t, 5, 100); got != 20 {
		t.Errorf("score-50 ticket granted at round %d, want 20", got)
	}
}

func TestScheduler_NoAging_StrictPriorityStarvesLowerScore(t *testing.T) {
	// Documents the default (aging off): strict score order, the p85 load
	// test's starvation. queue_timeout is what bounds such a wait.
	if got := grantsBeforeLowScoreServed(t, 0, 100); got != -1 {
		t.Errorf("score-50 ticket granted at round %d, want never with aging off", got)
	}
}

// --- Wait: deadline, client gone, and the grant/cancel race ---------------

func TestScheduler_Wait_DeadlineRejectsAndRemovesTicket(t *testing.T) {
	c := NewFixedController(1)
	c.Acquire(1) // nothing can be granted until the test releases
	s := NewScheduler(QueueConfig{MaxSize: 10, WaitTimeout: 50 * time.Millisecond}, c)
	s.Start()

	tk, reason := s.Enqueue(1)
	if reason != RejectNone {
		t.Fatalf("Enqueue rejected: %v", reason)
	}
	start := time.Now()
	if got := s.Wait(context.Background(), tk); got != RejectQueueTimedOut {
		t.Fatalf("Wait = %v, want RejectQueueTimedOut", got)
	}
	if waited := time.Since(start); waited < 50*time.Millisecond {
		t.Errorf("Wait returned after %v, before the 50ms deadline", waited)
	}
	if got := s.Depth(); got != 0 {
		t.Errorf("Depth() after timeout = %d, want 0 (ticket removed)", got)
	}
	mustNotGrantWithin(t, tk, 20*time.Millisecond, "timed-out ticket was granted")

	// The freed slot must go to the next ticket, not to the removed one.
	next, _ := s.Enqueue(1)
	c.Release(1, time.Millisecond, 200, false)
	if got := s.Wait(context.Background(), next); got != RejectNone {
		t.Fatalf("Wait(next) = %v, want RejectNone", got)
	}
	c.Release(1, time.Millisecond, 200, false)
	s.Stop()
	if got := c.InFlight(); got != 0 {
		t.Errorf("InFlight() after Stop = %d, want 0", got)
	}
}

func TestScheduler_Wait_ClientGoneWhileQueuedRemovesTicketWithoutLeakingCapacity(t *testing.T) {
	c := NewFixedController(1)
	c.Acquire(1)
	s := NewScheduler(QueueConfig{MaxSize: 10}, c)
	s.Start()

	tk, _ := s.Enqueue(1)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	if got := s.Wait(ctx, tk); got != RejectClientGone {
		t.Fatalf("Wait = %v, want RejectClientGone", got)
	}
	if got := s.Depth(); got != 0 {
		t.Errorf("Depth() after client gone = %d, want 0", got)
	}

	c.Release(1, time.Millisecond, 200, false)
	s.Stop()
	if got := c.InFlight(); got != 0 {
		t.Errorf("InFlight() after Stop = %d, want 0", got)
	}
	if got := c.window.total; got != 1 {
		t.Errorf("outcome window total = %d, want 1 (a cancelled ticket records no outcome)", got)
	}
}

func TestScheduler_Wait_ClientGoneAfterGrantReleasesCapacityUnused(t *testing.T) {
	c := NewFixedController(1)
	s := NewScheduler(QueueConfig{MaxSize: 10}, c)
	s.Start()

	tk, _ := s.Enqueue(1)
	mustGrantWithin(t, tk, time.Second, "ticket never granted with free capacity")
	if s.Cancel(tk) {
		t.Fatal("Cancel of an already-granted ticket returned true")
	}

	// Granted and cancelled are both ready: whichever select case runs,
	// the unit must go back unused and the request must not be dispatched.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := s.Wait(ctx, tk); got != RejectClientGone {
		t.Fatalf("Wait = %v, want RejectClientGone", got)
	}

	s.Stop()
	if got := c.InFlight(); got != 0 {
		t.Errorf("InFlight() after Stop = %d, want 0 (granted capacity given back)", got)
	}
	if got := c.window.total; got != 0 {
		t.Errorf("outcome window total = %d, want 0 (nothing was dispatched)", got)
	}
}

// raceOutcomes counts how the requests in raceWaits ended.
type raceOutcomes struct {
	admitted, timedOut, gone, evicted, rejected int64
}

// raceWaits races grants against client cancellations and queue timeouts
// (and, with cfg.EvictLowest, evictions): some requests are cancelled at
// random moments, often the same instant the dispatch loop pops them, and a
// short queue_timeout expires others. Every request must end exactly once,
// admissions must never exceed limit, and once everything drains no
// capacity may be left held. Run with -race.
func raceWaits(t *testing.T, cfg QueueConfig, limit int) raceOutcomes {
	t.Helper()
	const goroutines = 40
	const iterationsEach = 50

	c := NewFixedController(limit)
	s := NewScheduler(cfg, c)
	s.Start()

	var inFlight, maxObserved int64
	var out raceOutcomes
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			for i := 0; i < iterationsEach; i++ {
				tk, reason := s.Enqueue(float64(rng.Intn(100)))
				if reason != RejectNone {
					atomic.AddInt64(&out.rejected, 1)
					continue
				}
				ctx, cancel := context.WithCancel(context.Background())
				if rng.Intn(3) == 0 {
					time.AfterFunc(time.Duration(rng.Intn(1500))*time.Microsecond, cancel)
				}
				switch s.Wait(ctx, tk) {
				case RejectNone:
					if tk.wasEvicted() {
						t.Error("ticket both granted and evicted")
					}
					n := atomic.AddInt64(&inFlight, 1)
					for {
						cur := atomic.LoadInt64(&maxObserved)
						if n <= cur || atomic.CompareAndSwapInt64(&maxObserved, cur, n) {
							break
						}
					}
					time.Sleep(time.Duration(rng.Intn(300)) * time.Microsecond)
					atomic.AddInt64(&inFlight, -1)
					atomic.AddInt64(&out.admitted, 1)
					c.Release(1, time.Microsecond, 200, false)
				case RejectQueueTimedOut:
					atomic.AddInt64(&out.timedOut, 1)
				case RejectClientGone:
					atomic.AddInt64(&out.gone, 1)
				case RejectEvicted:
					atomic.AddInt64(&out.evicted, 1)
				default:
					t.Error("Wait returned an Enqueue-only reason")
				}
				cancel()
			}
		}(int64(g))
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("deadlock or lost wakeup: goroutines did not finish within 30s")
	}

	s.Stop()
	if got := c.InFlight(); got != 0 {
		t.Errorf("InFlight() after Stop = %d, want 0 (capacity leaked or double-released)", got)
	}
	if got := s.Depth(); got != 0 {
		t.Errorf("Depth() after all requests ended = %d, want 0", got)
	}
	if got := atomic.LoadInt64(&maxObserved); got > int64(limit) {
		t.Errorf("observed %d concurrently admitted, want <= limit (%d)", got, limit)
	}
	if total := out.admitted + out.timedOut + out.gone + out.evicted + out.rejected; total != goroutines*iterationsEach {
		t.Errorf("requests ended = %d, want %d", total, goroutines*iterationsEach)
	}
	return out
}

func TestScheduler_Wait_ConcurrentCancelsAndTimeouts_NoLeakNoOverAdmission(t *testing.T) {
	out := raceWaits(t, QueueConfig{MaxSize: 2000, WaitTimeout: 2 * time.Millisecond, AgingRate: 50}, 3)
	if out.rejected != 0 || out.evicted != 0 {
		t.Errorf("rejected=%d evicted=%d, want 0 with a queue that never fills", out.rejected, out.evicted)
	}
	if out.admitted == 0 || out.timedOut+out.gone == 0 {
		t.Errorf("race not exercised: %+v", out)
	}
}

// --- eviction from a full queue (QueueConfig.EvictLowest) -------------------

// enqueueAll enqueues one ticket per score, failing the test on a rejection.
func enqueueAll(t *testing.T, s *Scheduler, scores ...float64) []*Ticket {
	t.Helper()
	tickets := make([]*Ticket, len(scores))
	for i, score := range scores {
		tk, reason := s.Enqueue(score)
		if reason != RejectNone {
			t.Fatalf("Enqueue(%v) rejected: %v", score, reason)
		}
		tickets[i] = tk
	}
	return tickets
}

func TestScheduler_EvictLowest_BetterArrivalEvictsLastTicket(t *testing.T) {
	// Never started: these tests only exercise Enqueue's synchronous checks
	// (see TestScheduler_RejectsQueueFull).
	s := NewScheduler(QueueConfig{MaxSize: 3, EvictLowest: true}, NewFixedController(1))
	queued := enqueueAll(t, s, 5, 1, 3)

	if _, reason := s.Enqueue(2); reason != RejectNone {
		t.Fatalf("Enqueue(2) on a full queue = %v, want it to evict the score-1 ticket", reason)
	}
	for i, tk := range queued {
		if want := i == 1; tk.wasEvicted() != want {
			t.Errorf("ticket %d (score %v) evicted = %v, want %v", i, tk.Score, tk.wasEvicted(), want)
		}
	}
	if got := s.Depth(); got != 3 {
		t.Errorf("Depth() = %d, want 3 (one out, one in)", got)
	}
	if got := s.Wait(context.Background(), queued[1]); got != RejectEvicted {
		t.Errorf("Wait(evicted ticket) = %v, want RejectEvicted", got)
	}
}

func TestScheduler_EvictLowest_ArrivalNotBetterThanLastIsRejected(t *testing.T) {
	for _, score := range []float64{1, 0} {
		t.Run(fmt.Sprintf("score %v", score), func(t *testing.T) {
			s := NewScheduler(QueueConfig{MaxSize: 2, EvictLowest: true}, NewFixedController(1))
			queued := enqueueAll(t, s, 5, 1)
			// Equal to the last ticket's key loses on arrival order (FIFO).
			if _, reason := s.Enqueue(score); reason != RejectQueueFull {
				t.Fatalf("Enqueue(%v) = %v, want RejectQueueFull", score, reason)
			}
			for _, tk := range queued {
				if tk.wasEvicted() {
					t.Errorf("score-%v ticket evicted by an arrival that isn't better", tk.Score)
				}
			}
		})
	}
}

func TestScheduler_EvictLowest_NewestOfEqualLastKeysIsEvicted(t *testing.T) {
	s := NewScheduler(QueueConfig{MaxSize: 4, EvictLowest: true}, NewFixedController(1))
	queued := enqueueAll(t, s, 1, 5, 1, 1)
	if _, reason := s.Enqueue(2); reason != RejectNone {
		t.Fatalf("Enqueue(2) = %v, want RejectNone", reason)
	}
	for i, tk := range queued {
		if want := i == 3; tk.wasEvicted() != want {
			t.Errorf("ticket %d evicted = %v, want %v (the newest score-1 ticket is served last)", i, tk.wasEvicted(), want)
		}
	}
}

func TestScheduler_EvictLowest_ComparesAgedKeysNotScores(t *testing.T) {
	// Rate 5/s: the score-50 ticket queued at 0s has the key of a fresh
	// score 65 at 3s, so the fresh score-60 ticket is the one served last.
	s, clock := newSchedulerWithClock(QueueConfig{MaxSize: 2, EvictLowest: true, AgingRate: 5}, NewFixedController(1))
	old := enqueueAll(t, s, 50)[0]
	clock.set(3*time.Second, s.epoch)
	fresh := enqueueAll(t, s, 60)[0]

	if _, reason := s.Enqueue(61); reason != RejectNone {
		t.Fatalf("Enqueue(61) = %v, want RejectNone", reason)
	}
	if old.wasEvicted() || !fresh.wasEvicted() {
		t.Errorf("evicted: score-50 (aged) = %v, score-60 (fresh) = %v; want false, true", old.wasEvicted(), fresh.wasEvicted())
	}
}

func TestScheduler_EvictLowest_WaitExceededArrivalEvictsNothing(t *testing.T) {
	c := NewFixedController(1)
	s := NewScheduler(QueueConfig{MaxSize: 3, WaitTimeout: 150 * time.Millisecond, EvictLowest: true}, c)
	// Filled before any latency data, so nothing is projected yet.
	queued := enqueueAll(t, s, 5, 5, 1)
	// After evicting one, the arrival would join behind 2 tickets, a
	// projected 200ms wait, over the 150ms timeout.
	fillWindow(c, 5, 100*time.Millisecond, false, false)

	if _, reason := s.Enqueue(2); reason != RejectQueueWaitExceeded {
		t.Fatalf("Enqueue(2) = %v, want RejectQueueWaitExceeded", reason)
	}
	if queued[2].wasEvicted() || s.Depth() != 3 {
		t.Errorf("a rejected arrival evicted a ticket (Depth() = %d)", s.Depth())
	}
}

func TestScheduler_EvictLowest_AllProjectionDoesNotCountTheVictim(t *testing.T) {
	c := NewFixedController(1)
	s := NewScheduler(QueueConfig{MaxSize: 3, WaitTimeout: 250 * time.Millisecond, EvictLowest: true}, c)
	queued := enqueueAll(t, s, 5, 5, 1)
	// Behind the 2 tickets left after evicting one: 200ms, under the 250ms
	// timeout. Counting the victim too would project 300ms.
	fillWindow(c, 5, 100*time.Millisecond, false, false)

	if _, reason := s.Enqueue(2); reason != RejectNone {
		t.Fatalf("Enqueue(2) = %v, want RejectNone", reason)
	}
	if !queued[2].wasEvicted() {
		t.Error("score-1 ticket not evicted")
	}
}

// --- projected wait from the tickets ahead (QueueConfig.ProjectAhead) ------

func TestScheduler_ProjectAhead_HighScoreJoinsDeepLowScoreQueue(t *testing.T) {
	cases := []struct {
		projectAhead bool
		wantHigh     RejectReason
	}{
		{false, RejectQueueWaitExceeded},
		{true, RejectNone},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("ProjectAhead=%v", tc.projectAhead), func(t *testing.T) {
			c := NewFixedController(1)
			fillWindow(c, 5, 100*time.Millisecond, false, false)
			// 100ms per queued ticket ahead (limit 1): 4 low-score tickets
			// make a 400ms queue, over the 350ms timeout.
			s := NewScheduler(QueueConfig{MaxSize: 100, WaitTimeout: 350 * time.Millisecond, ProjectAhead: tc.projectAhead}, c)
			enqueueAll(t, s, 1, 1, 1, 1)

			if _, reason := s.Enqueue(10); reason != tc.wantHigh {
				t.Errorf("Enqueue(10) behind 4 low scores = %v, want %v", reason, tc.wantHigh)
			}
			if _, reason := s.Enqueue(1); reason != RejectQueueWaitExceeded {
				t.Errorf("Enqueue(1) behind 4+ tickets = %v, want RejectQueueWaitExceeded", reason)
			}
		})
	}
}

func TestScheduler_ProjectAhead_CountsEqualKeysAsAhead(t *testing.T) {
	c := NewFixedController(1)
	fillWindow(c, 5, 100*time.Millisecond, false, false)
	s := NewScheduler(QueueConfig{MaxSize: 100, WaitTimeout: 250 * time.Millisecond, ProjectAhead: true}, c)
	// The third score-5 ticket joined behind the other two (200ms); a
	// fourth would be behind three (300ms). The score-1 ticket never counts.
	enqueueAll(t, s, 1, 5, 5, 5)
	if _, reason := s.Enqueue(5); reason != RejectQueueWaitExceeded {
		t.Errorf("Enqueue(5) behind 3 score-5 tickets = %v, want RejectQueueWaitExceeded", reason)
	}
}

// TestTicketHeap_LastAndCountAhead checks the heap walks against a sorted
// copy of the queue, over random keys with many ties.
func TestTicketHeap_LastAndCountAhead(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for round := 0; round < 200; round++ {
		var h ticketHeap
		n := 1 + rng.Intn(50)
		for i := 0; i < n; i++ {
			heap.Push(&h, &Ticket{key: float64(rng.Intn(10)), seq: uint64(i)})
		}
		sorted := append([]*Ticket(nil), h...)
		sort.Slice(sorted, func(i, j int) bool { return ticketHeap(sorted).Less(i, j) })

		if got, want := h.last(), sorted[n-1]; got != want {
			t.Fatalf("round %d: last() = key %v seq %d, want key %v seq %d", round, got.key, got.seq, want.key, want.seq)
		}
		for key := -1.0; key <= 10; key++ {
			want := 0
			for _, tk := range sorted {
				if tk.key >= key {
					want++
				}
			}
			if got := h.countAhead(key, 0); got != want {
				t.Fatalf("round %d: countAhead(%v) = %d, want %d", round, key, got, want)
			}
		}
	}
}

// TestScheduler_Wait_EvictionRacesGrantsCancelsAndTimeouts adds eviction to
// raceWaits: a small full queue makes arrivals evict queued tickets at the
// same moments the dispatch loop pops them, timers fire and clients go away.
// A ticket is evicted or granted, never both, and an evicted ticket owns no
// capacity.
func TestScheduler_Wait_EvictionRacesGrantsCancelsAndTimeouts(t *testing.T) {
	out := raceWaits(t, QueueConfig{MaxSize: 4, WaitTimeout: 2 * time.Millisecond, AgingRate: 50, EvictLowest: true, ProjectAhead: true}, 3)
	if out.admitted == 0 || out.evicted == 0 {
		t.Errorf("race not exercised: %+v", out)
	}
}

// TestScheduler_Wait_EvictedTicketReportedEvictedWhateverElseIsReady pins
// the fallback after a lost Cancel: an evicted ticket whose deadline or
// context is also ready must still report RejectEvicted, never be served.
func TestScheduler_Wait_EvictedTicketReportedEvictedWhateverElseIsReady(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	cases := []struct {
		name        string
		waitTimeout time.Duration
		ctx         context.Context
	}{
		{"deadline", time.Nanosecond, context.Background()},
		{"client gone", 0, cancelled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewFixedController(1)
			// Repeated because select picks among the ready cases at random.
			for i := 0; i < 100; i++ {
				// Never started, so nothing is ever granted.
				s := NewScheduler(QueueConfig{MaxSize: 1, WaitTimeout: tc.waitTimeout, EvictLowest: true}, c)
				victim := enqueueAll(t, s, 1, 2)[0]
				if got := s.Wait(tc.ctx, victim); got != RejectEvicted {
					t.Fatalf("iteration %d: Wait = %v, want RejectEvicted", i, got)
				}
				if got := c.InFlight(); got != 0 {
					t.Fatalf("iteration %d: InFlight() = %d, want 0", i, got)
				}
			}
		})
	}
}

// BenchmarkTicketHeap_LastAndCountAhead measures the two walks an arrival
// at a full queue makes under Scheduler.mu with evict_lowest and ahead
// projection, for an arrival in the middle of the queue, at queue sizes
// around and well above what deployments configure.
func BenchmarkTicketHeap_LastAndCountAhead(b *testing.B) {
	for _, size := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			rng := rand.New(rand.NewSource(1))
			var h ticketHeap
			for i := 0; i < size; i++ {
				heap.Push(&h, &Ticket{key: float64(rng.Intn(100)), seq: uint64(i)})
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = h.last()
				_ = h.countAhead(50, 0)
			}
		})
	}
}
