package adaptiveadmission

import (
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
	}
	for _, tc := range cases {
		if got := tc.r.String(); got != tc.want {
			t.Errorf("RejectReason(%d).String() = %q, want %q", tc.r, got, tc.want)
		}
	}
}
