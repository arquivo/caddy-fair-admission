package adaptiveadmission

import (
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- outcomeWindow / histogram -----------------------------------------------

func TestOutcomeWindow_PercentileApproximatesSortedSamples(t *testing.T) {
	w := newOutcomeWindow(1000)
	for i := 1; i <= 1000; i++ {
		w.record(time.Duration(i)*time.Millisecond, false, false)
	}
	// p95 of 1..1000ms should land close to 950ms; histogram quantization
	// (256 exponential buckets over 1ms-60s) gives a few percent of slack.
	got := w.percentile(0.95)
	want := 950 * time.Millisecond
	if diff := math.Abs(float64(got - want)); diff > float64(80*time.Millisecond) {
		t.Errorf("percentile(0.95) = %v, want close to %v (diff %v)", got, want, diff)
	}
}

func TestOutcomeWindow_EmptyWindowPercentileIsZero(t *testing.T) {
	w := newOutcomeWindow(10)
	if got := w.percentile(0.95); got != 0 {
		t.Errorf("percentile on empty window = %v, want 0", got)
	}
	if got := w.timeoutRate(); got != 0 {
		t.Errorf("timeoutRate on empty window = %v, want 0", got)
	}
	if got := w.errorRate(); got != 0 {
		t.Errorf("errorRate on empty window = %v, want 0", got)
	}
}

func TestOutcomeWindow_EvictionIsExactAndO1(t *testing.T) {
	w := newOutcomeWindow(3)
	w.record(10*time.Millisecond, true, false) // evicted first
	w.record(20*time.Millisecond, false, true)
	w.record(30*time.Millisecond, false, false)
	if w.total != 3 || w.timeouts != 1 || w.errors != 1 {
		t.Fatalf("after 3 records: total=%d timeouts=%d errors=%d, want 3/1/1", w.total, w.timeouts, w.errors)
	}

	// A 4th record evicts the oldest (10ms, timedOut=true) exactly.
	w.record(40*time.Millisecond, false, false)
	if w.total != 3 {
		t.Errorf("total after eviction = %d, want 3 (window size)", w.total)
	}
	if w.timeouts != 0 {
		t.Errorf("timeouts after evicting the only timeout = %d, want 0", w.timeouts)
	}
	if w.errors != 1 {
		t.Errorf("errors after eviction = %d, want 1 (untouched)", w.errors)
	}
}

// --- Controller: Fixed --------------------------------------------------------

func TestFixedController_NeverChangesLimit(t *testing.T) {
	c := NewFixedController(5)
	c.Start() // no-op for fixed
	defer c.Stop()

	c.Acquire(1)
	c.Release(1, 10*time.Millisecond, 200, false)
	if got := c.Limit(); got != 5 {
		t.Errorf("Limit() = %d, want 5 (fixed controller must never change)", got)
	}
}

func TestFixedController_AcquireBlocksUntilReleaseFreesCapacity(t *testing.T) {
	c := NewFixedController(1)
	c.Acquire(1)

	acquired := make(chan struct{})
	go func() {
		c.Acquire(1)
		close(acquired)
	}()

	select {
	case <-acquired:
		t.Fatal("second Acquire returned before capacity was released")
	case <-time.After(50 * time.Millisecond):
	}

	c.Release(1, time.Millisecond, 200, false)

	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("second Acquire never woke up after Release freed capacity")
	}
}

// --- Controller: concurrency stress (no over-admission, no lost wakeups) ----

func TestController_ConcurrencyStress_NoOverAdmissionNoLostWakeups(t *testing.T) {
	const limit = 8
	const goroutines = 64
	const iterationsEach = 200

	c := NewFixedController(limit)

	var inFlight int64
	var maxObserved int64
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterationsEach; i++ {
				c.Acquire(1)

				n := atomic.AddInt64(&inFlight, 1)
				for {
					cur := atomic.LoadInt64(&maxObserved)
					if n <= cur || atomic.CompareAndSwapInt64(&maxObserved, cur, n) {
						break
					}
				}

				atomic.AddInt64(&inFlight, -1)
				c.Release(1, time.Microsecond, 200, false)
			}
		}()
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
		t.Errorf("observed %d in-flight requests, want <= limit (%d): over-admission", got, limit)
	}
	if got := c.InFlight(); got != 0 {
		t.Errorf("InFlight() after all goroutines finished = %d, want 0", got)
	}
}

// --- Controller: adaptive adjustment branches --------------------------------

func newTestAdaptiveController(target time.Duration) *Controller {
	return NewAdaptiveController(AdaptiveConfig{
		MinConcurrency:       1,
		InitialConcurrency:   100,
		MaxConcurrency:       1000,
		TargetP95:            target,
		TimeoutRateThreshold: 0.05,
		ErrorRateThreshold:   0.05,
	})
}

func fillWindow(c *Controller, n int, latency time.Duration, timedOut, isError bool) {
	for i := 0; i < n; i++ {
		c.window.record(latency, timedOut, isError)
	}
}

func TestAdjust_NoSamplesYet_NoChange(t *testing.T) {
	c := newTestAdaptiveController(800 * time.Millisecond)
	c.adjust(time.Unix(1000, 0))
	if got := c.Limit(); got != 100 {
		t.Errorf("Limit() with no samples = %d, want unchanged 100", got)
	}
}

// neutralLatency sits strictly between 0.5x and 1x the 800ms target used by
// newTestAdaptiveController, so timeout-rate/error-rate branch tests don't
// accidentally also satisfy (or narrowly avoid) a p95 branch.
const neutralLatency = 600 * time.Millisecond

func TestAdjust_TimeoutRateShrink(t *testing.T) {
	c := newTestAdaptiveController(800 * time.Millisecond)
	// 10% timeout rate, above the 5% threshold.
	fillWindow(c, 90, neutralLatency, false, false)
	fillWindow(c, 10, neutralLatency, true, false)

	now := time.Unix(1000, 0)
	c.adjust(now)

	want := int(math.Round(100 * timeoutShrinkMultiplier))
	if got := c.Limit(); got != want {
		t.Errorf("Limit() after timeout-rate shrink = %d, want %d", got, want)
	}
}

func TestAdjust_TimeoutRateShrink_RespectsCooldown(t *testing.T) {
	c := newTestAdaptiveController(800 * time.Millisecond)
	fillWindow(c, 90, neutralLatency, false, false)
	fillWindow(c, 10, neutralLatency, true, false)

	now := time.Unix(1000, 0)
	c.adjust(now)
	afterFirst := c.Limit()

	// Still within the 60s cooldown: must not shrink again.
	c.adjust(now.Add(30 * time.Second))
	if got := c.Limit(); got != afterFirst {
		t.Errorf("Limit() shrank again within cooldown: got %d, want unchanged %d", got, afterFirst)
	}

	// Cooldown elapsed: shrinks again.
	c.adjust(now.Add(61 * time.Second))
	want := int(math.Round(float64(afterFirst) * timeoutShrinkMultiplier))
	if got := c.Limit(); got != want {
		t.Errorf("Limit() after cooldown elapsed = %d, want %d", got, want)
	}
}

func TestAdjust_ErrorRateShrink(t *testing.T) {
	c := newTestAdaptiveController(800 * time.Millisecond)
	fillWindow(c, 90, neutralLatency, false, false)
	fillWindow(c, 10, neutralLatency, false, true)

	c.adjust(time.Unix(1000, 0))
	want := int(math.Round(100 * errorShrinkMultiplier))
	if got := c.Limit(); got != want {
		t.Errorf("Limit() after error-rate shrink = %d, want %d", got, want)
	}
}

func TestAdjust_ErrorRateShrink_RespectsCooldown(t *testing.T) {
	c := newTestAdaptiveController(800 * time.Millisecond)
	fillWindow(c, 90, neutralLatency, false, false)
	fillWindow(c, 10, neutralLatency, false, true)

	now := time.Unix(1000, 0)
	c.adjust(now)
	afterFirst := c.Limit()

	c.adjust(now.Add(10 * time.Second)) // within 30s cooldown
	if got := c.Limit(); got != afterFirst {
		t.Errorf("Limit() shrank again within cooldown: got %d, want unchanged %d", got, afterFirst)
	}

	c.adjust(now.Add(31 * time.Second))
	want := int(math.Round(float64(afterFirst) * errorShrinkMultiplier))
	if got := c.Limit(); got != want {
		t.Errorf("Limit() after cooldown elapsed = %d, want %d", got, want)
	}
}

func TestAdjust_P95HardShrink(t *testing.T) {
	target := 800 * time.Millisecond
	c := newTestAdaptiveController(target)
	// Well above 2x target (1600ms) -- clear of histogram quantization.
	fillWindow(c, 100, 4*time.Second, false, false)

	c.adjust(time.Unix(1000, 0))
	want := int(math.Round(100 * p95HardShrinkMultiplier))
	if got := c.Limit(); got != want {
		t.Errorf("Limit() after p95>2x shrink = %d, want %d", got, want)
	}
}

func TestAdjust_P95SoftShrink(t *testing.T) {
	target := 800 * time.Millisecond
	c := newTestAdaptiveController(target)
	// Between target (800ms) and 2x target (1600ms), clear of both
	// boundaries: 1200ms.
	fillWindow(c, 100, 1200*time.Millisecond, false, false)

	c.adjust(time.Unix(1000, 0))
	want := int(math.Round(100 * p95SoftShrinkMultiplier))
	if got := c.Limit(); got != want {
		t.Errorf("Limit() after p95>target shrink = %d, want %d", got, want)
	}
}

func TestAdjust_P95Shrink_HardAndSoftShareOneCooldown(t *testing.T) {
	target := 800 * time.Millisecond
	c := newTestAdaptiveController(target)
	fillWindow(c, 100, 4*time.Second, false, false) // triggers hard shrink

	now := time.Unix(1000, 0)
	c.adjust(now)
	afterHard := c.Limit()

	// Reset window contents to now show a "soft" p95 condition instead --
	// still within the shared cooldown, must not fire again.
	c.window = newOutcomeWindow(defaultWindowSize)
	fillWindow(c, 100, 1200*time.Millisecond, false, false)
	c.adjust(now.Add(10 * time.Second))
	if got := c.Limit(); got != afterHard {
		t.Errorf("soft p95 branch fired within the hard branch's cooldown: got %d, want unchanged %d", got, afterHard)
	}

	c.adjust(now.Add(31 * time.Second))
	want := int(math.Round(float64(afterHard) * p95SoftShrinkMultiplier))
	if got := c.Limit(); got != want {
		t.Errorf("Limit() after shared cooldown elapsed = %d, want %d", got, want)
	}
}

func TestAdjust_Grow_NoCooldown(t *testing.T) {
	target := 800 * time.Millisecond
	c := newTestAdaptiveController(target)
	// Well below 0.5x target (400ms): 100ms.
	fillWindow(c, 100, 100*time.Millisecond, false, false)

	now := time.Unix(1000, 0)
	c.adjust(now)
	want1 := int(math.Round(100 * growMultiplier))
	if got := c.Limit(); got != want1 {
		t.Errorf("Limit() after first grow = %d, want %d", got, want1)
	}

	// Grow has no cooldown: an immediately-following tick with the same
	// condition grows again.
	c.window = newOutcomeWindow(defaultWindowSize)
	fillWindow(c, 100, 100*time.Millisecond, false, false)
	c.adjust(now.Add(time.Second))
	want2 := int(math.Round(float64(want1) * growMultiplier))
	if got := c.Limit(); got != want2 {
		t.Errorf("Limit() after second immediate grow = %d, want %d (no cooldown)", got, want2)
	}
}

func TestAdjust_Grow_MakesForwardProgressWhenRoundingWouldStall(t *testing.T) {
	c := NewAdaptiveController(AdaptiveConfig{
		MinConcurrency:     1,
		InitialConcurrency: 1,
		MaxConcurrency:     100,
		TargetP95:          800 * time.Millisecond,
	})
	fillWindow(c, 10, 100*time.Millisecond, false, false)
	c.adjust(time.Unix(1000, 0))
	if got := c.Limit(); got != 2 {
		t.Errorf("Limit() after grow from 1 = %d, want 2 (forced +1 when rounding would stall)", got)
	}
}

func TestAdjust_PriorityChain_TimeoutBeatsErrorAndP95(t *testing.T) {
	target := 800 * time.Millisecond
	c := newTestAdaptiveController(target)
	// All three conditions true at once: 10% timeouts, 10% errors, p95 well
	// above 2x target.
	fillWindow(c, 80, 4*time.Second, false, false)
	fillWindow(c, 10, 4*time.Second, true, false)
	fillWindow(c, 10, 4*time.Second, false, true)

	c.adjust(time.Unix(1000, 0))
	want := int(math.Round(100 * timeoutShrinkMultiplier))
	if got := c.Limit(); got != want {
		t.Errorf("Limit() with all branches triggered = %d, want %d (timeout-rate takes priority)", got, want)
	}
}

func TestAdjust_ClampsToMinMax(t *testing.T) {
	c := NewAdaptiveController(AdaptiveConfig{
		MinConcurrency:     20,
		InitialConcurrency: 25,
		MaxConcurrency:     30,
		TargetP95:          800 * time.Millisecond,
	})
	// Severe timeout rate would shrink 25 -> 15, but MinConcurrency clamps
	// it to 20.
	fillWindow(c, 50, 10*time.Millisecond, true, false)
	c.adjust(time.Unix(1000, 0))
	if got := c.Limit(); got != 20 {
		t.Errorf("Limit() after shrink below min = %d, want clamped to MinConcurrency (20)", got)
	}
}

func TestAdjust_TargetZeroDisablesP95Branches(t *testing.T) {
	c := NewAdaptiveController(AdaptiveConfig{
		MinConcurrency:     1,
		InitialConcurrency: 100,
		MaxConcurrency:     1000,
		// TargetP95 left at zero.
	})
	fillWindow(c, 100, 10*time.Second, false, false) // would be a huge p95 if target were set
	c.adjust(time.Unix(1000, 0))
	if got := c.Limit(); got != 100 {
		t.Errorf("Limit() with TargetP95=0 = %d, want unchanged 100 (p95 branches disabled)", got)
	}
}

// --- Controller: growth wakes waiters immediately ----------------------------

func TestAdjust_GrowWakesBlockedAcquireImmediately(t *testing.T) {
	c := NewAdaptiveController(AdaptiveConfig{
		MinConcurrency:     1,
		InitialConcurrency: 1,
		MaxConcurrency:     10,
		TargetP95:          800 * time.Millisecond,
	})
	c.Acquire(1) // saturate the limit of 1

	acquired := make(chan struct{})
	go func() {
		c.Acquire(1)
		close(acquired)
	}()

	select {
	case <-acquired:
		t.Fatal("Acquire returned before the limit was raised")
	case <-time.After(50 * time.Millisecond):
	}

	fillWindow(c, 10, 100*time.Millisecond, false, false) // triggers grow
	c.adjust(time.Unix(1000, 0))

	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("blocked Acquire never woke up after a limit increase")
	}
}

// --- Controller: Start/Stop lifecycle ----------------------------------------

func TestController_FixedStartStop_IsNoOp(t *testing.T) {
	c := NewFixedController(3)
	c.Start()
	c.Stop()
	c.Stop() // safe to call twice
}

func TestController_AdaptiveStartStop_StopsBackgroundLoop(t *testing.T) {
	c := NewAdaptiveController(AdaptiveConfig{
		MinConcurrency:     1,
		InitialConcurrency: 10,
		MaxConcurrency:     20,
		TargetP95:          800 * time.Millisecond,
		AdjustInterval:     10 * time.Millisecond,
	})
	c.Start()
	time.Sleep(50 * time.Millisecond) // let the loop tick a few times harmlessly
	c.Stop()
	c.Stop() // safe to call twice
}

// --- shrink/grow/clampInt helpers ---------------------------------------------

func TestShrink_NeverGoesBelowOne(t *testing.T) {
	if got := shrink(1, 0.1); got != 1 {
		t.Errorf("shrink(1, 0.1) = %d, want floored at 1", got)
	}
}

func TestClampInt(t *testing.T) {
	cases := []struct{ v, min, max, want int }{
		{5, 0, 10, 5},
		{-5, 0, 10, 0},
		{15, 0, 10, 10},
	}
	for _, tc := range cases {
		if got := clampInt(tc.v, tc.min, tc.max); got != tc.want {
			t.Errorf("clampInt(%d, %d, %d) = %d, want %d", tc.v, tc.min, tc.max, got, tc.want)
		}
	}
}
