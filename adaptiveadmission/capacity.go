// Package adaptiveadmission implements the http.handlers.adaptive_admission
// Caddy module: capacity control, priority queue/scheduler, load balancing,
// and dispatch (REQUIREMENTS.md §4.4-§4.7).
//
// This file (capacity.go) is deliberately standalone and not yet wired into
// ServeHTTP (that lands in a later phase) — it implements the bounded-
// concurrency admission primitive in isolation first, since it is the
// subtlest piece of the whole system (a bounded-wake condition variable plus
// a self-tuning adjustment loop) and needs its own thorough test coverage
// before anything else depends on it.
package adaptiveadmission

import (
	"math"
	"sync"
	"time"
)

// ControllerKind selects which capacity-control strategy a Controller uses
// (§4.4). Both kinds share the same Acquire/Release bounded-concurrency
// primitive; only ControllerAdaptive runs a background adjustment loop that
// changes its own limit over time.
type ControllerKind int

const (
	ControllerFixed ControllerKind = iota
	ControllerAdaptive
)

// String renders k as the same "fixed"/"adaptive" spelling used by
// ControllerConfig.Kind (config.go), for admin API output (admin.go, §4.10).
func (k ControllerKind) String() string {
	switch k {
	case ControllerFixed:
		return controllerKindFixed
	case ControllerAdaptive:
		return controllerKindAdaptive
	default:
		return "unknown"
	}
}

// AdaptiveConfig is the tuning surface for an adaptive Controller (§4.4).
type AdaptiveConfig struct {
	MinConcurrency     int
	InitialConcurrency int
	MaxConcurrency     int

	// TargetP95 is the latency the adjustment loop tries to keep p95 near.
	// Zero disables all p95-driven branches (shrink-on->target,
	// shrink-on->2x-target, grow-on-<0.5x-target) — only timeout-rate and
	// error-rate can still adjust the limit.
	TargetP95            time.Duration
	TimeoutRateThreshold float64
	ErrorRateThreshold   float64

	// AdjustInterval is how often the adjustment loop re-evaluates the
	// limit. Zero/negative uses defaultAdjustInterval (30s, §4.4).
	AdjustInterval time.Duration

	// WindowSize is how many of the most recent Release() outcomes
	// (latency, timeout, error) feed the rolling p95/timeout-rate/
	// error-rate calculations the adjustment loop reads from. Zero/negative
	// uses defaultWindowSize (100, matching §8's "100-sample deque"
	// starting point). This is a count-based rolling window, not reset on
	// the AdjustInterval tick — growth/shrink decisions always react to the
	// most recent WindowSize outcomes regardless of how many ticks have
	// elapsed since they were recorded.
	WindowSize int
}

const (
	defaultAdjustInterval = 30 * time.Second
	defaultWindowSize     = 100

	// Cooldowns and multipliers, exactly as specified in REQUIREMENTS.md
	// §4.4. After a shrink triggered by a given branch, that same branch
	// cannot fire again until its cooldown elapses; a different branch is
	// unaffected by another branch's cooldown. The two p95 branches (>2x
	// target, >target) share one cooldown timer since the spec states no
	// distinct cooldown for the milder branch ("port exact
	// thresholds/multipliers as-is" — there is nothing to distinguish them
	// by, so treating them as one degradation signal with one cooldown is
	// the literal reading).
	timeoutShrinkCooldown = 60 * time.Second
	errorShrinkCooldown   = 30 * time.Second
	p95ShrinkCooldown     = 30 * time.Second

	timeoutShrinkMultiplier = 0.60
	errorShrinkMultiplier   = 0.75
	p95HardShrinkMultiplier = 0.70 // p95 > 2x target
	p95SoftShrinkMultiplier = 0.85 // p95 > target
	growMultiplier          = 1.05 // p95 < 0.5x target, no cooldown
)

// --- Rolling latency/outcome window -----------------------------------------
//
// §8 explicitly calls out the Python system's per-tick full re-sort of a
// 100-sample deque as a design smell to not repeat, requiring an
// incrementally-maintained percentile structure instead. This is a fixed-size
// exponential-bucket histogram whose bucket counts are updated in O(1) on
// both insert and eviction (a ring buffer remembers which bucket each slot's
// sample landed in, so evicting the oldest sample is a plain decrement, never
// a scan or re-sort) — percentile/rate queries are O(histBucketCount), a
// small fixed constant, never a function of the window size.

const (
	histBucketCount = 256
	histMinMs       = 1.0
	histMaxMs       = 60000.0
)

// histFactor is the per-bucket exponential growth factor spanning
// [histMinMs, histMaxMs] over histBucketCount buckets.
var histFactor = math.Pow(histMaxMs/histMinMs, 1.0/float64(histBucketCount-1))

// bucketFor returns the histogram bucket index a latency falls into.
func bucketFor(d time.Duration) int {
	ms := float64(d) / float64(time.Millisecond)
	if ms <= histMinMs {
		return 0
	}
	if ms >= histMaxMs {
		return histBucketCount - 1
	}
	idx := int(math.Log(ms/histMinMs) / math.Log(histFactor))
	if idx < 0 {
		idx = 0
	}
	if idx >= histBucketCount {
		idx = histBucketCount - 1
	}
	return idx
}

// bucketUpperBound returns the latency value at the top of bucket i, used as
// that bucket's representative value when reporting a percentile.
func bucketUpperBound(i int) time.Duration {
	ms := histMinMs * math.Pow(histFactor, float64(i))
	return time.Duration(ms * float64(time.Millisecond))
}

// outcomeSample records which bucket a single recorded outcome landed in,
// its exact latency (for exact O(1) mean-latency eviction, separate from the
// bucket-quantized percentile machinery), and its timeout/error
// classification, so outcomeWindow can undo it in O(1) once evicted from the
// ring.
type outcomeSample struct {
	latency  time.Duration
	bucket   int
	timedOut bool
	isError  bool
}

// outcomeWindow is a fixed-size rolling window over the most recent
// WindowSize Release() outcomes. Not safe for concurrent use on its own —
// callers (Controller) serialize access under their own mutex.
type outcomeWindow struct {
	size   int
	ring   []outcomeSample
	pos    int
	filled int // number of valid entries so far, caps at size

	buckets    [histBucketCount]int
	total      int
	timeouts   int
	errors     int
	sumLatency time.Duration
}

func newOutcomeWindow(size int) *outcomeWindow {
	if size <= 0 {
		size = defaultWindowSize
	}
	return &outcomeWindow{size: size, ring: make([]outcomeSample, size)}
}

// record adds one outcome, evicting the oldest sample first if the window is
// already full. O(1).
func (w *outcomeWindow) record(latency time.Duration, timedOut, isError bool) {
	if w.filled == w.size {
		old := w.ring[w.pos]
		w.buckets[old.bucket]--
		w.total--
		w.sumLatency -= old.latency
		if old.timedOut {
			w.timeouts--
		}
		if old.isError {
			w.errors--
		}
	} else {
		w.filled++
	}

	b := bucketFor(latency)
	w.ring[w.pos] = outcomeSample{latency: latency, bucket: b, timedOut: timedOut, isError: isError}
	w.buckets[b]++
	w.total++
	w.sumLatency += latency
	if timedOut {
		w.timeouts++
	}
	if isError {
		w.errors++
	}
	w.pos = (w.pos + 1) % w.size
}

// meanLatency returns the rolling mean of the window's current samples, or 0
// if empty. O(1) — sumLatency is maintained incrementally by record().
func (w *outcomeWindow) meanLatency() time.Duration {
	if w.total == 0 {
		return 0
	}
	return w.sumLatency / time.Duration(w.total)
}

// percentile returns the latency value below which at least a p fraction of
// the window's current samples fall (e.g. p=0.95 for p95), or 0 if the
// window is empty. O(histBucketCount).
func (w *outcomeWindow) percentile(p float64) time.Duration {
	if w.total == 0 {
		return 0
	}
	target := int(math.Ceil(p * float64(w.total)))
	cum := 0
	for i, c := range w.buckets {
		cum += c
		if cum >= target {
			return bucketUpperBound(i)
		}
	}
	return bucketUpperBound(histBucketCount - 1)
}

func (w *outcomeWindow) timeoutRate() float64 {
	if w.total == 0 {
		return 0
	}
	return float64(w.timeouts) / float64(w.total)
}

func (w *outcomeWindow) errorRate() float64 {
	if w.total == 0 {
		return 0
	}
	return float64(w.errors) / float64(w.total)
}

// --- Controller --------------------------------------------------------------

// Controller is a bounded-concurrency admission primitive (§4.4): Acquire
// blocks until capacity is available, Release records the outcome and wakes
// waiters bounded by freed capacity via sync.Cond.Signal — never Broadcast,
// so a single release or limit increase never wakes more goroutines than
// there is now capacity for (the Python system's wake-storm bug, designed in
// correctly here from the start rather than fixed after the fact).
//
// Acquire never rejects — a bounded wait/queue-and-reject policy is Phase
// 7's scheduler, built on top of this, not a concern of Controller itself.
type Controller struct {
	mu   sync.Mutex
	cond *sync.Cond

	kind     ControllerKind
	limit    int
	inFlight int

	// window tracks recent Release() outcomes for both controller kinds:
	// MeanLatency() (read by the scheduler in queue.go for its Little's-law
	// wait projection, §4.5, which applies to fixed-limit backends too) and,
	// for an adaptive controller only, the percentile/timeout-rate/
	// error-rate reads the adjustment loop uses. cfg is adaptive-only (zero
	// value on a Fixed controller).
	cfg    AdaptiveConfig
	window *outcomeWindow

	lastTimeoutShrink time.Time
	lastErrorShrink   time.Time
	lastP95Shrink     time.Time

	// onLimitChange, if set, is invoked from adjust() whenever it actually
	// changes the limit (delta != 0) — module.go uses this to drive the
	// adaptive_limit_changes_total counter and concurrency_limit gauge
	// (§4.8) without coupling this file to Prometheus. Must be set (via
	// SetOnLimitChange) before Start(); not safe to change concurrently with
	// a running adjustment loop.
	onLimitChange func(oldLimit, newLimit int)

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// NewFixedController returns a Controller with a static concurrency limit
// that never changes. It still maintains an outcome window (for
// MeanLatency(), read by the scheduler) even though nothing here reads its
// percentile/rate fields.
func NewFixedController(limit int) *Controller {
	c := &Controller{kind: ControllerFixed, limit: limit, window: newOutcomeWindow(defaultWindowSize)}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// NewAdaptiveController returns a Controller that starts at
// cfg.InitialConcurrency and self-tunes via adjust() once Start() is called.
func NewAdaptiveController(cfg AdaptiveConfig) *Controller {
	if cfg.AdjustInterval <= 0 {
		cfg.AdjustInterval = defaultAdjustInterval
	}
	if cfg.WindowSize <= 0 {
		cfg.WindowSize = defaultWindowSize
	}
	c := &Controller{
		kind:   ControllerAdaptive,
		limit:  cfg.InitialConcurrency,
		cfg:    cfg,
		window: newOutcomeWindow(cfg.WindowSize),
	}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// Kind returns which capacity-control strategy this Controller uses.
func (c *Controller) Kind() ControllerKind {
	return c.kind
}

// SetOnLimitChange registers f to be called from adjust() whenever it
// actually changes the limit. Not safe to call concurrently with a running
// adjustment loop — set this before Start().
func (c *Controller) SetOnLimitChange(f func(oldLimit, newLimit int)) {
	c.onLimitChange = f
}

// Limit returns the current concurrency limit.
func (c *Controller) Limit() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.limit
}

// InFlight returns the current in-flight cost total.
//
// When driven through adaptiveadmission's Scheduler (queue.go), this can
// read up to 1 higher than genuinely in-flight work while the system is
// idle: the dispatch loop's acquire-before-pop design always holds one
// speculative reservation while blocked waiting for the next ticket to
// arrive. This is an accepted, documented consequence of that design (see
// queue.go's package doc), not a bug — it only affects idle-state readings
// of this method and the requests_in_flight gauge derived from it
// (metrics.go), never admission correctness or overload protection.
func (c *Controller) InFlight() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inFlight
}

// Acquire blocks until cost units of capacity are available, then reserves
// them. cost is uniformly 1 for v1 (§4.4) — the parameter exists to match
// the ported acquire(cost)/release(cost, ...) signature, not to support
// per-request variable cost.
func (c *Controller) Acquire(cost int) {
	c.mu.Lock()
	for c.inFlight+cost > c.limit {
		c.cond.Wait()
	}
	c.inFlight += cost
	c.mu.Unlock()
}

// Release frees cost units of capacity and records the outcome (latency,
// status code, timeout) into the rolling window — for both controller
// kinds, since MeanLatency() is meaningful for a Fixed controller's backend
// too (§4.5's wait projection isn't adaptive-only). statusCode >= 500 counts
// as an error for the adaptive adjustment loop's error-rate branch; a Fixed
// controller simply never reads timeoutRate()/errorRate()/percentile().
//
// Wakes exactly cost waiters via bounded Signal() calls — never Broadcast().
func (c *Controller) Release(cost int, latency time.Duration, statusCode int, timedOut bool) {
	c.mu.Lock()
	c.inFlight -= cost
	c.window.record(latency, timedOut, statusCode >= 500)
	c.mu.Unlock()

	c.wake(cost)
}

// ReleaseUnused frees cost units of capacity that were acquired but never
// used for actual work (e.g. the scheduler's dispatch loop in queue.go
// acquiring capacity, then finding nothing queued to grant it to before
// shutting down). Unlike Release, this never touches the outcome window —
// there is no latency or status code to record for capacity that did
// nothing.
func (c *Controller) ReleaseUnused(cost int) {
	c.mu.Lock()
	c.inFlight -= cost
	c.mu.Unlock()

	c.wake(cost)
}

// MeanLatency returns the rolling mean latency of Release()-recorded
// outcomes, or 0 if none have been recorded yet. Read by the scheduler
// (queue.go) for its Little's-law wait projection (§4.5).
func (c *Controller) MeanLatency() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.window.meanLatency()
}

// wake signals up to n waiters, bounded — never Broadcast(). Extra Signal
// calls beyond the number of actually-blocked waiters are harmless no-ops
// (Signal on a Cond with no waiters does nothing), so n may safely exceed
// the true waiter count.
func (c *Controller) wake(n int) {
	for i := 0; i < n; i++ {
		c.cond.Signal()
	}
}

// Start launches the adaptive adjustment loop; a no-op for a Fixed
// controller, whose limit never changes.
func (c *Controller) Start() {
	if c.kind != ControllerAdaptive {
		return
	}
	c.stopCh = make(chan struct{})
	c.wg.Add(1)
	go c.runAdjustLoop()
}

func (c *Controller) runAdjustLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(c.cfg.AdjustInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case now := <-ticker.C:
			c.adjust(now)
		}
	}
}

// Stop stops the adjustment loop, if running. Safe to call multiple times
// and on a Fixed controller (no-op either way).
func (c *Controller) Stop() {
	if c.kind != ControllerAdaptive || c.stopCh == nil {
		return
	}
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
	c.wg.Wait()
}

// adjust re-evaluates the adaptive limit against the rolling window's
// current p95/timeout-rate/error-rate (§4.4). Conditions are checked in
// priority order and at most one branch fires per call — the spec presents
// these as a priority chain of degradation signals (most severe first), and
// applying more than one multiplier in the same tick isn't meaningful:
//
//  1. timeout rate over threshold -> ×0.60, 60s cooldown
//  2. error rate over threshold   -> ×0.75, 30s cooldown
//  3. p95 > 2×target              -> ×0.70, 30s cooldown (shared w/ #4)
//  4. p95 > target                -> ×0.85, 30s cooldown (shared w/ #3)
//  5. p95 < 0.5×target            -> ×1.05, no cooldown
//
// A cooldown means "this branch may not fire again until it elapses",
// tracked independently per branch — e.g. a timeout-rate shrink doesn't
// block a later error-rate shrink even within the timeout branch's own 60s
// window. No samples recorded yet (window.total == 0) skips adjustment
// entirely — there is nothing to react to. Exported as taking `now`
// explicitly (like fairness/scoring.go's tick()/gc()) so tests can drive
// cooldowns deterministically without a real ticker or real sleeps.
func (c *Controller) adjust(now time.Time) {
	c.mu.Lock()

	if c.window.total == 0 {
		c.mu.Unlock()
		return
	}

	timeoutRate := c.window.timeoutRate()
	errorRate := c.window.errorRate()
	p95 := c.window.percentile(0.95)
	target := c.cfg.TargetP95

	oldLimit := c.limit
	newLimit := oldLimit

	switch {
	case timeoutRate > c.cfg.TimeoutRateThreshold && now.Sub(c.lastTimeoutShrink) >= timeoutShrinkCooldown:
		newLimit = shrink(oldLimit, timeoutShrinkMultiplier)
		c.lastTimeoutShrink = now
	case errorRate > c.cfg.ErrorRateThreshold && now.Sub(c.lastErrorShrink) >= errorShrinkCooldown:
		newLimit = shrink(oldLimit, errorShrinkMultiplier)
		c.lastErrorShrink = now
	case target > 0 && p95 > 2*target && now.Sub(c.lastP95Shrink) >= p95ShrinkCooldown:
		newLimit = shrink(oldLimit, p95HardShrinkMultiplier)
		c.lastP95Shrink = now
	case target > 0 && p95 > target && now.Sub(c.lastP95Shrink) >= p95ShrinkCooldown:
		newLimit = shrink(oldLimit, p95SoftShrinkMultiplier)
		c.lastP95Shrink = now
	case target > 0 && p95 < target/2:
		newLimit = grow(oldLimit, growMultiplier)
	}

	newLimit = clampInt(newLimit, c.cfg.MinConcurrency, c.cfg.MaxConcurrency)
	c.limit = newLimit
	delta := newLimit - oldLimit
	c.mu.Unlock()

	if delta != 0 && c.onLimitChange != nil {
		c.onLimitChange(oldLimit, newLimit)
	}

	// Wake immediately on a limit increase (§4.4): modeled as "freeing"
	// delta units of capacity through the same bounded Signal mechanism as
	// Release, so this never needs Broadcast() either.
	if delta > 0 {
		c.wake(delta)
	}
}

// shrink applies multiplier to limit, rounding to the nearest int and never
// going below 1 (a limit of 0 would deadlock every future Acquire — the
// caller's clampInt against cfg.MinConcurrency is the primary floor, this is
// a safety net for a misconfigured/unset MinConcurrency).
func shrink(limit int, multiplier float64) int {
	n := int(math.Round(float64(limit) * multiplier))
	if n < 1 {
		n = 1
	}
	return n
}

// grow applies multiplier to limit, guaranteeing at least +1 so a small
// limit (where rounding would otherwise round back down to itself) still
// makes forward progress when the grow condition fires.
func grow(limit int, multiplier float64) int {
	n := int(math.Round(float64(limit) * multiplier))
	if n <= limit {
		n = limit + 1
	}
	return n
}

func clampInt(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
