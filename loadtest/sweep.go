// Package loadtest implements a concurrency ramp/sweep load generator: a Go
// port of the original Python system's scripts/load_test.py (REQUIREMENTS.md
// §8, implementation_plan.md Phase 11). At each offered-concurrency level it
// ramps up N persistent workers (staggered starts, not a thundering herd),
// holds them open hammering a set of endpoints (round-robin, closed-loop) for
// a steady-state measurement window, then reports p50/p95/p99 latency and
// throughput for that level -- the same shape of measurement the Python
// investigation used to find its 50-250 concurrency throughput inversion.
package loadtest

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Target describes what to hit.
type Target struct {
	// BaseURL is the scheme://host:port prefix each endpoint path is
	// appended to (e.g. "http://127.0.0.1:19090").
	BaseURL string
	// Endpoints are request paths, round-robined across requests so a
	// sweep exercises more than one route per REQUIREMENTS.md §8's
	// "multi-endpoint" requirement. Must be non-empty.
	Endpoints []string
	// Header, if non-nil, is applied to every request (e.g. Authorization).
	Header http.Header
}

// Config controls how each concurrency level in a sweep is driven.
type Config struct {
	// Levels are the offered-concurrency values to sweep, in order (the
	// Python investigation's report used 50->250; REQUIREMENTS.md §8
	// asks that the same range not show the same inversion here).
	Levels []int
	// RampUp is how long it takes to stagger-start all workers at a
	// given level, avoiding a synchronized thundering herd at t=0.
	RampUp time.Duration
	// Hold is the steady-state measurement window per level: only
	// requests completing after RampUp has elapsed (and before RampUp+
	// Hold) are counted toward that level's latency/throughput numbers.
	Hold time.Duration
	// RequestTimeout bounds each individual HTTP request.
	RequestTimeout time.Duration
}

// LevelResult is one concurrency level's measured outcome.
type LevelResult struct {
	Concurrency   int           `json:"concurrency"`
	Requests      int           `json:"requests"`
	Errors        int           `json:"errors"`
	Window        time.Duration `json:"window"`
	ThroughputRPS float64       `json:"throughput_rps"`
	P50           time.Duration `json:"p50"`
	P95           time.Duration `json:"p95"`
	P99           time.Duration `json:"p99"`
}

// workerLatencies accumulates a single worker's measured-window latencies
// locally (no shared lock on the request hot path -- the Python system's own
// lesson, §8, is that per-request contention points compound into a single
// bottleneck) and its own request/error counters.
type workerLatencies struct {
	latencies []time.Duration
	requests  int
	errors    int
}

// Sweep runs cfg.Levels in sequence against target, returning one
// LevelResult per level in the same order.
func Sweep(ctx context.Context, client *http.Client, target Target, cfg Config) ([]LevelResult, error) {
	if len(target.Endpoints) == 0 {
		return nil, fmt.Errorf("loadtest: Target.Endpoints must be non-empty")
	}
	results := make([]LevelResult, 0, len(cfg.Levels))
	for _, n := range cfg.Levels {
		r, err := runLevel(ctx, client, target, cfg, n)
		if err != nil {
			return results, fmt.Errorf("concurrency %d: %w", n, err)
		}
		results = append(results, r)
	}
	return results, nil
}

func runLevel(ctx context.Context, client *http.Client, target Target, cfg Config, concurrency int) (LevelResult, error) {
	levelStart := time.Now()
	measureStart := levelStart.Add(cfg.RampUp)
	measureEnd := measureStart.Add(cfg.Hold)

	var endpointCounter uint64
	nextEndpoint := func() string {
		i := atomic.AddUint64(&endpointCounter, 1) - 1
		return target.Endpoints[int(i)%len(target.Endpoints)]
	}

	workerResults := make([]workerLatencies, concurrency)
	var wg sync.WaitGroup
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		// Stagger this worker's start across RampUp so the level ramps
		// up rather than arriving as one synchronized burst.
		var startDelay time.Duration
		if concurrency > 1 {
			startDelay = cfg.RampUp * time.Duration(i) / time.Duration(concurrency)
		}
		go func(idx int, delay time.Duration) {
			defer wg.Done()
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			runWorker(ctx, client, target, cfg, nextEndpoint, measureStart, measureEnd, &workerResults[idx])
		}(i, startDelay)
	}
	wg.Wait()

	return summarizeLevel(concurrency, cfg.Hold, workerResults), nil
}

// runWorker closed-loop-fires requests (fire, wait for response, fire again)
// until measureEnd has passed, recording only samples whose completion falls
// within [measureStart, measureEnd) into out.
func runWorker(ctx context.Context, client *http.Client, target Target, cfg Config, nextEndpoint func() string, measureStart, measureEnd time.Time, out *workerLatencies) {
	for {
		now := time.Now()
		if !now.Before(measureEnd) {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}

		reqCtx := ctx
		var cancel context.CancelFunc
		if cfg.RequestTimeout > 0 {
			reqCtx, cancel = context.WithTimeout(ctx, cfg.RequestTimeout)
		}
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target.BaseURL+nextEndpoint(), nil)
		if err != nil {
			if cancel != nil {
				cancel()
			}
			return
		}
		for k, vs := range target.Header {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}

		start := time.Now()
		resp, err := client.Do(req)
		elapsed := time.Since(start)
		if cancel != nil {
			cancel()
		}

		inWindow := start.After(measureStart) || start.Equal(measureStart)
		if err != nil {
			if inWindow {
				out.errors++
			}
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			if inWindow {
				out.errors++
			}
			continue
		}
		if inWindow {
			out.requests++
			out.latencies = append(out.latencies, elapsed)
		}
	}
}

func summarizeLevel(concurrency int, window time.Duration, workerResults []workerLatencies) LevelResult {
	var all []time.Duration
	var requests, errs int
	for _, wr := range workerResults {
		requests += wr.requests
		errs += wr.errors
		all = append(all, wr.latencies...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })

	windowSeconds := window.Seconds()
	var throughput float64
	if windowSeconds > 0 {
		throughput = float64(requests) / windowSeconds
	}

	return LevelResult{
		Concurrency:   concurrency,
		Requests:      requests,
		Errors:        errs,
		Window:        window,
		ThroughputRPS: throughput,
		P50:           percentile(all, 50),
		P95:           percentile(all, 95),
		P99:           percentile(all, 99),
	}
}

// percentile returns the p-th percentile (0-100) of sorted, using the
// standard nearest-rank method: rank = ceil(p/100 * N), 1-indexed, clamped to
// [1, N]. sorted must already be sorted ascending.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(math.Ceil((p / 100) * float64(len(sorted))))
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}
