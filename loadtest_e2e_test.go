// loadtest_e2e_test.go runs implementation_plan.md's Phase 11 concurrency
// sweep against the actual fairness + adaptive_admission + reverse_proxy
// chain (Phase 8), loaded the same way integration_test.go does (a real
// caddy.Load'd instance, no xcaddy binary). It is gated behind
// RUN_LOADTEST_E2E=1 -- unlike the correctness-focused integration tests, this
// is a runtime performance measurement (several concurrency levels, each held
// open for seconds), not something that should run on every `go test ./...`
// in CI (Phase 3). Run it explicitly:
//
//	RUN_LOADTEST_E2E=1 go test . -run TestLoadTest_FullChain_ConcurrencySweep -v
//
// Per REQUIREMENTS.md §8, the Python system's throughput peaked around
// 50-100 concurrency (~327 req/s) then dropped as offered concurrency rose to
// 250 (~80 req/s). This test sweeps the same 50->250 range through the Go
// port and fails if the same inversion shape reappears -- catching it here,
// rather than assuming Go's parallelism alone rules it out.
package caddyaac

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/arquivo/caddy-adaptive-admission-controller/loadtest"
)

// loadTestReportPath is where the captured report (implementation_plan.md
// Phase 11's "done when" deliverable) is written on each run.
const loadTestReportPath = "docs/LOAD_TEST_REPORT.md"

func TestLoadTest_FullChain_ConcurrencySweep(t *testing.T) {
	if os.Getenv("RUN_LOADTEST_E2E") != "1" {
		t.Skip("set RUN_LOADTEST_E2E=1 to run the Phase 11 concurrency-sweep load test against the full chain (slow, not run in CI)")
	}

	// A realistic dummy upstream latency (a page-search-API-shaped
	// backend, per examples/fairness-adaptive-admission.Caddyfile) across
	// three distinct endpoints, satisfying §8's "multi-endpoint" sweep
	// requirement.
	const upstreamLatency = 15 * time.Millisecond
	endpoints := []string{"/", "/search", "/api/lookup"}
	mux := http.NewServeMux()
	for _, p := range endpoints {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(upstreamLatency)
			w.WriteHeader(http.StatusOK)
		})
	}
	upstream := httptest.NewServer(mux)
	t.Cleanup(upstream.Close)

	// The controller limit (300) intentionally sits above every swept
	// concurrency level (max 250): this test measures the chain's own
	// throughput ceiling, not an admission-control cap rejecting the
	// excess -- a cap below offered concurrency would trivially "prevent"
	// an inversion without proving anything about real throughput.
	input := fmt.Sprintf(`
:19090 {
	fairness
	adaptive_admission {
		controller fixed {
			limit 300
		}
		queue_max_size 1000
		queue_timeout 30s
	}
	reverse_proxy %s
}
`, upstream.Listener.Addr().String())
	loadCaddy(t, input)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 4096,
			DisableCompression:  true,
		},
	}

	target := loadtest.Target{
		BaseURL:   "http://127.0.0.1:19090",
		Endpoints: endpoints,
	}
	cfg := loadtest.Config{
		Levels:         []int{50, 100, 150, 200, 250},
		RampUp:         1 * time.Second,
		Hold:           3 * time.Second,
		RequestTimeout: 10 * time.Second,
	}

	results, err := loadtest.Sweep(context.Background(), client, target, cfg)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	report := loadtest.FormatReport(results)
	t.Log("\n" + report)

	inv := loadtest.DetectInversion(results, 0.15)
	var verdict string
	if inv.Inverted {
		verdict = fmt.Sprintf("**THROUGHPUT INVERSION DETECTED:** %s\n", inv.Detail)
	} else {
		verdict = fmt.Sprintf("No throughput inversion detected: peak %.1f req/s at concurrency %d, and throughput does not drop >=15%% below that peak at any higher concurrency level swept.\n", inv.PeakThroughputRPS, inv.PeakConcurrency)
	}

	doc := fmt.Sprintf(`# Load test report — Phase 11 concurrency sweep

Captured by TestLoadTest_FullChain_ConcurrencySweep (loadtest_e2e_test.go) at %s.

Chain under test: fairness -> adaptive_admission (fixed controller, limit=300,
i.e. non-limiting for this sweep's 50-250 range) -> reverse_proxy, against a
dummy upstream with a fixed %s latency across %d endpoints (%v), matching
REQUIREMENTS.md §8's methodology (ramp-up/hold-open/multi-endpoint concurrency
sweep, measuring p50/p95/p99 and throughput vs. offered concurrency) and the
50->250 concurrency range the original Python system's own investigation used.

Each level: %s ramp-up (staggered worker start), then %s steady-state hold
measured for throughput/percentiles.

`+"```"+`
%s`+"```"+`

%s`,
		time.Now().UTC().Format(time.RFC3339),
		upstreamLatency, len(endpoints), endpoints,
		cfg.RampUp, cfg.Hold,
		report,
		verdict,
	)

	if err := os.WriteFile(loadTestReportPath, []byte(doc), 0o644); err != nil {
		t.Fatalf("write %s: %v", loadTestReportPath, err)
	}

	if inv.Inverted {
		t.Fatalf("throughput inversion detected across concurrency 50-250 -- per REQUIREMENTS.md §8, profile with pprof before applying a fix (see %s): %s", loadTestReportPath, inv.Detail)
	}
}

// TestLoadTest_StarvationScenario replays the 2026-11-13 load test of the
// p85 dev broker against the full chain, with the broker's fairness
// scoring and trusted_proxies setup: one heavy client (c=50) and 20 light
// clients (c=2), each a fake X-Forwarded-For in its own /24, against a
// fixed limit-20 backend. The heavy client earns an ip penalty and, with
// strict priority, got nothing served for over 30s while the light clients
// ran. Here, with queue_aging_rate set, it must keep being served, and with
// aging off, queue_timeout must reject its starved requests rather than
// leave them queued. Gated like the sweep above:
//
//	RUN_LOADTEST_E2E=1 go test . -run TestLoadTest_StarvationScenario -v
func TestLoadTest_StarvationScenario(t *testing.T) {
	if os.Getenv("RUN_LOADTEST_E2E") != "1" {
		t.Skip("set RUN_LOADTEST_E2E=1 to run the p85 starvation scenario against the full chain (slow, not run in CI)")
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	const queueTimeout = 5 * time.Second
	for _, tc := range []struct {
		name  string
		port  int
		aging string
	}{
		{"aging off", 19113, ""},
		{"aging 5 per second", 19114, "queue_aging_rate 5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loadCaddy(t, fmt.Sprintf(`
{
	servers {
		trusted_proxies static 127.0.0.1/32
		trusted_proxies_strict
	}
}
:%d {
	fairness {
		scoring {
			base_score anonymous 60
			penalty ip          alpha=0.2 soft=20:10  hard=100:40
			penalty ipv4_subnet alpha=0.2 soft=100:10 hard=500:40
		}
	}
	adaptive_admission {
		controller fixed {
			limit 20
		}
		queue_max_size 1000
		queue_timeout  %s
		%s
	}
	reverse_proxy %s
}
`, tc.port, queueTimeout, tc.aging, upstream.Listener.Addr().String()))

			r := runStarvationClients(t, fmt.Sprintf("http://127.0.0.1:%d/", tc.port), 12*time.Second)
			t.Logf("heavy: %s", r.heavy)
			t.Logf("light: %s", r.light)

			for _, s := range []clientStats{r.heavy, r.light} {
				if s.maxLatency > queueTimeout+2*time.Second {
					t.Errorf("a request took %v, want at most queue_timeout (%v) plus backend time", s.maxLatency, queueTimeout)
				}
			}
			if tc.aging != "" && r.heavy.servedSecondHalf == 0 {
				t.Errorf("heavy client got nothing served in the second half of the run, despite aging")
			}
		})
	}
}

type clientStats struct {
	served, rejected, failed int
	servedSecondHalf         int
	maxLatency               time.Duration
}

func (s clientStats) String() string {
	return fmt.Sprintf("served=%d (second half %d) rejected=%d failed=%d max_latency=%v",
		s.served, s.servedSecondHalf, s.rejected, s.failed, s.maxLatency.Round(time.Millisecond))
}

type starvationResult struct{ heavy, light clientStats }

// runStarvationClients runs the heavy (10.0.0.1, c=50) and light (10.1.N.1,
// c=2, N=1..20) closed-loop clients against url for d.
func runStarvationClients(t *testing.T, url string, d time.Duration) starvationResult {
	t.Helper()
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{MaxIdleConnsPerHost: 256},
	}
	start := time.Now()
	half, end := start.Add(d/2), start.Add(d)

	var mu sync.Mutex
	var res starvationResult
	var wg sync.WaitGroup
	worker := func(ip string, stats *clientStats) {
		defer wg.Done()
		for time.Now().Before(end) {
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
			req.Header.Set("X-Forwarded-For", ip)
			reqStart := time.Now()
			resp, err := client.Do(req)
			latency := time.Since(reqStart)
			mu.Lock()
			switch {
			case err != nil:
				stats.failed++
			case resp.StatusCode == http.StatusOK:
				stats.served++
				if time.Now().After(half) {
					stats.servedSecondHalf++
				}
			default:
				stats.rejected++
			}
			if latency > stats.maxLatency {
				stats.maxLatency = latency
			}
			mu.Unlock()
			if resp != nil {
				resp.Body.Close()
			}
		}
	}
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go worker("10.0.0.1", &res.heavy)
	}
	for n := 1; n <= 20; n++ {
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go worker(fmt.Sprintf("10.1.%d.1", n), &res.light)
		}
	}
	wg.Wait()
	return res
}
