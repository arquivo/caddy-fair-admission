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
	"testing"
	"time"

	"github.com/arquivo/caddy-adaptive-admission-controller/loadtest"
)

// loadTestReportPath is where the captured report (implementation_plan.md
// Phase 11's "done when" deliverable) is written on each run.
const loadTestReportPath = "LOAD_TEST_REPORT.md"

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
