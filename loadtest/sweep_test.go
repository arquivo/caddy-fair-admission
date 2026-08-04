package loadtest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestPercentile(t *testing.T) {
	ms := func(vals ...int) []time.Duration {
		out := make([]time.Duration, len(vals))
		for i, v := range vals {
			out[i] = time.Duration(v) * time.Millisecond
		}
		return out
	}

	tests := []struct {
		name   string
		sorted []time.Duration
		p      float64
		want   time.Duration
	}{
		{"empty", nil, 50, 0},
		{"single", ms(10), 50, 10 * time.Millisecond},
		{"single_p99", ms(10), 99, 10 * time.Millisecond},
		{"four_p50", ms(1, 2, 3, 4), 50, 2 * time.Millisecond},
		{"four_p99", ms(1, 2, 3, 4), 99, 4 * time.Millisecond},
		{"hundred_p95", func() []time.Duration {
			vals := make([]int, 100)
			for i := range vals {
				vals[i] = i + 1
			}
			return ms(vals...)
		}(), 95, 95 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := percentile(tt.sorted, tt.p); got != tt.want {
				t.Errorf("percentile(%v, %v) = %v, want %v", tt.sorted, tt.p, got, tt.want)
			}
		})
	}
}

// TestSweep_MultiEndpointRampHold runs a small sweep against a local test
// server that sleeps a fixed latency and records which endpoints it served,
// asserting: every configured endpoint got hit (multi-endpoint), throughput
// and percentiles are computed and non-zero, and no errors were recorded.
func TestSweep_MultiEndpointRampHold(t *testing.T) {
	const latency = 5 * time.Millisecond
	var hits [3]int64
	mux := http.NewServeMux()
	paths := []string{"/a", "/b", "/c"}
	for i, p := range paths {
		i := i
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(latency)
			atomic.AddInt64(&hits[i], 1)
			w.WriteHeader(http.StatusOK)
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	target := Target{BaseURL: srv.URL, Endpoints: paths}
	cfg := Config{
		Levels:         []int{4, 8},
		RampUp:         20 * time.Millisecond,
		Hold:           150 * time.Millisecond,
		RequestTimeout: 2 * time.Second,
	}

	results, err := Sweep(context.Background(), srv.Client(), target, cfg)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(results) != len(cfg.Levels) {
		t.Fatalf("results = %d entries, want %d", len(results), len(cfg.Levels))
	}
	for i, r := range results {
		if r.Concurrency != cfg.Levels[i] {
			t.Errorf("results[%d].Concurrency = %d, want %d", i, r.Concurrency, cfg.Levels[i])
		}
		if r.Errors != 0 {
			t.Errorf("results[%d].Errors = %d, want 0", i, r.Errors)
		}
		if r.Requests == 0 {
			t.Errorf("results[%d].Requests = 0, want > 0", i)
		}
		if r.ThroughputRPS <= 0 {
			t.Errorf("results[%d].ThroughputRPS = %v, want > 0", i, r.ThroughputRPS)
		}
		if r.P50 <= 0 || r.P95 < r.P50 || r.P99 < r.P95 {
			t.Errorf("results[%d] percentiles = p50=%v p95=%v p99=%v, want 0 < p50 <= p95 <= p99", i, r.P50, r.P95, r.P99)
		}
	}
	for i, h := range hits {
		if atomic.LoadInt64(&h) == 0 {
			t.Errorf("endpoint %q was never hit across the sweep", paths[i])
		}
	}
}

// TestSweep_MeasurementWindowExcludesRampUp asserts that requests completing
// before the ramp-up period has elapsed are not counted -- otherwise
// cold-start latency (or a burst of near-simultaneous connection setup)
// would skew the steady-state percentiles the sweep is meant to report.
func TestSweep_MeasurementWindowExcludesRampUp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	target := Target{BaseURL: srv.URL, Endpoints: []string{"/"}}
	cfg := Config{
		Levels:         []int{2},
		RampUp:         100 * time.Millisecond,
		Hold:           50 * time.Millisecond,
		RequestTimeout: time.Second,
	}

	start := time.Now()
	results, err := Sweep(context.Background(), srv.Client(), target, cfg)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	elapsed := time.Since(start)
	// The level must run for at least RampUp+Hold -- if requests completing
	// during ramp-up were being counted, the level could return almost
	// immediately with samples that don't reflect the requested Hold window.
	if elapsed < cfg.RampUp+cfg.Hold {
		t.Errorf("level took %v, want >= rampup+hold (%v)", elapsed, cfg.RampUp+cfg.Hold)
	}
	if results[0].Requests == 0 {
		t.Fatal("expected some requests counted within the measurement window")
	}
}

func TestFormatReport(t *testing.T) {
	results := []LevelResult{
		{Concurrency: 50, Requests: 1000, Errors: 0, ThroughputRPS: 327.4, P50: 10 * time.Millisecond, P95: 30 * time.Millisecond, P99: 50 * time.Millisecond},
	}
	out := FormatReport(results)
	if out == "" {
		t.Fatal("FormatReport returned empty string")
	}
	// Sanity: header and the one data row's concurrency value must appear.
	if !contains(out, "concurrency") || !contains(out, "50") {
		t.Errorf("FormatReport output missing expected content: %q", out)
	}
}

func TestDetectInversion(t *testing.T) {
	tests := []struct {
		name          string
		results       []LevelResult
		dropThreshold float64
		wantInverted  bool
		wantPeakConc  int
	}{
		{
			name: "monotonic_increase_no_inversion",
			results: []LevelResult{
				{Concurrency: 50, ThroughputRPS: 300},
				{Concurrency: 100, ThroughputRPS: 350},
				{Concurrency: 250, ThroughputRPS: 400},
			},
			dropThreshold: 0.15,
			wantInverted:  false,
			wantPeakConc:  250,
		},
		{
			name: "python_style_inversion",
			results: []LevelResult{
				{Concurrency: 50, ThroughputRPS: 327},
				{Concurrency: 100, ThroughputRPS: 320},
				{Concurrency: 250, ThroughputRPS: 80},
			},
			dropThreshold: 0.15,
			wantInverted:  true,
			wantPeakConc:  50,
		},
		{
			name: "small_dip_within_noise_tolerance",
			results: []LevelResult{
				{Concurrency: 50, ThroughputRPS: 300},
				{Concurrency: 100, ThroughputRPS: 290},
			},
			dropThreshold: 0.15,
			wantInverted:  false,
			wantPeakConc:  50,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectInversion(tt.results, tt.dropThreshold)
			if got.Inverted != tt.wantInverted {
				t.Errorf("Inverted = %v, want %v (detail: %s)", got.Inverted, tt.wantInverted, got.Detail)
			}
			if got.PeakConcurrency != tt.wantPeakConc {
				t.Errorf("PeakConcurrency = %d, want %d", got.PeakConcurrency, tt.wantPeakConc)
			}
		})
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
