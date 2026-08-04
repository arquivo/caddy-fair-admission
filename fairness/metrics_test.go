package fairness

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

// TestServeHTTP_RecordsScoreDistributionAndLogFields drives one request
// through ServeHTTP on an unprovisioned Handler (mirrors
// TestHandler_ServeHTTP_SetsFairnessScoreVar_FailOpenWithoutProvision in
// scoring_test.go) and asserts this package's one owned metric series (§4.8,
// fairness_score_distribution) observed a value with the expected labels,
// and that fairness_log_fields (§4.9) carries every key adaptive_admission's
// logDecision reads.
func TestServeHTTP_RecordsScoreDistributionAndLogFields(t *testing.T) {
	backend := "metrics-test-backend"
	h := Handler{Config: Config{Backend: backend}}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:1234"
	vars := map[string]any{}
	req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars))

	rec := httptest.NewRecorder()
	called := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})

	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !called {
		t.Fatal("next handler was not called")
	}

	if got := testutil.CollectAndCount(fairnessMetrics.scoreDistribution, "fairness_score_distribution"); got == 0 {
		t.Error("fairness_score_distribution has no observations")
	}

	obs := fairnessMetrics.scoreDistribution.WithLabelValues(backend, string(UserClassAnonymous))
	hist, ok := obs.(prometheus.Histogram)
	if !ok {
		t.Fatalf("scoreDistribution.WithLabelValues(...) = %T, want prometheus.Histogram", obs)
	}
	var m dto.Metric
	if err := hist.Write(&m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := m.GetHistogram().GetSampleCount(); got != 1 {
		t.Errorf("fairness_score_distribution{backend=%q,user_class=%q} sample count = %d, want 1", backend, UserClassAnonymous, got)
	}

	lf, ok := caddyhttp.GetVar(req.Context(), logFieldsVarKey).(map[string]any)
	if !ok {
		t.Fatalf("fairness_log_fields var = %#v, want map[string]any", caddyhttp.GetVar(req.Context(), logFieldsVarKey))
	}
	wantKeys := []string{"ip", "asn", "country", "user_class", "exempt", "score_breakdown"}
	for _, k := range wantKeys {
		if _, ok := lf[k]; !ok {
			t.Errorf("fairness_log_fields missing key %q; got %v", k, lf)
		}
	}
	if got, _ := lf["user_class"].(string); got != string(UserClassAnonymous) {
		t.Errorf("fairness_log_fields[user_class] = %q, want %q", got, UserClassAnonymous)
	}
	if _, ok := lf["score_breakdown"].(map[string]float64); !ok {
		t.Errorf("fairness_log_fields[score_breakdown] = %#v, want map[string]float64", lf["score_breakdown"])
	}
}
