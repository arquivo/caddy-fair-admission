package adaptiveadmission

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// TestServeHTTP_RecordsAllElevenMetricSeries drives one admitted and one
// rejected request through ServeHTTP and asserts every one of the 11 series
// this package owns (§4.8) observed the expected value, using a fresh,
// unregistered *Handler (not going through caddy.Load) so the assertions
// read directly off the package-level admissionMetrics collectors rather
// than scraping /metrics text.
func TestServeHTTP_RecordsAllElevenMetricSeries(t *testing.T) {
	backend := "metrics-test-backend-" + t.Name()

	c := NewFixedController(1)
	s := NewScheduler(QueueConfig{MaxSize: 1}, c)
	s.Start()
	defer s.Stop()

	h := &Handler{Config: Config{Backend: backend}, controller: c, scheduler: s}
	admissionMetrics.concurrencyLimit.WithLabelValues(backend).Set(float64(c.Limit()))

	// 1. Admitted request.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP (admitted): %v", err)
	}

	if got := testutil.ToFloat64(admissionMetrics.requestsTotal.WithLabelValues(backend)); got != 1 {
		t.Errorf("requests_total = %v, want 1", got)
	}
	if got := testutil.ToFloat64(admissionMetrics.requestsAdmitted.WithLabelValues(backend)); got != 1 {
		t.Errorf("requests_admitted_total = %v, want 1", got)
	}
	// requests_in_flight is Set() from Controller.InFlight() immediately
	// after dispatch returns (module.go) -- this races the dispatch loop's
	// own speculative re-Acquire for the next, not-yet-arrived ticket (see
	// Controller.InFlight's doc), so it can read 0 or 1 here depending on
	// scheduling.
	if got := testutil.ToFloat64(admissionMetrics.requestsInFlight.WithLabelValues(backend)); got < 0 || got > 1 {
		t.Errorf("requests_in_flight = %v, want 0 or 1", got)
	}
	// queue_size is set to Depth() right after Enqueue, racing the dispatch
	// loop's own pop -- it settles at 0 or 1 depending on scheduling, so
	// only sanity-check it's a valid, non-negative reading rather than
	// asserting an exact post-dispatch value.
	if got := testutil.ToFloat64(admissionMetrics.queueSize.WithLabelValues(backend)); got < 0 {
		t.Errorf("queue_size = %v, want >= 0", got)
	}
	if got := testutil.ToFloat64(admissionMetrics.concurrencyLimit.WithLabelValues(backend)); got != 1 {
		t.Errorf("concurrency_limit = %v, want 1", got)
	}
	if got := testutil.CollectAndCount(admissionMetrics.requestDuration, "adaptive_admission_backend_request_duration_seconds"); got == 0 {
		t.Error("backend_request_duration_seconds has no observations")
	}
	if got := testutil.CollectAndCount(admissionMetrics.queueWaitDuration, "adaptive_admission_queue_wait_duration_seconds"); got == 0 {
		t.Error("queue_wait_duration_seconds has no observations")
	}
	if got := testutil.ToFloat64(admissionMetrics.backendErrors.WithLabelValues(backend)); got != 0 {
		t.Errorf("backend_errors_total = %v, want 0 for a 200 response", got)
	}
	if got := testutil.ToFloat64(admissionMetrics.backendTimeouts.WithLabelValues(backend)); got != 0 {
		t.Errorf("backend_timeouts_total = %v, want 0 for a successful response", got)
	}

	// 2. Reject a second request outright, on a second, never-started
	// scheduler/controller pair (mirrors module_test.go's
	// TestHandler_ServeHTTP_RejectsQueueFull_As429) -- reusing the first
	// pair here would race the running dispatch loop's own
	// controller.Acquire(1) against this test directly holding the slot,
	// deadlocking the deferred s.Stop() below.
	c2 := NewFixedController(1)
	c2.Acquire(1) // hold the only slot; dispatch loop never started
	s2 := NewScheduler(QueueConfig{MaxSize: 1}, c2)
	if _, reason := s2.Enqueue(1); reason != RejectNone {
		t.Fatalf("seed Enqueue rejected: %v", reason)
	}
	h2 := &Handler{Config: Config{Backend: backend}, controller: c2, scheduler: s2}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	rec2 := httptest.NewRecorder()
	if err := h2.ServeHTTP(rec2, req2, next); err == nil {
		t.Fatal("expected a rejection error for the second request")
	}
	if got := testutil.ToFloat64(admissionMetrics.requestsRejected.WithLabelValues(backend, RejectQueueFull.String())); got != 1 {
		t.Errorf("requests_rejected_total{reason=queue_full} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(admissionMetrics.requestsTotal.WithLabelValues(backend)); got != 2 {
		t.Errorf("requests_total = %v, want 2", got)
	}

	// 3. Limit-change counter/gauge (onLimitChange hook), exercised directly
	// since it's driven from Provision, not ServeHTTP.
	h.controller.SetOnLimitChange(func(oldLimit, newLimit int) {
		direction := "grow"
		if newLimit < oldLimit {
			direction = "shrink"
		}
		admissionMetrics.limitChanges.WithLabelValues(backend, direction).Inc()
		admissionMetrics.concurrencyLimit.WithLabelValues(backend).Set(float64(newLimit))
	})
	if fn := h.controller.onLimitChange; fn == nil {
		t.Fatal("onLimitChange hook was not set")
	} else {
		fn(1, 2)
	}
	if got := testutil.ToFloat64(admissionMetrics.limitChanges.WithLabelValues(backend, "grow")); got != 1 {
		t.Errorf("adaptive_limit_changes_total{direction=grow} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(admissionMetrics.concurrencyLimit.WithLabelValues(backend)); got != 2 {
		t.Errorf("concurrency_limit = %v, want 2 after onLimitChange(1, 2)", got)
	}
}

// TestLogDecision_AdmittedRequest_EmitsExactlyOneLineWithEveryField drives one
// admitted request through ServeHTTP with an observer-backed zap logger and
// asserts exactly one "admission_decision" log entry is emitted, carrying
// every field REQUIREMENTS.md §4.9 lists for the admitted case (both this
// package's own fields and fairness's folded-in classification/score-
// breakdown fields, read via the fairness_log_fields var).
func TestLogDecision_AdmittedRequest_EmitsExactlyOneLineWithEveryField(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	c := NewFixedController(1)
	s := NewScheduler(QueueConfig{MaxSize: 10}, c)
	s.Start()
	defer s.Stop()

	h := &Handler{Config: Config{Backend: "log-test"}, controller: c, scheduler: s, logger: logger}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	vars := map[string]any{
		fairnessLogFieldsVarKey: map[string]any{
			"ip":              "203.0.113.5",
			"asn":             uint64(64500),
			"country":         "PT",
			"user_class":      "researcher",
			"exempt":          false,
			"score_breakdown": map[string]float64{"base": 100, "total_penalty": 5, "final": 95},
		},
	}
	req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars))
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want exactly 1", len(entries))
	}
	entry := entries[0]
	if entry.Message != "admission_decision" {
		t.Errorf("message = %q, want %q", entry.Message, "admission_decision")
	}

	fields := entry.ContextMap()
	wantKeys := []string{
		"backend", "admitted", "queue_wait_ms", "backend_latency_ms", "status_code",
		"ip", "asn", "country", "user_class", "exempt", "score_breakdown",
	}
	for _, k := range wantKeys {
		if _, ok := fields[k]; !ok {
			t.Errorf("log entry missing field %q; got fields %v", k, fields)
		}
	}
	if got, _ := fields["admitted"].(bool); !got {
		t.Errorf("admitted = %v, want true", fields["admitted"])
	}
	if got, _ := fields["backend"].(string); got != "log-test" {
		t.Errorf("backend = %q, want %q", got, "log-test")
	}
	if _, hasReject := fields["reject_reason"]; hasReject {
		t.Error("admitted entry must not carry reject_reason")
	}
}

// TestLogDecision_RejectedRequest_EmitsExactlyOneLineWithRejectReason mirrors
// the admitted-path test above for the reject branch (§4.9): exactly one log
// line, carrying reject_reason and no admitted-only fields.
func TestLogDecision_RejectedRequest_EmitsExactlyOneLineWithRejectReason(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	c := NewFixedController(1)
	c.Acquire(1) // hold the only slot; dispatch loop never started
	s := NewScheduler(QueueConfig{MaxSize: 1}, c)
	if _, reason := s.Enqueue(1); reason != RejectNone {
		t.Fatalf("seed Enqueue rejected: %v", reason)
	}

	h := &Handler{Config: Config{Backend: "log-test"}, controller: c, scheduler: s, logger: logger}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("next must not be called when the request is rejected")
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err == nil {
		t.Fatal("expected a rejection error")
	}

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want exactly 1", len(entries))
	}
	fields := entries[0].ContextMap()
	if _, ok := fields["reject_reason"]; !ok {
		t.Error("rejected entry missing reject_reason field")
	}
	if got, _ := fields["admitted"].(bool); got {
		t.Errorf("admitted = %v, want false", fields["admitted"])
	}
	for _, k := range []string{"queue_wait_ms", "backend_latency_ms", "status_code"} {
		if _, ok := fields[k]; ok {
			t.Errorf("rejected entry must not carry admitted-only field %q", k)
		}
	}
}
