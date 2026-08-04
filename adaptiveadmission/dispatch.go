package adaptiveadmission

import (
	"errors"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// dispatchOutcome reports what happened during a dispatch call, for
// ServeHTTP to fold into its structured log line (§4.9) after dispatch
// returns.
type dispatchOutcome struct {
	statusCode int
	latency    time.Duration
	timedOut   bool
}

// dispatch calls next (§4.7 — normally Caddy's own reverse_proxy directive,
// chained immediately after adaptive_admission per RegisterDirectiveOrder in
// module.go) while timing the call, then records the outcome onto the
// Controller and releases the ticket's one unit of capacity. This is the
// only place capacity granted by ServeHTTP's Enqueue/Granted gets released —
// every path below calls Release exactly once.
func (h *Handler) dispatch(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) (dispatchOutcome, error) {
	rec := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}

	start := time.Now()
	err := next.ServeHTTP(rec, r)
	latency := time.Since(start)

	statusCode, timedOut := classifyOutcome(rec.statusCode, err)
	h.controller.Release(1, latency, statusCode, timedOut)

	backend := h.Config.backendLabel()
	admissionMetrics.requestDuration.WithLabelValues(backend).Observe(latency.Seconds())
	if timedOut {
		admissionMetrics.backendTimeouts.WithLabelValues(backend).Inc()
	}
	if statusCode >= 500 {
		admissionMetrics.backendErrors.WithLabelValues(backend).Inc()
	}

	return dispatchOutcome{statusCode: statusCode, latency: latency, timedOut: timedOut}, err
}

// classifyOutcome derives the status code and timeout classification to
// record for this outcome (§4.4's release(cost, latency_ms, status_code,
// timed_out)). recordedStatus is what the response writer actually wrote
// (meaningful when next succeeded); err is what next.ServeHTTP returned.
// reverse_proxy surfaces connect failures and round-trip timeouts as a
// caddyhttp.HandlerError rather than by writing a response directly (§4.7) —
// an upstream's own 5xx *response* is not an error at all and is read from
// recordedStatus instead.
func classifyOutcome(recordedStatus int, err error) (statusCode int, timedOut bool) {
	if err == nil {
		return recordedStatus, false
	}
	var he caddyhttp.HandlerError
	if errors.As(err, &he) && he.StatusCode != 0 {
		return he.StatusCode, he.StatusCode == http.StatusGatewayTimeout
	}
	// Unrecognized error shape: still record it as admitted-but-failed
	// rather than silently counting it as a success.
	return http.StatusInternalServerError, false
}

// statusRecorder captures the status code the wrapped handler actually
// wrote, defaulting to 200 to match net/http's own behavior when
// WriteHeader is never called explicitly.
type statusRecorder struct {
	http.ResponseWriter
	statusCode  int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.statusCode = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	r.wroteHeader = true
	return r.ResponseWriter.Write(b)
}
