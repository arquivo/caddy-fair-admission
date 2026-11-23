package adaptiveadmission

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// dispatch calls next (§4.7 — normally Caddy's own reverse_proxy directive,
// chained immediately after adaptive_admission per RegisterDirectiveOrder in
// module.go) while timing the call, then records the outcome onto the
// Controller, releases the ticket's one unit of capacity, and emits the
// request's structured log line (§4.9). This is the only place capacity
// granted by ServeHTTP's Enqueue/Granted gets released.
//
// The release runs in a deferred call, so it also happens when next panics:
// reverse_proxy panics with http.ErrAbortHandler when copying a response
// body fails after the headers were sent (the client or the upstream went
// away mid-body), and net/http recovers that panic silently. The panic is
// not recovered here; it carries on to net/http once the slot is given back.
//
// With DispatchTimeout set, next gets a request context that is cancelled
// once it elapses, so a backend that never answers can't hold the slot for
// longer than that.
func (h *Handler) dispatch(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, queueWait time.Duration) (err error) {
	rec := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}

	clientCtx := r.Context()
	if h.DispatchTimeout > 0 {
		ctx, cancel := context.WithTimeout(clientCtx, h.DispatchTimeout)
		defer cancel()
		r = r.WithContext(ctx)
	}

	start := time.Now()
	panicked := true
	defer func() {
		latency := time.Since(start)
		statusCode, timedOut := classifyOutcome(rec.statusCode, err)
		if panicked {
			statusCode, timedOut = classifyAbort(clientCtx)
		}
		if (panicked || err != nil) && dispatchTimedOut(clientCtx, r.Context()) {
			statusCode, timedOut = http.StatusGatewayTimeout, true
		}
		h.controller.Release(1, latency, statusCode, timedOut)

		backend := h.Config.backendLabel()
		admissionMetrics.requestsInFlight.WithLabelValues(backend).Set(float64(h.controller.InFlight()))
		admissionMetrics.requestDuration.WithLabelValues(backend).Observe(latency.Seconds())
		if timedOut {
			admissionMetrics.backendTimeouts.WithLabelValues(backend).Inc()
		}
		if statusCode >= 500 {
			admissionMetrics.backendErrors.WithLabelValues(backend).Inc()
		}

		h.logDecision(r, logDecisionParams{
			backend:    backend,
			admitted:   true,
			queueWait:  queueWait,
			latency:    latency,
			statusCode: statusCode,
		})
	}()

	err = next.ServeHTTP(rec, r)
	panicked = false
	return err
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

// classifyAbort derives the outcome to record when next panicked instead of
// returning. A client that went away is not the backend's fault, so it is
// recorded as 499, which the adaptive controller doesn't count as an error,
// the same as reverse_proxy reports a client that disconnects before the
// response starts. Anything else is recorded as a 500.
func classifyAbort(clientCtx context.Context) (statusCode int, timedOut bool) {
	if clientCtx.Err() != nil {
		return statusClientClosedRequest, false
	}
	return http.StatusInternalServerError, false
}

// dispatchTimedOut reports whether dispatchCtx was cancelled by
// DispatchTimeout rather than by the client going away.
func dispatchTimedOut(clientCtx, dispatchCtx context.Context) bool {
	return clientCtx.Err() == nil && errors.Is(dispatchCtx.Err(), context.DeadlineExceeded)
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
