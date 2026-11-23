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
// A request that switches protocols (e.g. a WebSocket upgrade) is finished
// as soon as the switch is written, so the tunnel that follows neither holds
// a slot nor counts towards latency. That is a 101 to an HTTP/1.x Upgrade
// request, or a 2xx to a CONNECT request (WebSocket over HTTP/2 or HTTP/3
// answers an extended CONNECT with 200).
//
// Any other request is finished in a deferred call, so it also happens
// when next panics: reverse_proxy panics with http.ErrAbortHandler when
// copying a response body fails after the headers were sent (the client or
// the upstream went away mid-body), and net/http recovers that panic
// silently. The panic is not recovered here; it carries on to net/http once
// the slot is given back.
func (h *Handler) dispatch(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, queueWait time.Duration) (err error) {
	start := time.Now()
	finished := false
	finish := func(statusCode int, timedOut bool) {
		finished = true
		latency := time.Since(start)
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
	}

	rec := &statusRecorder{
		ResponseWriter:    w,
		statusCode:        http.StatusOK,
		upgrade:           r.ProtoMajor == 1 && r.Header.Get("Upgrade") != "",
		connect:           r.Method == http.MethodConnect,
		onSwitchProtocols: func(code int) { finish(code, false) },
	}

	panicked := true
	defer func() {
		if finished {
			return
		}
		if panicked {
			finish(classifyAbort(r.Context()), false)
		} else {
			finish(classifyOutcome(rec.statusCode, err))
		}
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

// classifyAbort derives the status code to record when next panicked
// instead of returning. A client that went away is not the backend's fault,
// so it is recorded as 499, which the adaptive controller doesn't count as
// an error. Anything else is recorded as a 500.
func classifyAbort(ctx context.Context) int {
	if ctx.Err() != nil {
		return statusClientClosedRequest
	}
	return http.StatusInternalServerError
}

// statusRecorder captures the final status code the wrapped handler
// actually wrote, defaulting to 200 to match net/http's own behavior when
// WriteHeader is never called explicitly. Informational responses (1xx,
// e.g. 100 Continue or 103 Early Hints) come before the final status and
// are not recorded. A status that switches protocols (a 101 when upgrade
// is set, a 2xx when connect is set) is final and calls onSwitchProtocols.
type statusRecorder struct {
	http.ResponseWriter
	statusCode        int
	wroteHeader       bool
	upgrade           bool // the request is an HTTP/1.x Upgrade request
	connect           bool // the request is a CONNECT request
	onSwitchProtocols func(code int)
}

func (r *statusRecorder) WriteHeader(code int) {
	r.ResponseWriter.WriteHeader(code)
	if r.wroteHeader {
		return
	}
	switched := (r.upgrade && code == http.StatusSwitchingProtocols) ||
		(r.connect && code >= http.StatusOK && code < http.StatusMultipleChoices)
	if code < http.StatusOK && !switched {
		return
	}
	r.statusCode = code
	r.wroteHeader = true
	if switched && r.onSwitchProtocols != nil {
		r.onSwitchProtocols(code)
	}
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	r.wroteHeader = true
	return r.ResponseWriter.Write(b)
}

// Unwrap lets http.NewResponseController reach the wrapped writer's optional
// methods, such as the Flush and Hijack that reverse_proxy uses for streamed
// responses and protocol upgrades (e.g. WebSocket).
func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}
