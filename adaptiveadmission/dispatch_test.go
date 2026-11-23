package adaptiveadmission

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestClassifyOutcome_NilError_UsesRecordedStatus(t *testing.T) {
	statusCode, timedOut := classifyOutcome(http.StatusOK, nil)
	if statusCode != http.StatusOK {
		t.Errorf("statusCode = %d, want %d", statusCode, http.StatusOK)
	}
	if timedOut {
		t.Error("timedOut = true, want false")
	}
}

func TestClassifyOutcome_HandlerError_BadGateway(t *testing.T) {
	err := caddyhttp.Error(http.StatusBadGateway, errors.New("connect refused"))
	statusCode, timedOut := classifyOutcome(http.StatusOK, err)
	if statusCode != http.StatusBadGateway {
		t.Errorf("statusCode = %d, want %d", statusCode, http.StatusBadGateway)
	}
	if timedOut {
		t.Error("timedOut = true, want false for a non-timeout HandlerError")
	}
}

func TestClassifyOutcome_HandlerError_GatewayTimeout(t *testing.T) {
	err := caddyhttp.Error(http.StatusGatewayTimeout, errors.New("upstream took too long"))
	statusCode, timedOut := classifyOutcome(http.StatusOK, err)
	if statusCode != http.StatusGatewayTimeout {
		t.Errorf("statusCode = %d, want %d", statusCode, http.StatusGatewayTimeout)
	}
	if !timedOut {
		t.Error("timedOut = false, want true for a 504 HandlerError")
	}
}

func TestClassifyOutcome_UnrecognizedError_DefaultsTo500(t *testing.T) {
	statusCode, timedOut := classifyOutcome(http.StatusOK, errors.New("something else went wrong"))
	if statusCode != http.StatusInternalServerError {
		t.Errorf("statusCode = %d, want %d", statusCode, http.StatusInternalServerError)
	}
	if timedOut {
		t.Error("timedOut = true, want false for an unrecognized error shape")
	}
}

func TestStatusRecorder_DefaultsTo200WhenWriteHeaderNeverCalled(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder(), statusCode: http.StatusOK}
	if _, err := rec.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if rec.statusCode != http.StatusOK {
		t.Errorf("statusCode = %d, want %d", rec.statusCode, http.StatusOK)
	}
}

func TestStatusRecorder_FirstWriteHeaderCallWins(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder(), statusCode: http.StatusOK}
	rec.WriteHeader(http.StatusAccepted)
	rec.WriteHeader(http.StatusInternalServerError)
	if rec.statusCode != http.StatusAccepted {
		t.Errorf("statusCode = %d, want %d (first WriteHeader call should win)", rec.statusCode, http.StatusAccepted)
	}
}

func TestStatusRecorder_FlushReachesWrappedWriter(t *testing.T) {
	inner := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: inner, statusCode: http.StatusOK}
	if err := http.NewResponseController(rec).Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if !inner.Flushed {
		t.Error("wrapped writer was not flushed")
	}
}

// hijackableRecorder is an httptest.ResponseRecorder that also supports
// Hijack, standing in for net/http's HTTP/1.1 response writer.
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	return nil, nil, nil
}

func TestStatusRecorder_HijackReachesWrappedWriter(t *testing.T) {
	inner := &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}
	rec := &statusRecorder{ResponseWriter: inner, statusCode: http.StatusOK}
	if _, _, err := http.NewResponseController(rec).Hijack(); err != nil {
		t.Fatalf("Hijack: %v", err)
	}
	if !inner.hijacked {
		t.Error("wrapped writer was not hijacked")
	}
}

func TestHandler_Dispatch_RecordsLatencyAndReleasesCapacity(t *testing.T) {
	c := NewFixedController(2)
	c.Acquire(1)
	h := &Handler{controller: c}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	if err := h.dispatch(rec, req, next, 0); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if got := c.InFlight(); got != 0 {
		t.Errorf("InFlight() = %d, want 0 after dispatch releases its cost", got)
	}
	if got := c.window.total; got != 1 {
		t.Errorf("window.total = %d, want 1", got)
	}
}

// dispatchRecovering calls h.dispatch and returns what next panicked with,
// or nil if it didn't.
func dispatchRecovering(h *Handler, r *http.Request, next caddyhttp.Handler) (panicked any) {
	defer func() { panicked = recover() }()
	_ = h.dispatch(httptest.NewRecorder(), r, next, 0)
	return nil
}

func lastOutcome(c *Controller) outcomeSample {
	return c.window.ring[(c.window.pos+c.window.size-1)%c.window.size]
}

func TestHandler_Dispatch_NextPanics_ReleasesCapacityAndRepanics(t *testing.T) {
	c := NewFixedController(1)
	c.Acquire(1)
	h := &Handler{controller: c}

	// What reverse_proxy does when copying the response body fails after
	// the headers were sent.
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		panic(http.ErrAbortHandler)
	})

	admissionMetrics.requestsInFlight.WithLabelValues(h.Config.backendLabel()).Set(1)
	if got := dispatchRecovering(h, httptest.NewRequest(http.MethodGet, "/", nil), next); got != http.ErrAbortHandler {
		t.Fatalf("recovered %v, want the next handler's own panic value http.ErrAbortHandler", got)
	}
	if got := c.InFlight(); got != 0 {
		t.Errorf("InFlight() = %d, want 0 after next panicked", got)
	}
	if got := testutil.ToFloat64(admissionMetrics.requestsInFlight.WithLabelValues(h.Config.backendLabel())); got != 0 {
		t.Errorf("requests_in_flight = %v, want 0 after next panicked", got)
	}
	if got := c.window.total; got != 1 {
		t.Fatalf("window.total = %d, want 1", got)
	}
	if last := lastOutcome(c); !last.isError || last.timedOut {
		t.Errorf("recorded outcome = %+v, want a 5xx error that is not a timeout", last)
	}
}

func TestHandler_Dispatch_NextPanicsAfterClientLeft_NotRecordedAsError(t *testing.T) {
	c := NewFixedController(1)
	c.Acquire(1)
	h := &Handler{controller: c}

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		cancel()
		panic(http.ErrAbortHandler)
	})

	if got := dispatchRecovering(h, req, next); got != http.ErrAbortHandler {
		t.Fatalf("recovered %v, want http.ErrAbortHandler", got)
	}
	if got := c.InFlight(); got != 0 {
		t.Errorf("InFlight() = %d, want 0 after next panicked", got)
	}
	if last := lastOutcome(c); last.isError || last.timedOut {
		t.Errorf("recorded outcome = %+v, want neither an error nor a timeout for a client that left", last)
	}
}
