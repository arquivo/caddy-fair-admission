package adaptiveadmission

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
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

	if got := dispatchRecovering(h, httptest.NewRequest(http.MethodGet, "/", nil), next); got != http.ErrAbortHandler {
		t.Fatalf("recovered %v, want the next handler's own panic value http.ErrAbortHandler", got)
	}
	if got := c.InFlight(); got != 0 {
		t.Errorf("InFlight() = %d, want 0 after next panicked", got)
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

func TestHandler_Dispatch_DispatchTimeout_CancelsNextAndRecordsTimeout(t *testing.T) {
	c := NewFixedController(1)
	c.Acquire(1)
	h := &Handler{Config: Config{DispatchTimeout: 20 * time.Millisecond}, controller: c}

	// A backend that never answers: next only returns once its context is
	// cancelled, as reverse_proxy does.
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		<-r.Context().Done()
		return r.Context().Err()
	})

	done := make(chan error, 1)
	go func() {
		done <- h.dispatch(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), next, 0)
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("dispatch error = %v, want next's context.DeadlineExceeded passed through", err)
		}
	case <-time.After(time.Second):
		t.Fatal("dispatch still running long after dispatch_timeout")
	}
	if got := c.InFlight(); got != 0 {
		t.Errorf("InFlight() = %d, want 0", got)
	}
	if last := lastOutcome(c); !last.timedOut || !last.isError {
		t.Errorf("recorded outcome = %+v, want a 504 timeout", last)
	}
}

func TestHandler_Dispatch_ClientLeavesBeforeDispatchTimeout_NotATimeout(t *testing.T) {
	c := NewFixedController(1)
	c.Acquire(1)
	h := &Handler{Config: Config{DispatchTimeout: time.Minute}, controller: c}

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		cancel()
		<-r.Context().Done()
		return caddyhttp.Error(statusClientClosedRequest, r.Context().Err())
	})

	_ = h.dispatch(httptest.NewRecorder(), req, next, 0)
	if last := lastOutcome(c); last.timedOut || last.isError {
		t.Errorf("recorded outcome = %+v, want neither a timeout nor an error when the client left", last)
	}
}
