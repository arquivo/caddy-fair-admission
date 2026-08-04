package adaptiveadmission

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

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

	if err := h.dispatch(rec, req, next); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if got := c.InFlight(); got != 0 {
		t.Errorf("InFlight() = %d, want 0 after dispatch releases its cost", got)
	}
	if got := c.window.total; got != 1 {
		t.Errorf("window.total = %d, want 1", got)
	}
}
