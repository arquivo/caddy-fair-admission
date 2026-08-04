package adaptiveadmission

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// newTestHandler builds a Handler with a working controller/scheduler pair
// without going through Provision (which requires a real caddy.Context) —
// exactly the fields handleStatus reads.
func newTestHandler(backend string, limit int) *Handler {
	controller := NewFixedController(limit)
	scheduler := NewScheduler(QueueConfig{}, controller)
	return &Handler{
		Config:     Config{Backend: backend},
		controller: controller,
		scheduler:  scheduler,
	}
}

func TestAdminAPI_HandleStatus_NotConfigured(t *testing.T) {
	a := &AdminAPI{}
	req := httptest.NewRequest(http.MethodGet, "/adaptive_admission/status", nil)
	rec := httptest.NewRecorder()

	err := a.handleStatus(rec, req)

	var apiErr caddy.APIError
	if !errors.As(err, &apiErr) || apiErr.HTTPStatus != http.StatusNotFound {
		t.Fatalf("handleStatus error = %v, want a 404 caddy.APIError", err)
	}
}

func TestAdminAPI_HandleStatus_MethodNotAllowed(t *testing.T) {
	a := &AdminAPI{app: &App{}}
	req := httptest.NewRequest(http.MethodPost, "/adaptive_admission/status", nil)
	rec := httptest.NewRecorder()

	err := a.handleStatus(rec, req)

	var apiErr caddy.APIError
	if !errors.As(err, &apiErr) || apiErr.HTTPStatus != http.StatusMethodNotAllowed {
		t.Fatalf("handleStatus error = %v, want a 405 caddy.APIError", err)
	}
}

func TestAdminAPI_HandleStatus_ReportsRegisteredBackends(t *testing.T) {
	app := &App{}
	h := newTestHandler("b1", 5)
	app.registerHandler("b1", h)

	a := &AdminAPI{app: app}
	req := httptest.NewRequest(http.MethodGet, "/adaptive_admission/status", nil)
	rec := httptest.NewRecorder()

	if err := a.handleStatus(rec, req); err != nil {
		t.Fatalf("handleStatus: %v", err)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	var body statusResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Backends) != 1 {
		t.Fatalf("backends = %+v, want 1 entry", body.Backends)
	}
	got := body.Backends[0]
	if got.Backend != "b1" || got.ControllerKind != "fixed" || got.Limit != 5 || got.InFlight != 0 || got.QueueSize != 0 {
		t.Errorf("backend status = %+v, want backend=b1 controller_kind=fixed limit=5 in_flight=0 queue_size=0", got)
	}
}

func TestAdminAPI_HandleStatus_SortsBackendsByLabel(t *testing.T) {
	app := &App{}
	app.registerHandler("zzz", newTestHandler("zzz", 1))
	app.registerHandler("aaa", newTestHandler("aaa", 1))

	a := &AdminAPI{app: app}
	req := httptest.NewRequest(http.MethodGet, "/adaptive_admission/status", nil)
	rec := httptest.NewRecorder()
	if err := a.handleStatus(rec, req); err != nil {
		t.Fatalf("handleStatus: %v", err)
	}

	var body statusResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Backends) != 2 || body.Backends[0].Backend != "aaa" || body.Backends[1].Backend != "zzz" {
		t.Fatalf("backends = %+v, want [aaa zzz]", body.Backends)
	}
}
