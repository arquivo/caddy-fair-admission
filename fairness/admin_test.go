package fairness

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// newTestFairnessHandler builds a Handler with a working scoringState
// without going through Provision (which requires a real caddy.Context/App) —
// exactly the fields handleStatus reads.
func newTestFairnessHandler(backend string) *Handler {
	cfg := newDefaultScoringConfig()
	scoring := newScoringState(cfg, defaultEWMATickInterval, defaultIdleEntryTTL)
	return &Handler{
		Config:  Config{Backend: backend},
		scoring: scoring,
	}
}

func TestAdminAPI_HandleStatus_NotConfigured(t *testing.T) {
	a := &AdminAPI{}
	req := httptest.NewRequest(http.MethodGet, "/fairness/status", nil)
	rec := httptest.NewRecorder()

	err := a.handleStatus(rec, req)

	var apiErr caddy.APIError
	if !errors.As(err, &apiErr) || apiErr.HTTPStatus != http.StatusNotFound {
		t.Fatalf("handleStatus error = %v, want a 404 caddy.APIError", err)
	}
}

func TestAdminAPI_HandleStatus_MethodNotAllowed(t *testing.T) {
	a := &AdminAPI{app: &App{}}
	req := httptest.NewRequest(http.MethodPost, "/fairness/status", nil)
	rec := httptest.NewRecorder()

	err := a.handleStatus(rec, req)

	var apiErr caddy.APIError
	if !errors.As(err, &apiErr) || apiErr.HTTPStatus != http.StatusMethodNotAllowed {
		t.Fatalf("handleStatus error = %v, want a 405 caddy.APIError", err)
	}
}

func TestAdminAPI_HandleStatus_ReportsRegisteredBackendsAndSharedHealth(t *testing.T) {
	app := &App{}
	h := newTestFairnessHandler("b1")
	h.scoring.track(Classification{IP: "203.0.113.5", UserClass: UserClassResearcher}, time.Now())
	app.registerHandler("b1", h)

	a := &AdminAPI{app: app}
	req := httptest.NewRequest(http.MethodGet, "/fairness/status", nil)
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
	if got.Backend != "b1" || got.MinScore != 0 || got.MaxScore != 100 {
		t.Errorf("backend status = %+v, want backend=b1 min_score=0 max_score=100", got)
	}
	if got.DimensionEntryCounts["ip"] != 1 {
		t.Errorf(`dimension_entry_counts["ip"] = %d, want 1`, got.DimensionEntryCounts["ip"])
	}
	if len(body.Shared.GeoIP) != 0 || len(body.Shared.JWKS) != 0 {
		t.Errorf("shared health = %+v, want empty (no pooled resources registered on this App)", body.Shared)
	}
}

func TestAdminAPI_HandleStatus_SortsBackendsByLabel(t *testing.T) {
	app := &App{}
	app.registerHandler("zzz", newTestFairnessHandler("zzz"))
	app.registerHandler("aaa", newTestFairnessHandler("aaa"))

	a := &AdminAPI{app: app}
	req := httptest.NewRequest(http.MethodGet, "/fairness/status", nil)
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

func TestAdminAPI_HandleStatus_ReportsPriorityNetworks(t *testing.T) {
	app := &App{}
	h := newTestFairnessHandler("b1")
	h.PriorityNetworks = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("::1/128")}
	app.registerHandler("b1", h)
	app.registerHandler("b2", newTestFairnessHandler("b2"))

	a := &AdminAPI{app: app}
	req := httptest.NewRequest(http.MethodGet, "/fairness/status", nil)
	rec := httptest.NewRecorder()
	if err := a.handleStatus(rec, req); err != nil {
		t.Fatalf("handleStatus: %v", err)
	}

	var body struct {
		Backends []map[string]any `json:"backends"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Backends) != 2 {
		t.Fatalf("backends = %+v, want 2 entries", body.Backends)
	}
	got, _ := json.Marshal(body.Backends[0]["priority_networks"])
	if string(got) != `["192.0.2.0/24","::1/128"]` {
		t.Errorf("b1 priority_networks = %s, want [\"192.0.2.0/24\",\"::1/128\"]", got)
	}
	if _, ok := body.Backends[1]["priority_networks"]; ok {
		t.Errorf("b2 priority_networks = %v, want the field omitted", body.Backends[1]["priority_networks"])
	}
}
