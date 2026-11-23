package adaptiveadmission

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(AdminAPI{})
}

// AdminAPI is a separate "admin.api.adaptive_admission" module exposing
// GET /adaptive_admission/status (REQUIREMENTS.md §4.10). It must be
// registered under Caddy's "admin.api" module namespace to be picked up by
// the admin server's route collection (see admin.go in Caddy's own source:
// only modules under that namespace are scanned for caddy.AdminRouter) —
// the adaptive_admission App module itself (namespace "adaptive_admission")
// is not eligible for that regardless of REQUIREMENTS.md §4.10's simplified
// "both App modules implement caddy.AdminRouter" wording. This mirrors the
// caddypki ("admin.api.pki") and reverseproxy ("admin.api.reverse_proxy")
// admin modules' own precedent exactly.
//
// Per Config's doc comment (config.go), this module has no upstream/load-
// balancer state of its own to report — that's Caddy's own reverse_proxy
// directive's concern, already exposed via its own admin.api.reverse_proxy
// module (GET /reverse_proxy/upstreams). So the "upstream snapshot" field
// REQUIREMENTS.md §4.10 mentions is intentionally omitted here rather than
// duplicated.
type AdminAPI struct {
	ctx caddy.Context

	// app, if set directly (bypassing Provision), overrides the ctx-based
	// lookup below — used by admin_test.go to exercise handleStatus without
	// a real caddy.Context.
	app *App
}

// CaddyModule returns the Caddy module information.
func (AdminAPI) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.adaptive_admission",
		New: func() caddy.Module { return new(AdminAPI) },
	}
}

// Provision stashes ctx for a per-request app lookup in handleStatus. It
// cannot resolve the adaptive_admission App here and cache it once: Caddy
// starts the admin server (and provisions admin.api.* modules like this one)
// *before* it provisions the rest of the config — including the http app,
// whose handler chain is what lazily loads and registers adaptive_admission
// via ctx.App (module.go) — confirmed empirically (an earlier version of
// this method that cached the app in Provision consistently got "not
// configured" against a real running instance in integration_test.go).
// ctx.cfg keeps being populated after this Provision call returns, so a
// later ctx.AppIfConfigured call (handleStatus, at actual request time, by
// which point config provisioning has long finished) reliably finds it.
func (a *AdminAPI) Provision(ctx caddy.Context) error {
	a.ctx = ctx
	return nil
}

// resolvedApp returns the live adaptive_admission App, or nil if it isn't
// configured (see Provision's doc for why this can't be resolved once and
// cached).
func (a *AdminAPI) resolvedApp() *App {
	if a.app != nil {
		return a.app
	}
	appIface, err := a.ctx.AppIfConfigured("adaptive_admission")
	if err != nil {
		return nil
	}
	app, _ := appIface.(*App)
	return app
}

// Routes returns the admin routes this module serves.
func (a *AdminAPI) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{Pattern: "/adaptive_admission/status", Handler: caddy.AdminHandlerFunc(a.handleStatus)},
	}
}

// backendControllerStatus is one backend's admin-reported snapshot (§4.10):
// controller kind/limit/latency plus current queue depth.
type backendControllerStatus struct {
	Backend        string  `json:"backend"`
	ControllerKind string  `json:"controller_kind"`
	Limit          int     `json:"limit"`
	InFlight       int     `json:"in_flight"`
	MeanLatencyMs  float64 `json:"mean_latency_ms"`
	QueueSize      int     `json:"queue_size"`
}

type statusResponse struct {
	Backends []backendControllerStatus `json:"backends"`
}

// handleStatus implements GET /adaptive_admission/status: a snapshot of
// every currently-registered backend's controller/queue state.
func (a *AdminAPI) handleStatus(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return caddy.APIError{HTTPStatus: http.StatusMethodNotAllowed, Err: fmt.Errorf("method not allowed")}
	}
	app := a.resolvedApp()
	if app == nil {
		return caddy.APIError{HTTPStatus: http.StatusNotFound, Err: fmt.Errorf("adaptive_admission is not configured")}
	}

	handlers := app.snapshotHandlers()
	backends := make([]backendControllerStatus, 0, len(handlers))
	for _, h := range handlers {
		backends = append(backends, backendControllerStatus{
			Backend:        h.Config.backendLabel(),
			ControllerKind: h.controller.Kind().String(),
			Limit:          h.controller.Limit(),
			InFlight:       h.controller.InFlight(),
			MeanLatencyMs:  float64(h.controller.MeanLatency()) / float64(time.Millisecond),
			QueueSize:      h.scheduler.Depth(),
		})
	}
	sort.Slice(backends, func(i, j int) bool { return backends[i].Backend < backends[j].Backend })

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(statusResponse{Backends: backends})
}

// Interface guards.
var (
	_ caddy.Provisioner = (*AdminAPI)(nil)
	_ caddy.AdminRouter = (*AdminAPI)(nil)
)
