package fairness

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(AdminAPI{})
}

// AdminAPI is a separate "admin.api.fairness" module exposing
// GET /fairness/status (REQUIREMENTS.md §4.10). It must be registered under
// Caddy's "admin.api" module namespace to be picked up by the admin
// server's route collection (only modules under that namespace are scanned
// for caddy.AdminRouter) — the fairness App module itself (namespace
// "fairness") is not eligible for that regardless of REQUIREMENTS.md
// §4.10's simplified "both App modules implement caddy.AdminRouter" wording.
// This mirrors the caddypki ("admin.api.pki") and reverseproxy
// ("admin.api.reverse_proxy") admin modules' own precedent exactly — see
// adaptiveadmission/admin.go for the identical pattern on that side.
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
		ID:  "admin.api.fairness",
		New: func() caddy.Module { return new(AdminAPI) },
	}
}

// Provision stashes ctx for a per-request app lookup in handleStatus. It
// cannot resolve the fairness App here and cache it once: Caddy starts the
// admin server (and provisions admin.api.* modules like this one) *before*
// it provisions the rest of the config — including the http app, whose
// handler chain is what lazily loads and registers fairness (module.go) via
// ctx.App — confirmed empirically (an earlier version of this method that
// cached the app in Provision consistently got "not configured" against a
// real running instance in integration_test.go). ctx.cfg keeps being
// populated after this Provision call returns, so a later
// ctx.AppIfConfigured call (handleStatus, at actual request time, by which
// point config provisioning has long finished) reliably finds it.
func (a *AdminAPI) Provision(ctx caddy.Context) error {
	a.ctx = ctx
	return nil
}

// resolvedApp returns the live fairness App, or nil if it isn't configured
// (see Provision's doc for why this can't be resolved once and cached).
func (a *AdminAPI) resolvedApp() *App {
	if a.app != nil {
		return a.app
	}
	appIface, err := a.ctx.AppIfConfigured("fairness")
	if err != nil {
		return nil
	}
	app, _ := appIface.(*App)
	return app
}

// Routes returns the admin routes this module serves.
func (a *AdminAPI) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{Pattern: "/fairness/status", Handler: caddy.AdminHandlerFunc(a.handleStatus)},
	}
}

// backendScoringStatus is one backend's admin-reported snapshot (§4.10):
// its fully-resolved scoring config plus per-dimension tracked-entity
// counts (not the raw per-entity EWMA values — see scoring.go's
// entryCounts doc for why counts rather than a full per-entity dump).
type backendScoringStatus struct {
	Backend              string                   `json:"backend"`
	BaseScores           map[UserClass]float64    `json:"base_scores"`
	MinScore             float64                  `json:"min_score"`
	MaxScore             float64                  `json:"max_score"`
	Dimensions           map[string]PenaltyConfig `json:"dimensions"`
	Divisors             map[string]float64       `json:"divisors"`
	DimensionEntryCounts map[string]int           `json:"dimension_entry_counts"`
}

type statusResponse struct {
	Backends []backendScoringStatus `json:"backends"`
	Shared   sharedResourceStatus   `json:"shared"`
}

// sharedResourceStatus is the App-wide pooled-resource health section
// (§4.10) — GeoIP DB readers and JWKS verifiers are shared across backend
// blocks (app.go), so they're reported once here rather than per-backend.
type sharedResourceStatus struct {
	GeoIP []resourceHealth `json:"geoip"`
	JWKS  []resourceHealth `json:"jwks"`
}

// handleStatus implements GET /fairness/status: a snapshot of every
// currently-registered backend's resolved scoring config/EWMA counters,
// plus the shared GeoIP/JWKS resource health section.
func (a *AdminAPI) handleStatus(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return caddy.APIError{HTTPStatus: http.StatusMethodNotAllowed, Err: fmt.Errorf("method not allowed")}
	}
	app := a.resolvedApp()
	if app == nil {
		return caddy.APIError{HTTPStatus: http.StatusNotFound, Err: fmt.Errorf("fairness is not configured")}
	}

	handlers := app.snapshotHandlers()
	backends := make([]backendScoringStatus, 0, len(handlers))
	for _, h := range handlers {
		cfg := h.scoring.resolvedConfig()
		backends = append(backends, backendScoringStatus{
			Backend:              h.Config.backendLabel(),
			BaseScores:           cfg.BaseScores,
			MinScore:             cfg.MinScore,
			MaxScore:             cfg.MaxScore,
			Dimensions:           cfg.Dimensions,
			Divisors:             cfg.Divisors,
			DimensionEntryCounts: h.scoring.entryCounts(),
		})
	}
	sort.Slice(backends, func(i, j int) bool { return backends[i].Backend < backends[j].Backend })

	resp := statusResponse{
		Backends: backends,
		Shared: sharedResourceStatus{
			GeoIP: app.geoHealth(),
			JWKS:  app.jwksHealth(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(resp)
}

// Interface guards.
var (
	_ caddy.Provisioner = (*AdminAPI)(nil)
	_ caddy.AdminRouter = (*AdminAPI)(nil)
)
