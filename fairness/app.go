package fairness

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(new(App))
}

// App is the fairness app module (namespace "fairness"). It holds resources
// shared across fairness handler blocks within one Caddy config — GeoIP DB
// readers and JWKS verifiers/refresh loops — deduped by resource identity
// (DB file path, JWKS URL) via caddy.UsagePool, so two blocks referencing
// the same resource share one open reader / refresh loop rather than each
// opening/starting their own (REQUIREMENTS.md §3.1).
//
// Per-backend EWMA scoring state (§3.2/§4.3) deliberately does NOT live
// here (§7 Q6) — each fairness Handler instance keeps its own, isolated per
// backend. Instead, App keeps a registry of the live Handler instances
// themselves (populated in Handler.Provision, cleared in Handler.Cleanup)
// so the admin introspection API (admin.go, §4.10) can read each backend's
// resolved config/EWMA counters without that state living on App.
type App struct {
	geoPool  *caddy.UsagePool
	authPool *caddy.UsagePool

	mu       sync.Mutex
	handlers map[string]*Handler
}

// CaddyModule returns the Caddy module information.
func (*App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "fairness",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision sets up the app's shared resource pools and registers this
// config load's Prometheus collectors (metrics.go) against ctx's registry.
func (a *App) Provision(ctx caddy.Context) error {
	a.geoPool = caddy.NewUsagePool()
	a.authPool = caddy.NewUsagePool()
	a.handlers = make(map[string]*Handler)
	initFairnessMetrics(ctx.GetMetricsRegistry())
	return nil
}

// Start starts the app module.
func (a *App) Start() error {
	return nil
}

// Stop stops the app module.
func (a *App) Stop() error {
	return nil
}

// acquireGeoReader returns a shared *geoReader for path, opening it (fail-
// open, see geoip.go) if this is the first reference, or reusing the
// existing one and incrementing its refcount otherwise. An empty path
// returns (nil, nil) without touching the pool at all — callers should
// treat a nil *geoReader as "this DB isn't configured".
func (a *App) acquireGeoReader(path string) (*geoReader, error) {
	if path == "" {
		return nil, nil
	}
	key := geoPoolKey(path)
	val, _, err := a.geoPool.LoadOrNew(key, openGeoReader(path))
	if err != nil {
		return nil, err
	}
	reader, ok := val.(*geoReader)
	if !ok {
		return nil, fmt.Errorf("fairness: unexpected type %T in GeoIP pool for %q", val, path)
	}
	return reader, nil
}

// releaseGeoReader releases this handler's reference to the reader opened
// for path (a no-op if path is empty). Once the last reference is released,
// the pool closes the underlying *geoip2.Reader.
func (a *App) releaseGeoReader(path string) {
	if path == "" {
		return
	}
	_, _ = a.geoPool.Delete(geoPoolKey(path))
}

// geoPoolKey normalizes a configured DB path into the GeoIP pool's key, so
// equivalent-but-differently-spelled paths (relative vs. absolute) across
// blocks still dedupe onto the same pool entry.
func geoPoolKey(path string) string {
	if abs, err := caddy.FastAbs(path); err == nil {
		return abs
	}
	return path
}

// acquireVerifier returns a *verifier backed by the shared JWKS refresh
// loop for jwksURL (opening it, fail-open, if this is the first reference),
// scoped with this block's own issuer/audience expectations. An empty
// jwksURL returns (nil, nil) without touching the pool — callers should
// treat a nil *verifier as "auth isn't configured on this block".
func (a *App) acquireVerifier(jwksURL, issuer, audience string, refreshInterval time.Duration) (*verifier, error) {
	if jwksURL == "" {
		return nil, nil
	}
	if refreshInterval <= 0 {
		refreshInterval = defaultJWKSRefreshInterval
	}
	val, _, err := a.authPool.LoadOrNew(jwksURL, openJWKSVerifier(jwksURL, refreshInterval))
	if err != nil {
		return nil, err
	}
	jv, ok := val.(*jwksVerifier)
	if !ok {
		return nil, fmt.Errorf("fairness: unexpected type %T in JWKS pool for %q", val, jwksURL)
	}
	return &verifier{kf: jv.kf, issuer: issuer, audience: audience}, nil
}

// releaseVerifier releases this handler's reference to the JWKS refresh
// loop for jwksURL (a no-op if jwksURL is empty). Once the last reference is
// released, the pool cancels the background refresh goroutine.
func (a *App) releaseVerifier(jwksURL string) {
	if jwksURL == "" {
		return
	}
	_, _ = a.authPool.Delete(jwksURL)
}

// registerHandler records h as the live Handler for backend, for the admin
// introspection API (admin.go, §4.10) — overwriting any previous
// registration under the same label (a config reload replaces rather than
// accumulates).
func (a *App) registerHandler(backend string, h *Handler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.handlers == nil {
		a.handlers = make(map[string]*Handler)
	}
	a.handlers[backend] = h
}

// unregisterHandler removes backend's registration, if h is still the
// currently-registered Handler for it (guards against a Cleanup racing a
// newer Provision during a reload from clobbering the newer registration).
func (a *App) unregisterHandler(backend string, h *Handler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.handlers[backend] == h {
		delete(a.handlers, backend)
	}
}

// snapshotHandlers returns the currently registered Handlers, sorted by
// backend label for deterministic admin API output.
func (a *App) snapshotHandlers() []*Handler {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*Handler, 0, len(a.handlers))
	for _, h := range a.handlers {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Config.backendLabel() < out[j].Config.backendLabel()
	})
	return out
}

// resourceHealth is one shared pooled resource's admin-reported health
// (admin.go, §4.10): whether it's actually usable (vs. configured-but-
// failed-open) and how many handler blocks currently reference it.
type resourceHealth struct {
	Key        string `json:"key"`
	Healthy    bool   `json:"healthy"`
	References int    `json:"references"`
}

// geoHealth snapshots every currently-pooled GeoIP reader's health, sorted
// by key for deterministic output. A reader is "healthy" if geoip2.Open
// actually succeeded for it (see geoReader/openGeoReader, geoip.go) —
// otherwise it's pooled but permanently fails open on every lookup.
func (a *App) geoHealth() []resourceHealth {
	return poolHealth(a.geoPool, func(v any) bool {
		r, ok := v.(*geoReader)
		return ok && r != nil && r.reader != nil
	})
}

// jwksHealth snapshots every currently-pooled JWKS verifier's health, sorted
// by key. A verifier is "healthy" if its background refresh loop actually
// obtained a keyfunc.Keyfunc (see jwksVerifier/openJWKSVerifier, auth.go) —
// otherwise it's pooled but permanently fails open (treated as unauthenticated).
func (a *App) jwksHealth() []resourceHealth {
	return poolHealth(a.authPool, func(v any) bool {
		jv, ok := v.(*jwksVerifier)
		return ok && jv != nil && jv.kf != nil
	})
}

// poolHealth walks pool, reporting each entry's key, reference count, and
// healthy(entry) — pool may be nil (an unprovisioned App), in which case it
// returns an empty slice rather than panicking.
func poolHealth(pool *caddy.UsagePool, healthy func(any) bool) []resourceHealth {
	if pool == nil {
		return nil
	}
	var out []resourceHealth
	pool.Range(func(key, val any) bool {
		k, _ := key.(string)
		refs, _ := pool.References(key)
		out = append(out, resourceHealth{Key: k, Healthy: healthy(val), References: refs})
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Interface guards.
var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
)
