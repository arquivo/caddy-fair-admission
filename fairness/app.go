package fairness

import (
	"fmt"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(App{})
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
// backend.
type App struct {
	geoPool  *caddy.UsagePool
	authPool *caddy.UsagePool
}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
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

// Interface guards.
var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
)
