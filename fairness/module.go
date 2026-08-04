// Package fairness implements the http.handlers.fairness Caddy module: ingress
// consumption, classification, and EWMA-based scoring/penalties (REQUIREMENTS.md §4.1-§4.3).
package fairness

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("fairness", parseCaddyfile)
}

// classificationVarKey is the caddyhttp variable key this handler writes its
// computed Classification to (§3.1's caddyhttp.SetVar/GetVar hand-off
// mechanism). Later handlers in the same chain (Phase 5 scoring, and
// eventually adaptive_admission) read it back via
// caddyhttp.GetVar(r.Context(), classificationVarKey).
const classificationVarKey = "fairness_classification"

// Handler is the http.handlers.fairness middleware. It consumes Caddy's
// already-resolved client IP (§4.1) and computes a Classification (§4.2) for
// each request. Config is embedded so both Caddyfile and JSON config flow
// through the same fields.
type Handler struct {
	Config

	app  *App
	geo  *geoLookup
	auth *verifier
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.fairness",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the handler: it looks up the fairness App module and
// acquires (via its UsagePools) the GeoIP readers and JWKS verifier this
// block's config asks for. An empty path/URL for any of these means that
// resource simply isn't configured on this block — no pool interaction, no
// error.
func (h *Handler) Provision(ctx caddy.Context) error {
	appIface, err := ctx.App("fairness")
	if err != nil {
		return err
	}
	app, ok := appIface.(*App)
	if !ok {
		return fmt.Errorf("fairness: unexpected app module type %T", appIface)
	}
	h.app = app

	geo := &geoLookup{}
	if h.GeoIPCityDB != "" {
		reader, err := app.acquireGeoReader(h.GeoIPCityDB)
		if err != nil {
			return err
		}
		geo.city = reader
	}
	if h.GeoIPASNDB != "" {
		reader, err := app.acquireGeoReader(h.GeoIPASNDB)
		if err != nil {
			return err
		}
		geo.asn = reader
	}
	h.geo = geo

	if h.AuthJWKSURL != "" {
		v, err := app.acquireVerifier(h.AuthJWKSURL, h.AuthIssuer, h.AuthAudience, defaultJWKSRefreshInterval)
		if err != nil {
			return err
		}
		h.auth = v
	}

	return nil
}

// Cleanup implements caddy.CleanerUpper: it releases this handler's
// references to any shared GeoIP readers / JWKS verifier it acquired in
// Provision, so the last handler referencing a given resource (e.g. after a
// config reload replaces this instance) causes the pool to actually close
// it.
func (h *Handler) Cleanup() error {
	if h.app == nil {
		return nil
	}
	if h.GeoIPCityDB != "" {
		h.app.releaseGeoReader(h.GeoIPCityDB)
	}
	if h.GeoIPASNDB != "" {
		h.app.releaseGeoReader(h.GeoIPASNDB)
	}
	if h.AuthJWKSURL != "" {
		h.app.releaseVerifier(h.AuthJWKSURL)
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler. It computes the
// request's Classification and hands it off to later handlers in the chain
// via caddyhttp.SetVar (§3.1), then proceeds — this handler never rejects a
// request itself.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip := resolveClientIP(r)
	classification := classify(&h.Config, h.geo, h.auth, ip, r)
	caddyhttp.SetVar(r.Context(), classificationVarKey, classification)
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens, per the §5
// schema. The `scoring { }` sub-block belongs to Phase 5 (§4.3) and is
// intentionally consumed-but-ignored here rather than rejected, since
// shared_fairness_defaults-style snippets may already carry it.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "geoip_city_db":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.GeoIPCityDB = d.Val()

			case "geoip_asn_db":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.GeoIPASNDB = d.Val()

			case "auth_issuer":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.AuthIssuer = d.Val()

			case "auth_jwks_url":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.AuthJWKSURL = d.Val()

			case "auth_audience":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.AuthAudience = d.Val()

			case "exempt_country":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.ExemptCountries = append(h.ExemptCountries, d.Val())

			case "ipv6_prefix_length":
				if !d.NextArg() {
					return d.ArgErr()
				}
				n, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid ipv6_prefix_length %q: %v", d.Val(), err)
				}
				if n != 48 && n != 56 {
					return d.Errf("ipv6_prefix_length must be 48 or 56, got %d", n)
				}
				h.IPv6PrefixLength = n

			case "ewma_tick_interval":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid ewma_tick_interval %q: %v", d.Val(), err)
				}
				h.EWMATickInterval = dur

			case "idle_entry_ttl":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid idle_entry_ttl %q: %v", d.Val(), err)
				}
				h.IdleEntryTTL = dur

			case "scoring":
				// Phase 5 sub-block (§4.3) — not handled by this phase yet;
				// consume its tokens without erroring so §5-schema
				// Caddyfiles still parse.
				for d.NextBlock(1) {
				}

			default:
				return d.Errf("unrecognized fairness subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Handler
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
