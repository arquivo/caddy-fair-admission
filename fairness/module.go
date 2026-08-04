// Package fairness implements the http.handlers.fairness Caddy module: ingress
// consumption, classification, and EWMA-based scoring/penalties (REQUIREMENTS.md §4.1-§4.3).
package fairness

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

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

// fairnessScoreVarKey is the caddyhttp variable key this handler writes its
// computed fairness score to (§4.3). Documented in REQUIREMENTS.md §3.1 as
// becoming usable as the Caddy placeholder {vars.fairness_score} — the
// string value is load-bearing, not just an internal convention.
const fairnessScoreVarKey = "fairness_score"

// Handler is the http.handlers.fairness middleware. It consumes Caddy's
// already-resolved client IP (§4.1), computes a Classification (§4.2), and
// scores the request (§4.3) for each request. Config is embedded so both
// Caddyfile and JSON config flow through the same fields.
//
// ServeHTTP uses a pointer receiver (not value) because scoring holds a
// *scoringState backed by per-dimension mutexes and background goroutines —
// see scoring.go. Holding it via a pointer field means copying a Handler
// value would only copy the pointer, not the mutexes themselves, but the
// pointer receiver is kept throughout for consistency and to avoid ever
// tempting a future change to store scoringState by value.
type Handler struct {
	Config

	app  *App
	geo  *geoLookup
	auth *verifier

	// scoringOverrides holds only the fields a `scoring { }` sub-block
	// explicitly specified (nil if the block was absent entirely); resolved
	// onto defaults in Provision via resolveScoringConfig (scoring.go).
	scoringOverrides *scoringOverrides
	// scoring is this instance's isolated EWMA scoring state (§3.2/§7 Q6),
	// constructed fresh in Provision and torn down in Cleanup.
	scoring *scoringState
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

	// Scoring state (§3.2/§4.3) is constructed fresh here, isolated per
	// Handler instance (§7 Q6) — never carried over across a config reload
	// (§3.3): every Provision call gets brand-new maps and a brand-new pair
	// of background goroutines.
	resolved := resolveScoringConfig(h.scoringOverrides)
	h.scoring = newScoringState(resolved, h.Config.ewmaTickInterval(), h.Config.idleEntryTTL())
	h.scoring.start()

	return nil
}

// Cleanup implements caddy.CleanerUpper: it releases this handler's
// references to any shared GeoIP readers / JWKS verifier it acquired in
// Provision, so the last handler referencing a given resource (e.g. after a
// config reload replaces this instance) causes the pool to actually close
// it. It also stops this instance's own EWMA-tick and idle-GC goroutines
// (scoring.go) — required so a config reload's old Handler instance doesn't
// leak background goroutines once it's replaced (§3.3).
func (h *Handler) Cleanup() error {
	h.scoring.stop()

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
// request's Classification and fairness score and hands both off to later
// handlers in the chain via caddyhttp.SetVar (§3.1), then proceeds — this
// handler never rejects a request itself.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip := resolveClientIP(r)
	classification := classify(&h.Config, h.geo, h.auth, ip, r)
	caddyhttp.SetVar(r.Context(), classificationVarKey, classification)

	now := time.Now()
	h.scoring.track(classification, now)
	score := h.scoring.computeScore(classification, h.Config.exemptCountrySet())
	caddyhttp.SetVar(r.Context(), fairnessScoreVarKey, score)

	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens, per the §5
// schema. The `scoring { }` sub-block (§4.3) is parsed by parseScoringBlock
// into a *scoringOverrides, later resolved onto defaults in Provision.
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
				overrides, err := parseScoringBlock(d)
				if err != nil {
					return err
				}
				h.scoringOverrides = overrides

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

// parseScoringBlock parses a `scoring { }` sub-block's tokens (§4.3/§5) into
// a *scoringOverrides, later overlaid onto newDefaultScoringConfig() by
// resolveScoringConfig (scoring.go). Grammar:
//
//	scoring {
//	    base_score <user_class> <float>          # repeatable
//	    penalty <dimension> alpha=<f> soft=<f>:<f> hard=<f>:<f>  # repeatable
//	    min_score <float>
//	    max_score <float>
//	}
func parseScoringBlock(d *caddyfile.Dispenser) (*scoringOverrides, error) {
	o := &scoringOverrides{}

	for d.NextBlock(1) {
		switch d.Val() {
		case "base_score":
			args := d.RemainingArgs()
			if len(args) != 2 {
				return nil, d.ArgErr()
			}
			uc := UserClass(args[0])
			if !validUserClasses[uc] {
				return nil, d.Errf("unrecognized user class %q for base_score", args[0])
			}
			v, err := strconv.ParseFloat(args[1], 64)
			if err != nil {
				return nil, d.Errf("invalid base_score value %q: %v", args[1], err)
			}
			if o.baseScores == nil {
				o.baseScores = make(map[UserClass]float64)
			}
			o.baseScores[uc] = v

		case "penalty":
			args := d.RemainingArgs()
			if len(args) < 1 {
				return nil, d.ArgErr()
			}
			dim := args[0]
			if !validScoringDimensions[dim] {
				return nil, d.Errf("unrecognized scoring dimension %q for penalty", dim)
			}
			pc, err := parsePenaltyArgs(args[1:])
			if err != nil {
				return nil, d.Errf("invalid penalty config for dimension %q: %v", dim, err)
			}
			if o.penalties == nil {
				o.penalties = make(map[string]PenaltyConfig)
			}
			o.penalties[dim] = pc

		case "min_score":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			v, err := strconv.ParseFloat(d.Val(), 64)
			if err != nil {
				return nil, d.Errf("invalid min_score %q: %v", d.Val(), err)
			}
			o.minScore = &v

		case "max_score":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			v, err := strconv.ParseFloat(d.Val(), 64)
			if err != nil {
				return nil, d.Errf("invalid max_score %q: %v", d.Val(), err)
			}
			o.maxScore = &v

		default:
			return nil, d.Errf("unrecognized scoring subdirective '%s'", d.Val())
		}
	}

	return o, nil
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
