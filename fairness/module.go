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

	// httpcaddyfile.RegisterDirectiveOrder cannot anchor one plugin
	// directive relative to another plugin's directive — only relative to a
	// directive in Caddy's own standard distribution. So fairness and
	// adaptive_admission (adaptiveadmission/module.go) each anchor to a
	// different standard directive instead of to each other: fairness here
	// anchors "before request_header" (early-middleware section);
	// adaptive_admission anchors "before reverse_proxy" (just before
	// dispatch). Since "request_header" unconditionally precedes
	// "reverse_proxy" in Caddy's defaultDirectiveOrder, this guarantees
	// fairness always runs before adaptive_admission regardless of which
	// package's init() happens to run first (§3.1, §7 Q7).
	httpcaddyfile.RegisterDirectiveOrder("fairness", httpcaddyfile.Before, "request_header")
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

// logFieldsVarKey is the caddyhttp variable key this handler writes a
// builtin-typed map of identity/score-breakdown fields to (§4.9), so
// adaptive_admission can fold them into its single structured log line
// without importing fairness's internal Classification/UserClass types
// (§3.4's package-independence boundary — every value in this map is a
// builtin/primitive type, e.g. string(classification.UserClass) rather than
// the UserClass type itself).
const logFieldsVarKey = "fairness_log_fields"

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

	// ScoringOverrides holds only the fields a `scoring { }` sub-block
	// explicitly specified (nil if the block was absent entirely); resolved
	// onto defaults in Provision via resolveScoringConfig (scoring.go).
	// Exported and JSON-tagged (see scoringOverrides's doc comment) so it
	// survives Caddy's real Caddyfile-adapter → JSON → caddy.Load round-trip
	// — an unexported field here would parse fine via UnmarshalCaddyfile but
	// silently vanish before Provision ever ran in that real pipeline.
	ScoringOverrides *scoringOverrides `json:"scoring_overrides,omitempty"`
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
// error. It then resolves this block's `scoring { }` overrides and, for any
// dimension whose scoring depends on one of those resources (asn/country on
// GeoIP, user on JWKS), verifies the resource actually opened/initialized —
// not merely that a path/URL was given — hard-erroring at load time
// otherwise (a typo'd or broken GeoIP DB path/JWKS URL must never silently
// degrade to a permanently-0-penalty dimension, see REQUIREMENTS.md §4.3
// design refinement). It also registers this instance with the App
// (app.go) so the admin introspection API (admin.go, §4.10) can report its
// live state.
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
	resolved := resolveScoringConfig(h.ScoringOverrides)

	if _, ok := resolved.Dimensions["asn"]; ok {
		if h.geo.asn == nil || h.geo.asn.reader == nil {
			h.releaseAcquired()
			if h.GeoIPASNDB == "" {
				return fmt.Errorf("fairness: scoring dimension %q is enabled but geoip_asn_db is not configured on this block", "asn")
			}
			return fmt.Errorf("fairness: scoring dimension %q is enabled but geoip_asn_db %q failed to open — check the file exists and is a valid MaxMind ASN database", "asn", h.GeoIPASNDB)
		}
	}
	if _, ok := resolved.Dimensions["country"]; ok {
		if h.geo.city == nil || h.geo.city.reader == nil {
			h.releaseAcquired()
			if h.GeoIPCityDB == "" {
				return fmt.Errorf("fairness: scoring dimension %q is enabled but geoip_city_db is not configured on this block", "country")
			}
			return fmt.Errorf("fairness: scoring dimension %q is enabled but geoip_city_db %q failed to open — check the file exists and is a valid MaxMind City/Country database", "country", h.GeoIPCityDB)
		}
	}
	if _, ok := resolved.Dimensions["user"]; ok {
		if h.auth == nil || h.auth.kf == nil {
			h.releaseAcquired()
			if h.AuthJWKSURL == "" {
				return fmt.Errorf("fairness: scoring dimension %q is enabled but auth_jwks_url is not configured on this block", "user")
			}
			return fmt.Errorf("fairness: scoring dimension %q is enabled but auth_jwks_url %q failed to initialize — check the URL is reachable and serves a well-formed JWKS", "user", h.AuthJWKSURL)
		}
	}

	h.scoring = newScoringState(resolved, h.Config.ewmaTickInterval(), h.Config.idleEntryTTL())
	h.scoring.start()

	app.registerHandler(h.Config.backendLabel(), h)

	return nil
}

// releaseAcquired releases this handler's references to any shared GeoIP
// readers / JWKS verifier it acquired earlier in Provision, without
// unregistering it or stopping its scoring state. Shared by Cleanup (the
// normal teardown path) and by Provision's own validation-failure paths —
// Caddy does not call Cleanup on a module whose Provision returned an error,
// so those paths must release acquired pool references themselves or they'd
// leak.
func (h *Handler) releaseAcquired() {
	if h.app == nil {
		return
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
}

// Cleanup implements caddy.CleanerUpper: it releases this handler's
// references to any shared GeoIP readers / JWKS verifier it acquired in
// Provision, so the last handler referencing a given resource (e.g. after a
// config reload replaces this instance) causes the pool to actually close
// it. It also stops this instance's own EWMA-tick and idle-GC goroutines
// (scoring.go) — required so a config reload's old Handler instance doesn't
// leak background goroutines once it's replaced (§3.3) — and unregisters
// this instance from the App (app.go).
func (h *Handler) Cleanup() error {
	h.scoring.stop()

	if h.app == nil {
		return nil
	}
	h.app.unregisterHandler(h.Config.backendLabel(), h)
	h.releaseAcquired()
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
	exempt := h.Config.exemptCountrySet()
	score, breakdown := h.scoring.computeScoreBreakdown(classification, exempt)

	// Apply the presence-based priority divisor (§4.3) after the identity-
	// based base/penalty computation above — it's a distinct, stateless
	// per-request adjustment, not part of the EWMA penalty math.
	if divisor := h.scoring.priorityDivisor(r.URL.Query()); divisor != 1 {
		score /= divisor
		breakdown["final"] = score
	}
	caddyhttp.SetVar(r.Context(), fairnessScoreVarKey, score)

	backend := h.Config.backendLabel()
	fairnessMetrics.scoreDistribution.WithLabelValues(backend, string(classification.UserClass)).Observe(score)

	caddyhttp.SetVar(r.Context(), logFieldsVarKey, map[string]any{
		"ip":              classification.IP,
		"asn":             uint64(classification.ASN),
		"country":         classification.Country,
		"user_class":      string(classification.UserClass),
		"exempt":          exempt[classification.Country],
		"score_breakdown": breakdown,
	})

	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens, per the §5
// schema. The `scoring { }` sub-block (§4.3) is parsed by parseScoringBlock
// into a *scoringOverrides, later resolved onto defaults in Provision.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "backend":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.Backend = d.Val()

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
				h.ScoringOverrides = overrides

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
// resolveScoringConfig (scoring.go). A dimension is tracked/scored only if
// named by a `penalty <dimension>` line — there is no "all dimensions active
// by default" state. Grammar:
//
//	scoring {
//	    base_score <user_class> <float>                          # repeatable
//	    penalty <dimension>                                      # repeatable — enables <dimension> with its built-in default tuning
//	    penalty <dimension> alpha=<f> soft=<f>:<f> hard=<f>:<f>   # repeatable — enables <dimension> with explicit tuning
//	    divisor param <name> <value>                             # repeatable — presence-based priority divisor (§4.3), stacks multiplicatively
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
			if o.BaseScores == nil {
				o.BaseScores = make(map[UserClass]float64)
			}
			o.BaseScores[uc] = v

		case "penalty":
			args := d.RemainingArgs()
			if len(args) < 1 {
				return nil, d.ArgErr()
			}
			dim := args[0]
			if !validScoringDimensions[dim] {
				return nil, d.Errf("unrecognized scoring dimension %q for penalty", dim)
			}
			if o.EnabledDimensions == nil {
				o.EnabledDimensions = make(map[string]bool)
			}
			o.EnabledDimensions[dim] = true

			if len(args) == 1 {
				// Bare enable: use this dimension's built-in default tuning.
				// A later bare line for the same dimension always resets any
				// earlier explicit tuning given in this same block.
				delete(o.Penalties, dim)
				continue
			}

			pc, err := parsePenaltyArgs(args[1:])
			if err != nil {
				return nil, d.Errf("invalid penalty config for dimension %q: %v", dim, err)
			}
			if o.Penalties == nil {
				o.Penalties = make(map[string]PenaltyConfig)
			}
			o.Penalties[dim] = pc

		case "min_score":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			v, err := strconv.ParseFloat(d.Val(), 64)
			if err != nil {
				return nil, d.Errf("invalid min_score %q: %v", d.Val(), err)
			}
			o.MinScore = &v

		case "divisor":
			args := d.RemainingArgs()
			if len(args) != 3 || args[0] != "param" {
				return nil, d.Errf("expected 'divisor param <name> <value>'")
			}
			name := args[1]
			v, err := strconv.ParseFloat(args[2], 64)
			if err != nil {
				return nil, d.Errf("invalid divisor value %q for param %q: %v", args[2], name, err)
			}
			if v <= 0 {
				return nil, d.Errf("divisor for param %q must be > 0, got %v", name, v)
			}
			if o.Divisors == nil {
				o.Divisors = make(map[string]float64)
			}
			o.Divisors[name] = v

		case "max_score":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			v, err := strconv.ParseFloat(d.Val(), 64)
			if err != nil {
				return nil, d.Errf("invalid max_score %q: %v", d.Val(), err)
			}
			o.MaxScore = &v

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
