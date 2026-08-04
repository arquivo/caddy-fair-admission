package fairness

import "time"

// defaultJWKSRefreshInterval is used when a block configures auth_jwks_url
// but the refresh interval isn't independently configurable yet (this
// phase doesn't expose one — see auth.go).
const defaultJWKSRefreshInterval = 5 * time.Minute

// Config is the fairness handler's configuration surface for ingress
// consumption + classification (REQUIREMENTS.md §4.1-§4.2, §5). It is
// embedded directly in Handler so both Caddyfile (via UnmarshalCaddyfile)
// and JSON (via encoding/json's normal field promotion) config flow through
// the same struct.
//
// EWMATickInterval and IdleEntryTTL belong to Phase 5's `scoring { }`
// sub-block (§4.3) and are not consumed by anything in this phase — they're
// parsed here now so that shared_fairness_defaults-style Caddyfile snippets
// (§5) which already carry them don't fail to parse against a Phase-4-only
// build.
type Config struct {
	// GeoIPCityDB is the path to a MaxMind city/country .mmdb database.
	// Empty, missing, or unopenable: country lookups silently return "" (no
	// error, no panic) — fail-open per §4.2.
	GeoIPCityDB string `json:"geoip_city_db,omitempty"`
	// GeoIPASNDB is the path to a MaxMind ASN .mmdb database. Same
	// independent fail-open behavior as GeoIPCityDB.
	GeoIPASNDB string `json:"geoip_asn_db,omitempty"`

	// AuthIssuer is the expected JWT `iss` claim. Empty means the issuer
	// isn't checked.
	AuthIssuer string `json:"auth_issuer,omitempty"`
	// AuthJWKSURL is the JWKS endpoint used to verify bearer tokens. Empty
	// means auth isn't configured on this block at all — bearer tokens are
	// then simply ignored and requests classify as anonymous (§4.2).
	AuthJWKSURL string `json:"auth_jwks_url,omitempty"`
	// AuthAudience is the expected JWT `aud` claim. Empty means the
	// audience isn't checked.
	AuthAudience string `json:"auth_audience,omitempty"`

	// ExemptCountries lists ISO 3166-1 alpha-2 country codes that are
	// exempt from scoring penalties (§4.3) — still tracked/counted
	// (observability) but never penalized. Repeatable in the Caddyfile.
	ExemptCountries []string `json:"exempt_countries,omitempty"`

	// IPv6PrefixLength is the IPv6 subnet-bucketing prefix length, 48 or
	// 56. Zero means "use the default" (56, matching the §5 example).
	IPv6PrefixLength int `json:"ipv6_prefix_length,omitempty"`

	// EWMATickInterval and IdleEntryTTL are Phase 5 (§4.3/§3.2) config —
	// parsed now, unused until scoring lands.
	EWMATickInterval time.Duration `json:"ewma_tick_interval,omitempty"`
	IdleEntryTTL     time.Duration `json:"idle_entry_ttl,omitempty"`
}

// ipv6PrefixLength returns the configured IPv6 bucketing prefix length, or
// the default (56) if unset. Safe to call on a nil *Config.
func (c *Config) ipv6PrefixLength() int {
	if c == nil || c.IPv6PrefixLength == 0 {
		return defaultIPv6PrefixLength
	}
	return c.IPv6PrefixLength
}

// exemptCountrySet returns ExemptCountries as a lookup set. Safe to call on
// a nil *Config. Retained here (rather than only in scoring, Phase 5) since
// it's derived purely from this phase's config surface.
func (c *Config) exemptCountrySet() map[string]bool {
	if c == nil || len(c.ExemptCountries) == 0 {
		return nil
	}
	set := make(map[string]bool, len(c.ExemptCountries))
	for _, cc := range c.ExemptCountries {
		set[cc] = true
	}
	return set
}
