// Package fairness — classification (REQUIREMENTS.md §4.2). Per-request
// classification is identity/context only: IP, subnet bucket, ASN, country,
// and user class/ID. Behavior-based signals (rate, penalties) belong
// entirely to scoring (§4.3, Phase 5) and must never be folded in here.
package fairness

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// UserClass is an identity classification for a request's caller. It never
// encodes behavior (rate, abuse signals, ...) — only who/what the caller is,
// per REQUIREMENTS.md §4.2.
type UserClass string

const (
	// UserClassAnonymous is the default for requests with no bearer token.
	UserClassAnonymous UserClass = "anonymous"
	// UserClassResearcher is an authenticated, verified researcher identity.
	UserClassResearcher UserClass = "researcher"
	// UserClassServiceAccount is an authenticated, verified service account.
	UserClassServiceAccount UserClass = "service_account"
	// UserClassInternal is an authenticated, verified internal caller.
	UserClassInternal UserClass = "internal"
	// UserClassUnknown is a bearer token that was present but could not be
	// verified (bad signature, expired, JWKS unreachable, wrong
	// issuer/audience, ...) or whose user_class claim wasn't recognized.
	UserClassUnknown UserClass = "unknown"
)

// validClaimedUserClasses are the classes a verified JWT's user_class claim
// may legitimately assert. anonymous/unknown are never claimed — they're
// derived by this module, not asserted by a token.
var validClaimedUserClasses = map[UserClass]bool{
	UserClassResearcher:     true,
	UserClassServiceAccount: true,
	UserClassInternal:       true,
}

// defaultIPv6PrefixLength matches the §5 example Caddyfile's
// ipv6_prefix_length default.
const defaultIPv6PrefixLength = 56

// Classification is the per-request identity/context computed by the
// fairness handler and handed off to scoring (Phase 5) and, eventually,
// adaptive_admission (via caddyhttp.SetVar/GetVar, §3.1).
type Classification struct {
	// IP is the canonical string form of the resolved client IP.
	IP string
	// Net24 is the IPv4 /24 bucket (e.g. "203.0.113.0/24"); empty for IPv6
	// or when the IP could not be resolved.
	Net24 string
	// NetV6 is the IPv6 /48 or /56 bucket (per config), e.g.
	// "2001:db8:1::/48"; empty for IPv4 or an unresolved IP.
	NetV6 string
	// ASN is the autonomous system number, 0 if unavailable.
	ASN uint
	// Country is the ISO 3166-1 alpha-2 country code, empty if unavailable.
	Country string
	// UserClass is the identity-only classification (never a behavior
	// signal, see UserClass docs).
	UserClass UserClass
	// UserID is the verified subject (JWT `sub`), empty if
	// anonymous/unavailable.
	UserID string
}

// bucketIPv4 returns the IPv4 /24 CIDR bucket string for ip, or "" if ip is
// not a valid IPv4 address.
func bucketIPv4(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	addr, ok := netip.AddrFromSlice(ip4)
	if !ok {
		return ""
	}
	prefix := netip.PrefixFrom(addr, 24)
	return prefix.Masked().String()
}

// bucketIPv6 returns the IPv6 /prefixLen CIDR bucket string for ip, or "" if
// ip is not a valid (non-v4-mapped) IPv6 address or prefixLen is out of
// range.
func bucketIPv6(ip net.IP, prefixLen int) string {
	if ip == nil || ip.To4() != nil {
		return ""
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return ""
	}
	addr, ok := netip.AddrFromSlice(ip16)
	if !ok || !addr.Is6() {
		return ""
	}
	if prefixLen < 0 || prefixLen > 128 {
		return ""
	}
	prefix := netip.PrefixFrom(addr, prefixLen)
	return prefix.Masked().String()
}

// resolveClientIP returns the request's client IP. It consumes Caddy's own
// already-resolved {client_ip} value (set via trusted_proxies handling) when
// present, per REQUIREMENTS.md §4.1 — this module implements no XFF/trusted
// proxy logic of its own. If that placeholder isn't populated (e.g. this
// handler is invoked outside Caddy's normal server pipeline, as in unit
// tests), it falls back to parsing r.RemoteAddr the same way Caddy's own
// remote-IP matcher does (net.SplitHostPort, stripping an IPv6 zone ID).
func resolveClientIP(r *http.Request) net.IP {
	if v := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey); v != nil {
		if s, ok := v.(string); ok && s != "" {
			if ip := net.ParseIP(s); ip != nil {
				return ip
			}
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr // OK; probably didn't have a port
	}
	if idx := strings.IndexByte(host, '%'); idx != -1 {
		host = host[:idx] // strip IPv6 zone ID
	}
	return net.ParseIP(host)
}

// classify computes a request's Classification from explicit dependencies
// (no hidden globals), so it's testable without spinning up a full Caddy
// instance. geo and auth may be nil (GeoIP/auth not configured on this
// block); both fail open per REQUIREMENTS.md §4.2.
func classify(cfg *Config, geo *geoLookup, auth *verifier, ip net.IP, r *http.Request) Classification {
	var c Classification

	if ip != nil {
		c.IP = ip.String()
		if ip.To4() != nil {
			c.Net24 = bucketIPv4(ip)
		} else {
			c.NetV6 = bucketIPv6(ip, cfg.ipv6PrefixLength())
		}
	}

	c.ASN, c.Country = geo.lookup(ip)
	c.UserClass, c.UserID = authenticate(auth, r)

	return c
}
