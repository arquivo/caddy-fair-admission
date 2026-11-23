// Package fairness — network membership for priority_network (module.go,
// classify.go). Matching always uses the client IP classify receives from
// resolveClientIP, i.e. Caddy's {client_ip} after trusted_proxies, never a
// forwarded header of its own.
package fairness

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// parseNetwork parses one CIDR prefix, or a bare IP taken as a single-host
// prefix (/32 or /128), with Caddy's own client_ip matcher parser, then
// applies validateNetwork.
func parseNetwork(s string) (netip.Prefix, error) {
	p, err := caddyhttp.CIDRExpressionToPrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return p, validateNetwork(p)
}

// validateNetwork rejects priority_network prefixes that are invalid or
// can't mean what was written: an IPv4-mapped IPv6 prefix (client IPs are
// matched unmapped, so it could never match), host bits set (a typo such as
// 192.168.1.0/8 would silently widen the list), and a /0 (every client).
// Checked for Caddyfile and JSON config alike.
func validateNetwork(p netip.Prefix) error {
	switch {
	case !p.IsValid():
		return errors.New("empty or invalid prefix")
	case p.Addr().Is4In6():
		return fmt.Errorf("%s is an IPv4-mapped IPv6 prefix; use the IPv4 form", p)
	case p != p.Masked():
		return fmt.Errorf("%s has host bits set; did you mean %s?", p, p.Masked())
	case p.Bits() == 0:
		return fmt.Errorf("%s matches every client", p)
	}
	return nil
}

// parsePriorityNetworks parses a priority_network directive's prefixes,
// given inline as arguments, in a block (any number per line, e.g. from an
// imported snippet), or both:
//
//	priority_network <cidr|ip>...
//	priority_network {
//	    <cidr|ip>...
//	}
//
// At least one is required.
func parsePriorityNetworks(d *caddyfile.Dispenser) ([]netip.Prefix, error) {
	vals := d.RemainingArgs()
	for d.NextBlock(1) {
		vals = append(vals, d.Val())
		vals = append(vals, d.RemainingArgs()...)
	}
	if len(vals) == 0 {
		return nil, d.Err("priority_network requires at least one network")
	}
	prefixes := make([]netip.Prefix, 0, len(vals))
	for _, v := range vals {
		p, err := parseNetwork(v)
		if err != nil {
			return nil, d.Errf("invalid priority_network: %v", err)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

// inNetworks reports whether ip is in any of prefixes. A nil (unresolved) ip
// never matches. An IPv4-mapped IPv6 ip is matched as its IPv4 form.
func inNetworks(prefixes []netip.Prefix, ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
