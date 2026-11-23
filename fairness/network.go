// Package fairness — network membership for priority_network (module.go,
// classify.go). Matching always uses the client IP classify receives from
// resolveClientIP, i.e. Caddy's {client_ip} after trusted_proxies, never a
// forwarded header of its own.
package fairness

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// parseNetwork parses one CIDR prefix, or a bare IP taken as a single-host
// prefix (/32 or /128), like Caddy's own client_ip matcher. The result is
// masked, so 192.0.2.7/24 is stored as 192.0.2.0/24. An IPv4-mapped IPv6
// prefix is rejected: client IPs are matched in their unmapped form, so it
// could never match.
func parseNetwork(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		if p.Addr().Is4In6() {
			return netip.Prefix{}, fmt.Errorf("%q is an IPv4-mapped IPv6 prefix; use the IPv4 form", s)
		}
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	if addr.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("%q has an IPv6 zone, which can't be matched", s)
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// parseNetworkList parses a network-list directive's prefixes, given inline
// as arguments, in a block (any number per line, e.g. from an imported
// snippet), or both:
//
//	<directive> <cidr|ip>...
//	<directive> {
//	    <cidr|ip>...
//	}
//
// At least one is required.
func parseNetworkList(d *caddyfile.Dispenser) ([]netip.Prefix, error) {
	name := d.Val()
	vals := d.RemainingArgs()
	for d.NextBlock(1) {
		vals = append(vals, d.Val())
		vals = append(vals, d.RemainingArgs()...)
	}
	if len(vals) == 0 {
		return nil, d.Errf("%s requires at least one network", name)
	}
	prefixes := make([]netip.Prefix, 0, len(vals))
	for _, v := range vals {
		p, err := parseNetwork(v)
		if err != nil {
			return nil, d.Errf("invalid %s %q: %v", name, v, err)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

// inNetworks reports whether ip is in any of prefixes. A nil (unresolved) ip
// never matches. An IPv4-mapped IPv6 ip is matched as its IPv4 form.
func inNetworks(prefixes []netip.Prefix, ip net.IP) bool {
	if len(prefixes) == 0 {
		return false
	}
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
