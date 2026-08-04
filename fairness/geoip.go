// GeoIP lookups (REQUIREMENTS.md §3.1, §4.2). Both DBs (city/country and
// ASN) are independently fail-open: an empty path, a missing file, or any
// error from geoip2.Open simply makes that DB's lookups return no data —
// never an error or panic on the request path. Readers are shared across
// fairness blocks that reference the same file path via the App module's
// caddy.UsagePool (see app.go), keyed by the DB's cleaned/absolute path.
package fairness

import (
	"net"
	"net/netip"

	"github.com/caddyserver/caddy/v2"
	"github.com/oschwald/geoip2-golang/v2"
)

// geoReader wraps a *geoip2.Reader so it can live in a caddy.UsagePool
// (implements caddy.Destructor). A geoReader whose reader field is nil
// (constructed when geoip2.Open failed) fails open: every lookup against it
// behaves as "no data".
type geoReader struct {
	reader *geoip2.Reader
}

// Destruct implements caddy.Destructor.
func (g *geoReader) Destruct() error {
	if g == nil || g.reader == nil {
		return nil
	}
	return g.reader.Close()
}

// openGeoReader returns a caddy.Constructor that opens path as an mmdb
// database. It never returns a non-nil error: if opening fails for any
// reason (missing file, corrupt data, ...), it yields a *geoReader with a
// nil reader, which fails open on every subsequent lookup rather than
// propagating the failure into request handling or retrying on every
// request.
func openGeoReader(path string) caddy.Constructor {
	return func() (caddy.Destructor, error) {
		reader, err := geoip2.Open(path)
		if err != nil {
			return &geoReader{}, nil
		}
		return &geoReader{reader: reader}, nil
	}
}

// geoLookup resolves ASN + country for an IP using up to two independently
// fail-open MaxMind readers. A nil *geoLookup, or one with both readers
// nil/unavailable, simply returns zero values.
type geoLookup struct {
	city *geoReader
	asn  *geoReader
}

// lookup returns the ASN and ISO country code for ip, or zero values for
// either that isn't available (no DB configured, DB failed to open, or the
// IP has no data in that DB). It never errors or panics.
func (g *geoLookup) lookup(ip net.IP) (asn uint, country string) {
	if g == nil || ip == nil {
		return 0, ""
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return 0, ""
	}
	addr, ok := netip.AddrFromSlice(ip16)
	if !ok {
		return 0, ""
	}
	if addr.Is4In6() {
		// Unmap IPv4-in-IPv6 so lookups behave the same as a native IPv4
		// address (geoip2's databases key IPv4 networks natively).
		addr = addr.Unmap()
	}

	if g.city != nil && g.city.reader != nil {
		if rec, err := g.city.reader.Country(addr); err == nil && rec != nil && rec.HasData() {
			country = rec.Country.ISOCode
		}
	}
	if g.asn != nil && g.asn.reader != nil {
		if rec, err := g.asn.reader.ASN(addr); err == nil && rec != nil && rec.HasData() {
			asn = rec.AutonomousSystemNumber
		}
	}
	return asn, country
}
