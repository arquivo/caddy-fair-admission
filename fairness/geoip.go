// GeoIP lookups (REQUIREMENTS.md §3.1, §4.2). Both DBs (city/country and
// ASN) are independently fail-open: an empty path, a missing file, or any
// error from geoip2.Open simply makes that DB's lookups return no data —
// never an error or panic on the request path. Readers are shared across
// fairness blocks that reference the same file path via the App module's
// caddy.UsagePool (see app.go), keyed by the DB's cleaned/absolute path.
//
// Each pooled reader polls its file (geoip_reload_interval) and swaps in a
// replacement once it has been opened and validated, so a geoipupdate run is
// picked up without a Caddy reload — and a file that was missing or broken
// at startup is picked up once a valid one appears.
package fairness

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/oschwald/geoip2-golang/v2"
	"go.uber.org/zap"
)

// defaultGeoIPReloadInterval is how often a GeoIP DB file is checked for a
// replacement when a block doesn't set geoip_reload_interval.
const defaultGeoIPReloadInterval = time.Minute

// geoDBKind is the lookup a configured DB must support: Country for
// geoip_city_db, ASN for geoip_asn_db.
type geoDBKind int

const (
	geoDBCity geoDBKind = iota
	geoDBASN
)

func (k geoDBKind) String() string {
	if k == geoDBASN {
		return "ASN"
	}
	return "City/Country"
}

// geoValidationAddr is looked up once in every newly opened DB to check it
// supports the expected lookup and its search tree decodes.
var geoValidationAddr = netip.MustParseAddr("1.1.1.1")

// geoReader wraps a *geoip2.Reader so it can live in a caddy.UsagePool
// (implements caddy.Destructor), and keeps it up to date with the file at
// path. A geoReader whose reader is nil (the file has never opened and
// validated) fails open: every lookup against it behaves as "no data".
//
// geoip2 memory-maps the file and Close unmaps it, so closing a reader while
// a lookup is still using it can crash the process. Lookups therefore hold
// mu's read lock for their duration, and a swap (or Destruct) replaces the
// reader under the write lock: once the write lock is held no lookup can
// still be using the old reader, so it's closed right away.
type geoReader struct {
	path   string
	kind   geoDBKind
	logger *zap.Logger

	mu       sync.RWMutex
	reader   *geoip2.Reader
	loadedAt time.Time
	lastErr  string

	// Only touched by the constructor and then the watch goroutine. loaded
	// is the stat of the file reader was opened from, failed that of the
	// last file that didn't open/validate; a poll only acts on a file that
	// differs from both, so a broken file is retried once it changes rather
	// than on every poll.
	loaded os.FileInfo
	failed os.FileInfo

	// stop/done are nil when reloading is disabled (interval 0).
	stop chan struct{}
	done chan struct{}
}

// openGeoReader returns a caddy.Constructor that opens path as an mmdb
// database of the given kind and, if interval > 0, starts polling it for
// replacements. It never returns a non-nil error: if opening fails for any
// reason (missing file, corrupt data, wrong kind of database, ...) it logs a
// warning and yields a *geoReader with a nil reader, which fails open until
// a later poll finds a valid file.
func openGeoReader(path string, kind geoDBKind, interval time.Duration, logger *zap.Logger) caddy.Constructor {
	return func() (caddy.Destructor, error) {
		g := &geoReader{path: path, kind: kind, logger: logger}
		fi, err := os.Stat(path)
		if err == nil {
			err = g.tryLoad(fi)
		} else {
			g.setError(err)
		}
		if err != nil {
			logger.Warn("GeoIP database unavailable, lookups return no data until it can be loaded",
				zap.String("path", path), zap.Error(err))
		}
		if interval > 0 {
			g.stop = make(chan struct{})
			g.done = make(chan struct{})
			go g.watch(interval)
		}
		return g, nil
	}
}

// Destruct implements caddy.Destructor: it stops the watch goroutine, then
// closes the reader once no lookup is using it.
func (g *geoReader) Destruct() error {
	if g == nil {
		return nil
	}
	if g.stop != nil {
		close(g.stop)
		<-g.done
	}
	g.mu.Lock()
	reader := g.reader
	g.reader = nil
	g.mu.Unlock()
	if reader == nil {
		return nil
	}
	return reader.Close()
}

func (g *geoReader) watch(interval time.Duration) {
	defer close(g.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-g.stop:
			return
		case <-ticker.C:
			g.poll()
		}
	}
}

// poll reloads the file if it's been replaced or modified since it was
// last loaded (or last failed to load). A file that's vanished keeps the
// current reader.
func (g *geoReader) poll() {
	fi, err := os.Stat(g.path)
	if err != nil || sameFileStat(fi, g.loaded) || sameFileStat(fi, g.failed) {
		return
	}
	oldEpoch := g.buildEpoch()
	if err := g.tryLoad(fi); err != nil {
		fairnessMetrics.geoipReloads.WithLabelValues(g.path, "failed").Inc()
		g.logger.Warn("rejected GeoIP database reload, keeping the current one",
			zap.String("path", g.path), zap.Error(err))
		return
	}
	fairnessMetrics.geoipReloads.WithLabelValues(g.path, "ok").Inc()
	g.logger.Info("reloaded GeoIP database",
		zap.String("path", g.path),
		zap.String("database_type", g.databaseType()),
		zap.Uint("old_build_epoch", oldEpoch),
		zap.Uint("new_build_epoch", g.buildEpoch()))
}

// tryLoad opens and validates the file at path — fi being its stat, taken
// before opening so a replacement landing mid-open shows up as a change on
// the next poll rather than being missed — and swaps it in. On failure the
// current reader is kept.
func (g *geoReader) tryLoad(fi os.FileInfo) error {
	reader, err := openValidGeoDB(g.path, g.kind)
	if err != nil {
		g.failed = fi
		g.setError(err)
		return err
	}
	g.loaded, g.failed = fi, nil

	g.mu.Lock()
	old := g.reader
	g.reader, g.loadedAt, g.lastErr = reader, time.Now(), ""
	g.mu.Unlock()

	fairnessMetrics.geoipBuildTimestamp.WithLabelValues(g.path).Set(float64(reader.Metadata().BuildEpoch))
	if old != nil {
		_ = old.Close()
	}
	return nil
}

// openValidGeoDB opens path and checks it supports kind's lookup (which also
// checks its database_type) and that a test lookup succeeds.
func openValidGeoDB(path string, kind geoDBKind) (*geoip2.Reader, error) {
	reader, err := geoip2.Open(path)
	if err != nil {
		// geoip2.Open returns the open reader alongside an unknown
		// database_type error.
		if reader != nil {
			_ = reader.Close()
		}
		return nil, err
	}
	if kind == geoDBASN {
		_, err = reader.ASN(geoValidationAddr)
	} else {
		_, err = reader.Country(geoValidationAddr)
	}
	if err != nil {
		dbType := reader.Metadata().DatabaseType
		_ = reader.Close()
		return nil, fmt.Errorf("not a usable %s database (database_type %q): %w", kind, dbType, err)
	}
	return reader, nil
}

// sameFileStat reports whether a and b describe the same, unmodified file:
// same inode (a geoipupdate run renames a new file into place), modification
// time and size. A nil b never matches.
func sameFileStat(a, b os.FileInfo) bool {
	return b != nil && os.SameFile(a, b) && a.ModTime().Equal(b.ModTime()) && a.Size() == b.Size()
}

func (g *geoReader) setError(err error) {
	g.mu.Lock()
	g.lastErr = err.Error()
	g.mu.Unlock()
}

// available reports whether a valid DB is currently loaded. Safe on a nil
// *geoReader.
func (g *geoReader) available() bool {
	if g == nil {
		return false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.reader != nil
}

func (g *geoReader) buildEpoch() uint {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.reader == nil {
		return 0
	}
	return g.reader.Metadata().BuildEpoch
}

func (g *geoReader) databaseType() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.reader == nil {
		return ""
	}
	return g.reader.Metadata().DatabaseType
}

// health reports this reader for the admin API (app.go's geoHealth).
func (g *geoReader) health() resourceHealth {
	g.mu.RLock()
	defer g.mu.RUnlock()
	h := resourceHealth{Healthy: g.reader != nil, LastError: g.lastErr}
	if g.reader != nil {
		loadedAt := g.loadedAt
		h.BuildEpoch = g.reader.Metadata().BuildEpoch
		h.LoadedAt = &loadedAt
	}
	return h
}

// country returns addr's ISO country code, or "" if there's no data.
func (g *geoReader) country(addr netip.Addr) string {
	if g == nil {
		return ""
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.reader == nil {
		return ""
	}
	rec, err := g.reader.Country(addr)
	if err != nil || rec == nil || !rec.HasData() {
		return ""
	}
	return rec.Country.ISOCode
}

// asn returns addr's autonomous system number, or 0 if there's no data.
func (g *geoReader) asn(addr netip.Addr) uint {
	if g == nil {
		return 0
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.reader == nil {
		return 0
	}
	rec, err := g.reader.ASN(addr)
	if err != nil || rec == nil || !rec.HasData() {
		return 0
	}
	return rec.AutonomousSystemNumber
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
	return g.asn.asn(addr), g.city.country(addr)
}
