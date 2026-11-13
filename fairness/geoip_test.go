package fairness

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestGeoLookup_NilFailsOpen(t *testing.T) {
	var g *geoLookup
	asn, country := g.lookup(net.ParseIP("203.0.113.5"))
	if asn != 0 || country != "" {
		t.Errorf("nil *geoLookup.lookup() = (%d, %q), want (0, \"\")", asn, country)
	}
}

func TestGeoLookup_NilIP(t *testing.T) {
	g := &geoLookup{}
	asn, country := g.lookup(nil)
	if asn != 0 || country != "" {
		t.Errorf("lookup(nil) = (%d, %q), want (0, \"\")", asn, country)
	}
}

func TestGeoLookup_NoReadersConfigured(t *testing.T) {
	g := &geoLookup{}
	asn, country := g.lookup(net.ParseIP("203.0.113.5"))
	if asn != 0 || country != "" {
		t.Errorf("lookup() with no readers = (%d, %q), want (0, \"\")", asn, country)
	}
}

func TestOpenGeoReader_MissingFile(t *testing.T) {
	construct := openGeoReader(filepath.Join(t.TempDir(), "does-not-exist.mmdb"), geoDBCity, 0, zap.NewNop())
	destructor, err := construct()
	if err != nil {
		t.Fatalf("openGeoReader constructor for missing file returned error, want fail-open nil error: %v", err)
	}
	gr, ok := destructor.(*geoReader)
	if !ok {
		t.Fatalf("constructor returned %T, want *geoReader", destructor)
	}
	if gr.reader != nil {
		t.Fatalf("expected nil reader for missing file, got a reader")
	}

	// Lookups against a fail-open reader must return no data, not panic.
	g := &geoLookup{city: gr, asn: gr}
	asn, country := g.lookup(net.ParseIP("203.0.113.5"))
	if asn != 0 || country != "" {
		t.Errorf("lookup() against missing-file reader = (%d, %q), want (0, \"\")", asn, country)
	}

	if err := gr.Destruct(); err != nil {
		t.Errorf("Destruct() on a reader-less geoReader returned error: %v", err)
	}
}

func TestOpenGeoReader_CorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.mmdb")
	if err := os.WriteFile(path, []byte("this is definitely not a valid mmdb file"), 0o600); err != nil {
		t.Fatalf("writing corrupt fixture: %v", err)
	}

	construct := openGeoReader(path, geoDBCity, 0, zap.NewNop())
	destructor, err := construct()
	if err != nil {
		t.Fatalf("openGeoReader constructor for corrupt file returned error, want fail-open nil error: %v", err)
	}
	gr, ok := destructor.(*geoReader)
	if !ok {
		t.Fatalf("constructor returned %T, want *geoReader", destructor)
	}
	if gr.reader != nil {
		t.Fatalf("expected nil reader for corrupt file, got a reader")
	}

	g := &geoLookup{city: gr, asn: gr}
	asn, country := g.lookup(net.ParseIP("203.0.113.5"))
	if asn != 0 || country != "" {
		t.Errorf("lookup() against corrupt-file reader = (%d, %q), want (0, \"\")", asn, country)
	}
}

func TestGeoReader_DestructNilSafe(t *testing.T) {
	var gr *geoReader
	if err := gr.Destruct(); err != nil {
		t.Errorf("Destruct() on nil *geoReader returned error: %v", err)
	}
}

// encodeMMDB appends v to buf in the MaxMind DB data-section encoding
// (https://maxmind.github.io/MaxMind-DB/), for the handful of types the test
// databases below need. Maps and arrays must have < 29 elements, strings
// < 285 bytes.
func encodeMMDB(buf *bytes.Buffer, v any) {
	uintBytes := func(n uint64) []byte {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], n)
		return bytes.TrimLeft(b[:], "\x00")
	}
	switch v := v.(type) {
	case string:
		if len(v) < 29 {
			buf.WriteByte(2<<5 | byte(len(v)))
		} else {
			buf.WriteByte(2<<5 | 29)
			buf.WriteByte(byte(len(v) - 29))
		}
		buf.WriteString(v)
	case uint16:
		b := uintBytes(uint64(v))
		buf.WriteByte(5<<5 | byte(len(b)))
		buf.Write(b)
	case uint32:
		b := uintBytes(uint64(v))
		buf.WriteByte(6<<5 | byte(len(b)))
		buf.Write(b)
	case uint64: // extended type 9
		b := uintBytes(v)
		buf.WriteByte(byte(len(b)))
		buf.WriteByte(9 - 7)
		buf.Write(b)
	case []string: // extended type 11 (array)
		buf.WriteByte(byte(len(v)))
		buf.WriteByte(11 - 7)
		for _, e := range v {
			encodeMMDB(buf, e)
		}
	case map[string]any:
		buf.WriteByte(7<<5 | byte(len(v)))
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			encodeMMDB(buf, k)
			encodeMMDB(buf, v[k])
		}
	default:
		panic(fmt.Sprintf("encodeMMDB: unsupported type %T", v))
	}
}

// buildTestMMDB returns an IPv4-only MaxMind DB of the given database_type
// and build_epoch in which every address maps to record: a one-node search
// tree whose both records point at the single data-section entry.
func buildTestMMDB(dbType string, buildEpoch uint64, record map[string]any) []byte {
	const nodeCount = 1
	var buf bytes.Buffer
	ptr := uint32(nodeCount + 16) // data pointer to offset 0 of the data section
	for range 2 {
		buf.Write([]byte{byte(ptr >> 16), byte(ptr >> 8), byte(ptr)}) // 24-bit records
	}
	buf.Write(make([]byte, 16)) // data section separator
	encodeMMDB(&buf, record)
	buf.WriteString("\xab\xcd\xefMaxMind.com")
	encodeMMDB(&buf, map[string]any{
		"binary_format_major_version": uint16(2),
		"binary_format_minor_version": uint16(0),
		"build_epoch":                 buildEpoch,
		"database_type":               dbType,
		"description":                 map[string]any{"en": "test"},
		"ip_version":                  uint16(4),
		"languages":                   []string{},
		"node_count":                  uint32(nodeCount),
		"record_size":                 uint16(24),
	})
	return buf.Bytes()
}

func testCityDB(country string, buildEpoch uint64) []byte {
	return buildTestMMDB("GeoLite2-City", buildEpoch, map[string]any{
		"country": map[string]any{"iso_code": country},
	})
}

func testASNDB(asn uint32, buildEpoch uint64) []byte {
	return buildTestMMDB("GeoLite2-ASN", buildEpoch, map[string]any{
		"autonomous_system_number":       asn,
		"autonomous_system_organization": "test",
	})
}

// replaceFile atomically replaces path with data, the way geoipupdate does:
// write a temporary file in the same directory, then rename it into place.
func replaceFile(t *testing.T, path string, data []byte) {
	t.Helper()
	tmp := path + ".temporary"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatalf("writing %s: %v", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("renaming %s: %v", tmp, err)
	}
}

const testReloadInterval = 5 * time.Millisecond

var testAddr = netip.MustParseAddr("193.136.7.2")

// newTestGeoReader opens path as a kind DB polled every interval, logging to
// the returned observer, and destructs it when the test ends.
func newTestGeoReader(t *testing.T, path string, kind geoDBKind, interval time.Duration) (*geoReader, *observer.ObservedLogs) {
	t.Helper()
	core, logs := observer.New(zapcore.InfoLevel)
	d, err := openGeoReader(path, kind, interval, zap.New(core))()
	if err != nil {
		t.Fatalf("openGeoReader: %v", err)
	}
	g := d.(*geoReader)
	t.Cleanup(func() { _ = g.Destruct() })
	return g, logs
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestGeoReader_LooksUpBothKinds(t *testing.T) {
	dir := t.TempDir()
	cityPath, asnPath := filepath.Join(dir, "city.mmdb"), filepath.Join(dir, "asn.mmdb")
	replaceFile(t, cityPath, testCityDB("PT", 1))
	replaceFile(t, asnPath, testASNDB(1930, 1))
	city, _ := newTestGeoReader(t, cityPath, geoDBCity, 0)
	asn, _ := newTestGeoReader(t, asnPath, geoDBASN, 0)

	g := &geoLookup{city: city, asn: asn}
	gotASN, gotCountry := g.lookup(net.ParseIP("193.136.7.2"))
	if gotASN != 1930 || gotCountry != "PT" {
		t.Errorf("lookup() = (%d, %q), want (1930, \"PT\")", gotASN, gotCountry)
	}
}

func TestOpenGeoReader_WrongKindIsUnavailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asn.mmdb")
	replaceFile(t, path, testASNDB(1930, 1))
	g, logs := newTestGeoReader(t, path, geoDBCity, 0)

	if g.available() {
		t.Error("an ASN database opened as geoip_city_db is available, want unavailable")
	}
	if logs.FilterMessageSnippet("GeoIP database unavailable").Len() != 1 {
		t.Errorf("want one startup warning, got %v", logs.All())
	}
	if h := g.health(); h.Healthy || h.LastError == "" {
		t.Errorf("health() = %+v, want unhealthy with last_error set", h)
	}
}

func TestGeoReader_ReloadsReplacedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "city.mmdb")
	replaceFile(t, path, testCityDB("PT", 100))
	g, logs := newTestGeoReader(t, path, geoDBCity, testReloadInterval)
	if got := g.country(testAddr); got != "PT" {
		t.Fatalf("country() = %q, want PT", got)
	}

	replaceFile(t, path, testCityDB("ES", 200))
	// The reload is logged just after the swap, so wait for the log.
	waitFor(t, "the reload to be logged", func() bool { return logs.FilterMessage("reloaded GeoIP database").Len() == 1 })
	if got := g.country(testAddr); got != "ES" {
		t.Errorf("country() after reload = %q, want ES", got)
	}

	entries := logs.FilterMessage("reloaded GeoIP database").All()
	fields := entries[0].ContextMap()
	if fields["old_build_epoch"] != uint64(100) || fields["new_build_epoch"] != uint64(200) || fields["database_type"] != "GeoLite2-City" {
		t.Errorf("reload log fields = %v, want old_build_epoch=100 new_build_epoch=200 database_type=GeoLite2-City", fields)
	}
	if h := g.health(); !h.Healthy || h.BuildEpoch != 200 || h.LoadedAt == nil || h.LastError != "" {
		t.Errorf("health() = %+v, want healthy, build_epoch 200, loaded_at set, no last_error", h)
	}
	if got := testutil.ToFloat64(fairnessMetrics.geoipBuildTimestamp.WithLabelValues(path)); got != 200 {
		t.Errorf("fairness_geoip_build_timestamp_seconds = %v, want 200", got)
	}
	if got := testutil.ToFloat64(fairnessMetrics.geoipReloads.WithLabelValues(path, "ok")); got != 1 {
		t.Errorf(`fairness_geoip_reloads_total{result="ok"} = %v, want 1`, got)
	}
}

func TestGeoReader_RejectsInvalidReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "city.mmdb")
	valid := testCityDB("PT", 100)
	replaceFile(t, path, valid)
	g, logs := newTestGeoReader(t, path, geoDBCity, testReloadInterval)

	for i, bad := range [][]byte{valid[:len(valid)/2], testASNDB(1930, 300)} {
		replaceFile(t, path, bad)
		waitFor(t, "the rejection to be logged", func() bool {
			return logs.FilterMessage("rejected GeoIP database reload, keeping the current one").Len() == i+1
		})
		if got := g.country(testAddr); got != "PT" {
			t.Fatalf("after invalid replacement %d, country() = %q, want the old reader's PT", i, got)
		}
		if h := g.health(); !h.Healthy || h.BuildEpoch != 100 || h.LastError == "" {
			t.Errorf("after invalid replacement %d, health() = %+v, want healthy, build_epoch 100, last_error set", i, h)
		}
	}
	if got := testutil.ToFloat64(fairnessMetrics.geoipReloads.WithLabelValues(path, "failed")); got != 2 {
		t.Errorf(`fairness_geoip_reloads_total{result="failed"} = %v, want 2`, got)
	}

	// The same broken file isn't retried on every poll.
	time.Sleep(10 * testReloadInterval)
	if n := logs.FilterMessageSnippet("rejected").Len(); n != 2 {
		t.Errorf("rejections logged = %d, want 2 (one per broken file)", n)
	}

	replaceFile(t, path, testCityDB("ES", 400))
	waitFor(t, "a later valid file to be loaded", func() bool { return g.country(testAddr) == "ES" })
}

func TestGeoReader_MissingAtStartupAppearsLater(t *testing.T) {
	path := filepath.Join(t.TempDir(), "city.mmdb")
	g, logs := newTestGeoReader(t, path, geoDBCity, testReloadInterval)
	if g.available() {
		t.Fatal("reader for a missing file is available")
	}
	if logs.FilterMessageSnippet("GeoIP database unavailable").Len() != 1 {
		t.Errorf("want one startup warning, got %v", logs.All())
	}

	replaceFile(t, path, testCityDB("PT", 100))
	waitFor(t, "the file to be loaded", func() bool { return g.country(testAddr) == "PT" })
}

func TestGeoReader_ConcurrentLookupsDuringSwaps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "city.mmdb")
	pt, es := testCityDB("PT", 1), testCityDB("ES", 2)
	replaceFile(t, path, pt)
	g, logs := newTestGeoReader(t, path, geoDBCity, time.Millisecond)

	var stop atomic.Bool
	var bad atomic.Value
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				if got := g.country(testAddr); got != "PT" && got != "ES" {
					bad.Store(got)
				}
			}
		}()
	}
	for i := range 20 {
		data := pt
		if i%2 == 0 {
			data = es
		}
		replaceFile(t, path, data)
		waitFor(t, "the swap", func() bool { return logs.FilterMessage("reloaded GeoIP database").Len() == i+1 })
	}
	stop.Store(true)
	wg.Wait()
	if v := bad.Load(); v != nil {
		t.Errorf("a lookup during a swap returned %q, want PT or ES", v)
	}
}

func TestGeoReader_DestructStopsWatchAndCloses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "city.mmdb")
	replaceFile(t, path, testCityDB("PT", 1))
	d, err := openGeoReader(path, geoDBCity, testReloadInterval, zap.NewNop())()
	if err != nil {
		t.Fatalf("openGeoReader: %v", err)
	}
	g := d.(*geoReader)

	if err := g.Destruct(); err != nil {
		t.Fatalf("Destruct: %v", err)
	}
	select {
	case <-g.done:
	default:
		t.Error("watch goroutine still running after Destruct")
	}
	if g.available() || g.country(testAddr) != "" {
		t.Error("reader still usable after Destruct, want closed and failing open")
	}
}

func TestGeoReader_ReloadDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "city.mmdb")
	replaceFile(t, path, testCityDB("PT", 1))
	g, _ := newTestGeoReader(t, path, geoDBCity, 0)
	if g.done != nil {
		t.Fatal("watch goroutine started with geoip_reload_interval 0")
	}

	replaceFile(t, path, testCityDB("ES", 2))
	time.Sleep(20 * time.Millisecond)
	if got := g.country(testAddr); got != "PT" {
		t.Errorf("country() = %q after replacement with reloading disabled, want PT", got)
	}
}
