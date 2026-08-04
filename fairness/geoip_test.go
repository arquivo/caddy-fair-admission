package fairness

import (
	"net"
	"os"
	"path/filepath"
	"testing"
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
	construct := openGeoReader(filepath.Join(t.TempDir(), "does-not-exist.mmdb"))
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

	construct := openGeoReader(path)
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
