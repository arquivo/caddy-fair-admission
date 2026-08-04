package fairness

import (
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// fakeDestructor is a minimal caddy.Destructor for exercising the
// caddy.UsagePool dedup mechanism directly, without needing a real GeoIP DB
// file on disk (REQUIREMENTS.md Phase 4 test plan: "assert via a counting
// fake or reference count").
type fakeDestructor struct{ destructCount *int32 }

func (f *fakeDestructor) Destruct() error {
	atomic.AddInt32(f.destructCount, 1)
	return nil
}

func TestUsagePool_DedupsByKey(t *testing.T) {
	pool := caddy.NewUsagePool()
	var constructCount int32
	var destructCount int32

	construct := func() (caddy.Destructor, error) {
		atomic.AddInt32(&constructCount, 1)
		return &fakeDestructor{destructCount: &destructCount}, nil
	}

	v1, loaded1, err := pool.LoadOrNew("shared-key", construct)
	if err != nil {
		t.Fatalf("first LoadOrNew: %v", err)
	}
	if loaded1 {
		t.Error("first LoadOrNew reported loaded=true, want false (should have constructed)")
	}

	v2, loaded2, err := pool.LoadOrNew("shared-key", construct)
	if err != nil {
		t.Fatalf("second LoadOrNew: %v", err)
	}
	if !loaded2 {
		t.Error("second LoadOrNew reported loaded=false, want true (should have reused)")
	}

	if v1 != v2 {
		t.Error("expected both LoadOrNew calls to return the same pooled value")
	}
	if got := atomic.LoadInt32(&constructCount); got != 1 {
		t.Errorf("constructor ran %d times, want exactly 1", got)
	}

	refs, ok := pool.References("shared-key")
	if !ok {
		t.Fatal("References() reported key not found")
	}
	if refs != 2 {
		t.Errorf("References() = %d, want 2", refs)
	}

	// Release both references; the destructor should run exactly once,
	// only once the last reference is dropped.
	if _, err := pool.Delete("shared-key"); err != nil {
		t.Fatalf("first Delete: %v", err)
	}
	if got := atomic.LoadInt32(&destructCount); got != 0 {
		t.Errorf("destructor ran after only one Delete (%d runs), want 0", got)
	}
	if _, err := pool.Delete("shared-key"); err != nil {
		t.Fatalf("second Delete: %v", err)
	}
	if got := atomic.LoadInt32(&destructCount); got != 1 {
		t.Errorf("destructor ran %d times after final Delete, want exactly 1", got)
	}
}

func TestApp_AcquireGeoReader_DedupsByPath(t *testing.T) {
	app := &App{}
	if err := app.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	path := filepath.Join(t.TempDir(), "does-not-exist.mmdb")

	r1, err := app.acquireGeoReader(path)
	if err != nil {
		t.Fatalf("first acquireGeoReader: %v", err)
	}
	r2, err := app.acquireGeoReader(path)
	if err != nil {
		t.Fatalf("second acquireGeoReader: %v", err)
	}
	if r1 != r2 {
		t.Error("expected both acquireGeoReader calls to return the same shared *geoReader")
	}

	refs, ok := app.geoPool.References(geoPoolKey(path))
	if !ok || refs != 2 {
		t.Errorf("References() = (%d, %v), want (2, true)", refs, ok)
	}

	app.releaseGeoReader(path)
	app.releaseGeoReader(path)

	if _, ok := app.geoPool.References(geoPoolKey(path)); ok {
		t.Error("expected pool entry to be gone after releasing both references")
	}
}

func TestApp_AcquireGeoReader_EmptyPathNoOp(t *testing.T) {
	app := &App{}
	if err := app.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	r, err := app.acquireGeoReader("")
	if err != nil || r != nil {
		t.Errorf("acquireGeoReader(\"\") = (%v, %v), want (nil, nil)", r, err)
	}
}

func TestApp_AcquireVerifier_EmptyURLNoOp(t *testing.T) {
	app := &App{}
	if err := app.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	v, err := app.acquireVerifier("", "", "", 0)
	if err != nil || v != nil {
		t.Errorf("acquireVerifier(\"\") = (%v, %v), want (nil, nil)", v, err)
	}
}
