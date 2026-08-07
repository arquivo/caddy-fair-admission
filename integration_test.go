// Package caddyaac's integration tests exercise the real Caddyfile adapter
// plus a real, running caddy.Load'd instance (no xcaddy binary, no
// caddytest -- see REQUIREMENTS.md §3.4/§4.6/§4.7 and Phase 8 of
// implementation_plan.md). Each test blank-imports fairness and
// adaptiveadmission transitively via this package's own module.go.
package caddyaac

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/golang-jwt/jwt/v5"
)

// adaptCaddyfile runs the real "caddyfile" adapter (registered via
// httpcaddyfile's own init(), transitively imported by both fairness and
// adaptiveadmission) and fails the test on any adapt error.
func adaptCaddyfile(t *testing.T, input string) map[string]any {
	t.Helper()
	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		t.Fatal(`caddyconfig adapter "caddyfile" is not registered`)
	}
	result, warnings, err := adapter.Adapt([]byte(input), nil)
	if err != nil {
		t.Fatalf("Adapt: %v (warnings: %v)", err, warnings)
	}
	var cfg map[string]any
	if err := json.Unmarshal(result, &cfg); err != nil {
		t.Fatalf("unmarshal adapted config: %v", err)
	}
	return cfg
}

// loadCaddy adapts input, disables the admin API, loads it as the running
// Caddy config, and registers a cleanup to stop it.
func loadCaddy(t *testing.T, input string) {
	t.Helper()
	cfg := adaptCaddyfile(t, input)
	cfg["admin"] = map[string]any{"disabled": true}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := caddy.Load(cfgJSON, false); err != nil {
		t.Fatalf("caddy.Load: %v", err)
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Errorf("caddy.Stop: %v", err)
		}
	})
	// Give the listener a moment to come up before the test fires requests.
	time.Sleep(150 * time.Millisecond)
}

// expectCaddyLoadError adapts input (which must itself adapt successfully --
// these tests target Provision-time validation errors, not adapter/parse
// errors) and attempts to load it as the running Caddy config. It fails the
// test if caddy.Load unexpectedly succeeds, and otherwise returns the error
// it produced.
func expectCaddyLoadError(t *testing.T, input string) error {
	t.Helper()
	cfg := adaptCaddyfile(t, input)
	cfg["admin"] = map[string]any{"disabled": true}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	loadErr := caddy.Load(cfgJSON, false)
	if loadErr == nil {
		t.Cleanup(func() {
			if err := caddy.Stop(); err != nil {
				t.Errorf("caddy.Stop: %v", err)
			}
		})
		t.Fatal("caddy.Load unexpectedly succeeded, want a Provision-time validation error")
	}
	return loadErr
}

// handleChain walks apps.http.servers.srv0.routes[0].handle[], descending
// into a "subroute" wrapper (produced by bare top-level directives) if
// present, and returns the ordered list of "handler" field values.
func handleChain(t *testing.T, cfg map[string]any) []string {
	t.Helper()
	apps, _ := cfg["apps"].(map[string]any)
	httpApp, _ := apps["http"].(map[string]any)
	servers, _ := httpApp["servers"].(map[string]any)
	srv0, _ := servers["srv0"].(map[string]any)
	routes, _ := srv0["routes"].([]any)
	if len(routes) == 0 {
		t.Fatal("no routes in adapted config")
	}
	route0, _ := routes[0].(map[string]any)
	handle, _ := route0["handle"].([]any)
	if len(handle) == 1 {
		if sub, ok := handle[0].(map[string]any); ok {
			if h, _ := sub["handler"].(string); h == "subroute" {
				subroutes, _ := sub["routes"].([]any)
				if len(subroutes) > 0 {
					if sr0, ok := subroutes[0].(map[string]any); ok {
						handle, _ = sr0["handle"].([]any)
					}
				}
			}
		}
	}
	names := make([]string, 0, len(handle))
	for _, h := range handle {
		hm, ok := h.(map[string]any)
		if !ok {
			continue
		}
		name, _ := hm["handler"].(string)
		names = append(names, name)
	}
	return names
}

func TestIntegration_DirectiveOrder_FairnessBeforeAdaptiveAdmissionBeforeReverseProxy(t *testing.T) {
	input := `
:19080 {
	fairness
	adaptive_admission {
		controller fixed {
			limit 10
		}
	}
	reverse_proxy 127.0.0.1:1
}
`
	cfg := adaptCaddyfile(t, input)
	got := handleChain(t, cfg)
	want := []string{"fairness", "adaptive_admission", "reverse_proxy"}
	if len(got) != len(want) {
		t.Fatalf("handler chain = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("handler chain = %v, want %v", got, want)
			break
		}
	}
}

// issueRS256JWT builds a JWKS document and a matching signed JWT for it,
// returning the JWKS server, the signed token, and its user_class claim.
type testClaims struct {
	jwt.RegisteredClaims
	UserClass string `json:"user_class,omitempty"`
}

func startJWKSServerAndSignToken(t *testing.T, userClass string) (jwksURL, signedToken string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwk, err := jwkset.NewJWKFromKey(key.Public(), jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{KID: "test-key", ALG: jwkset.AlgRS256},
	})
	if err != nil {
		t.Fatalf("NewJWKFromKey: %v", err)
	}
	jwksBytes, err := json.Marshal(jwkset.JWKSMarshal{Keys: []jwkset.JWKMarshal{jwk.Marshal()}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(jwksBytes)
	}))
	t.Cleanup(jwksSrv.Close)

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, testClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "test-subject"},
		UserClass:        userClass,
	})
	tok.Header["kid"] = "test-key"
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return jwksSrv.URL, signed
}

func TestIntegration_EndToEnd_PrioritizesHigherScoreRequestUnderSaturation(t *testing.T) {
	jwksURL, researcherToken := startJWKSServerAndSignToken(t, "researcher")

	// hold blocks the sole capacity slot open until release is closed; the
	// other paths respond immediately, echoing X-Name back so the test can
	// observe completion order.
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			<-release
		}
		w.Header().Set("X-Name", r.Header.Get("X-Name"))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	input := fmt.Sprintf(`
:19081 {
	fairness {
		auth_jwks_url %s
		scoring {
			base_score researcher 100
			base_score anonymous  60
		}
	}
	adaptive_admission {
		controller fixed {
			limit 1
		}
		queue_max_size 10
		queue_timeout 5s
	}
	reverse_proxy %s
}
`, jwksURL, upstream.Listener.Addr().String())
	loadCaddy(t, input)

	client := &http.Client{Timeout: 5 * time.Second}
	var mu sync.Mutex
	var order []string
	record := func(name string) {
		mu.Lock()
		order = append(order, name)
		mu.Unlock()
	}

	// 1. Occupy the sole capacity slot with a blocking request.
	holdDone := make(chan struct{})
	go func() {
		defer close(holdDone)
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:19081/hold", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("hold request: %v", err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("hold request status = %d, want 200", resp.StatusCode)
		}
	}()
	time.Sleep(150 * time.Millisecond) // ensure the hold request has acquired the slot

	// 2. Enqueue the low-score (anonymous) request first.
	lowDone := make(chan struct{})
	go func() {
		defer close(lowDone)
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:19081/", nil)
		req.Header.Set("X-Name", "low")
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("low request: %v", err)
			return
		}
		defer resp.Body.Close()
		record(resp.Header.Get("X-Name"))
	}()
	time.Sleep(100 * time.Millisecond) // ensure arrival order: low enqueues before high

	// 3. Enqueue the high-score (researcher, JWT-authenticated) request.
	highDone := make(chan struct{})
	go func() {
		defer close(highDone)
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:19081/", nil)
		req.Header.Set("X-Name", "high")
		req.Header.Set("Authorization", "Bearer "+researcherToken)
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("high request: %v", err)
			return
		}
		defer resp.Body.Close()
		record(resp.Header.Get("X-Name"))
	}()
	time.Sleep(100 * time.Millisecond)

	// 4. Free the slot: the queued requests should now dispatch, higher
	// score first, even though it arrived later.
	close(release)

	for _, done := range []chan struct{}{holdDone, lowDone, highDone} {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("a request never completed")
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 || order[0] != "high" || order[1] != "low" {
		t.Errorf("completion order = %v, want [high low]", order)
	}
}

func TestIntegration_EndToEnd_FailoverRoutesAroundUnhealthyUpstream(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "healthy")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(healthy.Close)

	// down: bind then immediately close, guaranteeing connection-refused
	// (simulates a genuinely unreachable instance) rather than depending on
	// timing against a real server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	downAddr := ln.Addr().String()
	ln.Close()

	input := fmt.Sprintf(`
:19082 {
	fairness
	adaptive_admission {
		controller fixed {
			limit 10
		}
	}
	reverse_proxy %s %s {
		lb_try_duration 2s
		fail_duration   30s
		max_fails       1
	}
}
`, downAddr, healthy.Listener.Addr().String())
	loadCaddy(t, input)

	client := &http.Client{Timeout: 5 * time.Second}
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:19082/", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		got := resp.Header.Get("X-Upstream")
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("request %d: status = %d, want 200", i, resp.StatusCode)
		}
		if got != "healthy" {
			t.Errorf("request %d: X-Upstream = %q, want %q (should fail over from the down upstream)", i, got, "healthy")
		}
	}
}

// TestIntegration_EndToEnd_AdminStatusEndpoints exercises Phase 10's admin
// introspection API against a genuinely running instance with the admin
// listener enabled (unlike loadCaddy, which disables it) — per
// implementation_plan.md's Phase 10 "done when": hitting both endpoints
// returns the documented per-backend shape, matching live state after
// synthetic traffic.
func TestIntegration_EndToEnd_AdminStatusEndpoints(t *testing.T) {
	jwksURL, researcherToken := startJWKSServerAndSignToken(t, "researcher")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	// Reserve a free port for the admin listener rather than using the real
	// default (localhost:2019), so this test can't collide with a developer's
	// own running Caddy instance.
	adminLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	adminAddr := adminLn.Addr().String()
	adminLn.Close()

	input := fmt.Sprintf(`
:19084 {
	fairness {
		auth_jwks_url %s
		scoring {
			penalty ip
		}
	}
	adaptive_admission {
		controller fixed {
			limit 5
		}
		queue_max_size 10
		queue_timeout 5s
	}
	reverse_proxy %s
}
`, jwksURL, upstream.Listener.Addr().String())

	cfg := adaptCaddyfile(t, input)
	cfg["admin"] = map[string]any{"listen": adminAddr}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := caddy.Load(cfgJSON, false); err != nil {
		t.Fatalf("caddy.Load: %v", err)
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Errorf("caddy.Stop: %v", err)
		}
	})
	time.Sleep(150 * time.Millisecond)

	client := &http.Client{Timeout: 5 * time.Second}

	// Send an authenticated (JWT) request through the full chain so the
	// admin endpoints have live state to report: a JWKS pool reference and a
	// tracked "researcher"-classified entry in fairness's EWMA state.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:19084/", nil)
	req.Header.Set("Authorization", "Bearer "+researcherToken)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("synthetic request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("synthetic request status = %d, want 200", resp.StatusCode)
	}

	aaResp, err := client.Get("http://" + adminAddr + "/adaptive_admission/status")
	if err != nil {
		t.Fatalf("GET /adaptive_admission/status: %v", err)
	}
	defer aaResp.Body.Close()
	if aaResp.StatusCode != http.StatusOK {
		t.Fatalf("/adaptive_admission/status status = %d, want 200", aaResp.StatusCode)
	}
	var aaBody struct {
		Backends []struct {
			Backend        string  `json:"backend"`
			ControllerKind string  `json:"controller_kind"`
			Limit          int     `json:"limit"`
			InFlight       int     `json:"in_flight"`
			MeanLatencyMs  float64 `json:"mean_latency_ms"`
			QueueSize      int     `json:"queue_size"`
		} `json:"backends"`
	}
	if err := json.NewDecoder(aaResp.Body).Decode(&aaBody); err != nil {
		t.Fatalf("decode /adaptive_admission/status: %v", err)
	}
	if len(aaBody.Backends) != 1 {
		t.Fatalf("adaptive_admission backends = %+v, want 1 entry", aaBody.Backends)
	}
	if got := aaBody.Backends[0]; got.Backend != "default" || got.ControllerKind != "fixed" || got.Limit != 5 {
		t.Errorf("adaptive_admission backend status = %+v, want backend=default controller_kind=fixed limit=5", got)
	}

	fResp, err := client.Get("http://" + adminAddr + "/fairness/status")
	if err != nil {
		t.Fatalf("GET /fairness/status: %v", err)
	}
	defer fResp.Body.Close()
	if fResp.StatusCode != http.StatusOK {
		t.Fatalf("/fairness/status status = %d, want 200", fResp.StatusCode)
	}
	var fBody struct {
		Backends []struct {
			Backend              string             `json:"backend"`
			BaseScores           map[string]float64 `json:"base_scores"`
			DimensionEntryCounts map[string]int     `json:"dimension_entry_counts"`
		} `json:"backends"`
		Shared struct {
			GeoIP []map[string]any `json:"geoip"`
			JWKS  []struct {
				Key        string `json:"key"`
				Healthy    bool   `json:"healthy"`
				References int    `json:"references"`
			} `json:"jwks"`
		} `json:"shared"`
	}
	if err := json.NewDecoder(fResp.Body).Decode(&fBody); err != nil {
		t.Fatalf("decode /fairness/status: %v", err)
	}
	if len(fBody.Backends) != 1 || fBody.Backends[0].Backend != "default" {
		t.Fatalf("fairness backends = %+v, want 1 entry with backend=default", fBody.Backends)
	}
	if got := fBody.Backends[0].DimensionEntryCounts["ip"]; got < 1 {
		t.Errorf(`fairness backend dimension_entry_counts["ip"] = %d, want >= 1 (the synthetic request's client IP)`, got)
	}
	if len(fBody.Shared.JWKS) != 1 || !fBody.Shared.JWKS[0].Healthy || fBody.Shared.JWKS[0].References < 1 {
		t.Errorf("fairness shared JWKS health = %+v, want 1 healthy entry with >= 1 reference", fBody.Shared.JWKS)
	}
}

// The tests below cover the Provision-time config errors added for opt-in
// scoring dimensions (REQUIREMENTS.md §4.3 design refinement,
// docs/configuration.md §1.1): enabling asn/country/user via `penalty <dim>`
// without its prerequisite (geoip_asn_db/geoip_city_db/auth_jwks_url)
// actually configured *and working* must hard-fail config load, with
// distinct wording for "not configured at all" vs. "configured but failed
// to open/initialize".

func TestIntegration_ConfigError_AsnEnabled_NotConfigured(t *testing.T) {
	input := `
:19085 {
	fairness {
		scoring {
			penalty asn
		}
	}
}
`
	err := expectCaddyLoadError(t, input)
	if !strings.Contains(err.Error(), `geoip_asn_db is not configured`) {
		t.Errorf("error = %v, want it to mention geoip_asn_db is not configured", err)
	}
}

func TestIntegration_ConfigError_AsnEnabled_FailedToOpen(t *testing.T) {
	badPath := filepath.Join(t.TempDir(), "does-not-exist.mmdb")
	input := fmt.Sprintf(`
:19086 {
	fairness {
		geoip_asn_db %s
		scoring {
			penalty asn
		}
	}
}
`, badPath)
	err := expectCaddyLoadError(t, input)
	if !strings.Contains(err.Error(), "failed to open") {
		t.Errorf("error = %v, want it to mention the DB failed to open", err)
	}
}

func TestIntegration_ConfigError_CountryEnabled_NotConfigured(t *testing.T) {
	input := `
:19087 {
	fairness {
		scoring {
			penalty country
		}
	}
}
`
	err := expectCaddyLoadError(t, input)
	if !strings.Contains(err.Error(), `geoip_city_db is not configured`) {
		t.Errorf("error = %v, want it to mention geoip_city_db is not configured", err)
	}
}

func TestIntegration_ConfigError_CountryEnabled_FailedToOpen(t *testing.T) {
	badPath := filepath.Join(t.TempDir(), "does-not-exist.mmdb")
	input := fmt.Sprintf(`
:19088 {
	fairness {
		geoip_city_db %s
		scoring {
			penalty country
		}
	}
}
`, badPath)
	err := expectCaddyLoadError(t, input)
	if !strings.Contains(err.Error(), "failed to open") {
		t.Errorf("error = %v, want it to mention the DB failed to open", err)
	}
}

func TestIntegration_ConfigError_UserEnabled_NotConfigured(t *testing.T) {
	input := `
:19089 {
	fairness {
		scoring {
			penalty user
		}
	}
}
`
	err := expectCaddyLoadError(t, input)
	if !strings.Contains(err.Error(), `auth_jwks_url is not configured`) {
		t.Errorf("error = %v, want it to mention auth_jwks_url is not configured", err)
	}
}

func TestIntegration_ConfigError_UserEnabled_FailedToInitialize(t *testing.T) {
	input := `
:19090 {
	fairness {
		auth_jwks_url ://bad-url
		scoring {
			penalty user
		}
	}
}
`
	err := expectCaddyLoadError(t, input)
	if !strings.Contains(err.Error(), "failed to initialize") {
		t.Errorf("error = %v, want it to mention the JWKS URL failed to initialize", err)
	}
}

// TestIntegration_ConfigError_ExemptCountryEnabled_NotConfigured proves the
// geoip_city_db requirement for exempt_country applies per-dimension even
// when the dimension configuring it isn't `country` itself -- ipv4_subnet
// here never triggers the country-dimension checks above, so this is the
// only thing that would catch a broken/missing geoip_city_db in this case.
func TestIntegration_ConfigError_ExemptCountryEnabled_NotConfigured(t *testing.T) {
	input := `
:19094 {
	fairness {
		scoring {
			penalty ipv4_subnet alpha=0.2 soft=100:10 hard=500:40 exempt_country=PT
		}
	}
}
`
	err := expectCaddyLoadError(t, input)
	if !strings.Contains(err.Error(), `geoip_city_db is not configured`) {
		t.Errorf("error = %v, want it to mention geoip_city_db is not configured", err)
	}
}

func TestIntegration_ConfigError_ExemptCountryEnabled_FailedToOpen(t *testing.T) {
	badPath := filepath.Join(t.TempDir(), "does-not-exist.mmdb")
	input := fmt.Sprintf(`
:19095 {
	fairness {
		geoip_city_db %s
		scoring {
			penalty ipv4_subnet alpha=0.2 soft=100:10 hard=500:40 exempt_country=PT
		}
	}
}
`, badPath)
	err := expectCaddyLoadError(t, input)
	if !strings.Contains(err.Error(), "failed to open") {
		t.Errorf("error = %v, want it to mention the DB failed to open", err)
	}
}

// Positive control: enabling `user` against a genuinely working JWKS
// endpoint must load cleanly -- the three tests above only prove the error
// paths fire; this proves they don't false-positive on a valid setup.
func TestIntegration_ConfigError_UserEnabled_ValidJWKS_LoadsCleanly(t *testing.T) {
	jwksURL, _ := startJWKSServerAndSignToken(t, "researcher")
	input := fmt.Sprintf(`
:19091 {
	fairness {
		auth_jwks_url %s
		scoring {
			penalty user
		}
	}
}
`, jwksURL)
	loadCaddy(t, input)
}

// TestIntegration_Provision_ValidationFailure_ReleasesAcquiredPoolRefs guards
// the h.releaseAcquired() fix in Provision's validation-failure paths
// (module.go): a *caddy.Load whose config fails validation must not leak the
// JWKS background refresh goroutine it acquired before failing. Caddy does
// not call Cleanup on a Handler whose own Provision returned an error, so
// without releaseAcquired() being called explicitly, each failed load here
// would leak one goroutine forever. Repeating the failing load many times
// and asserting the goroutine count doesn't grow is the only black-box
// signal available -- the fairness App itself is reprovisioned fresh (new,
// empty UsagePools) on every successful *caddy.Load*, so a post-hoc refcount
// check on a subsequent load can't observe a leak from an earlier failed one
// directly; only the underlying goroutine can.
func TestIntegration_Provision_ValidationFailure_ReleasesAcquiredPoolRefs(t *testing.T) {
	jwksURL, _ := startJWKSServerAndSignToken(t, "researcher")
	badPath := filepath.Join(t.TempDir(), "does-not-exist.mmdb")
	input := fmt.Sprintf(`
:19092 {
	fairness {
		auth_jwks_url %s
		geoip_asn_db %s
		scoring {
			penalty user
			penalty asn
		}
	}
}
`, jwksURL, badPath)

	// Warm up and let any steady-state background goroutines (e.g. from
	// package init or earlier tests) settle before taking the baseline.
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()

	const attempts = 20
	for i := 0; i < attempts; i++ {
		if err := expectCaddyLoadError(t, input); !strings.Contains(err.Error(), "asn") {
			t.Fatalf("attempt %d: error = %v, want it to mention the asn validation failure", i, err)
		}
	}

	// Give any (incorrectly) lingering goroutines a moment to be counted,
	// then retry a few times to absorb scheduler noise before failing.
	var after int
	for i := 0; i < 10; i++ {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
		after = runtime.NumGoroutine()
		if after <= before+2 {
			break
		}
	}
	if after > before+2 {
		t.Errorf("goroutine count after %d failed loads = %d, want <= %d (baseline %d) -- releaseAcquired() may not be releasing the JWKS verifier's background refresh goroutine", attempts, after, before+2, before)
	}
}

// TestIntegration_EndToEnd_NoScoringBlock_ZeroDimensionsTracked is the
// end-to-end counterpart to scoring_test.go's
// TestResolveScoringConfig_NoScoringBlockEnablesNoDimensions: a fairness
// block with no `scoring { }` sub-block at all must, through the *real*
// Caddyfile-adapter → JSON → caddy.Load pipeline (not just a direct
// UnmarshalCaddyfile call in-process), still end up with zero dimensions
// tracked. This specifically guards against the Handler.ScoringOverrides
// field (and its nil-vs-populated distinction) failing to survive that JSON
// round-trip -- the same class of bug that made every opt-in `penalty <dim>`
// line silently inert at real runtime before ScoringOverrides was exported.
func TestIntegration_EndToEnd_NoScoringBlock_ZeroDimensionsTracked(t *testing.T) {
	adminLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	adminAddr := adminLn.Addr().String()
	adminLn.Close()

	input := `
:19093 {
	fairness {
		backend no-scoring-block
	}
	respond "ok" 200
}
`
	cfg := adaptCaddyfile(t, input)
	cfg["admin"] = map[string]any{"listen": adminAddr}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := caddy.Load(cfgJSON, false); err != nil {
		t.Fatalf("caddy.Load: %v", err)
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Errorf("caddy.Stop: %v", err)
		}
	})
	time.Sleep(150 * time.Millisecond)

	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get("http://127.0.0.1:19093/")
	if err != nil {
		t.Fatalf("synthetic request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("synthetic request status = %d, want 200", resp.StatusCode)
	}

	fResp, err := client.Get("http://" + adminAddr + "/fairness/status")
	if err != nil {
		t.Fatalf("GET /fairness/status: %v", err)
	}
	defer fResp.Body.Close()
	if fResp.StatusCode != http.StatusOK {
		t.Fatalf("/fairness/status status = %d, want 200", fResp.StatusCode)
	}
	var fBody struct {
		Backends []struct {
			Backend              string             `json:"backend"`
			BaseScores           map[string]float64 `json:"base_scores"`
			DimensionEntryCounts map[string]int     `json:"dimension_entry_counts"`
		} `json:"backends"`
	}
	if err := json.NewDecoder(fResp.Body).Decode(&fBody); err != nil {
		t.Fatalf("decode /fairness/status: %v", err)
	}
	if len(fBody.Backends) != 1 || fBody.Backends[0].Backend != "no-scoring-block" {
		t.Fatalf("fairness backends = %+v, want 1 entry with backend=no-scoring-block", fBody.Backends)
	}
	if got := fBody.Backends[0].DimensionEntryCounts; len(got) != 0 {
		t.Errorf("dimension_entry_counts = %+v, want empty -- no `scoring { }` block was given, so no dimension should ever be tracked", got)
	}
	// Base scores still apply even with zero dimensions enabled (§4.3 design
	// refinement: base_score is independent of dimension enablement).
	if len(fBody.Backends[0].BaseScores) == 0 {
		t.Errorf("base_scores = %+v, want the hardcoded defaults to still be present", fBody.Backends[0].BaseScores)
	}
}
