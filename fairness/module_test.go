package fairness

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestUnmarshalCaddyfile_BasicDirectives(t *testing.T) {
	input := `fairness {
		geoip_city_db /etc/caddy/GeoLite2-City.mmdb
		geoip_asn_db  /etc/caddy/GeoLite2-ASN.mmdb
		auth_issuer   https://sso.example.org/realms/arquivo
		auth_jwks_url https://sso.example.org/realms/arquivo/protocol/openid-connect/certs
		auth_audience arquivo-api
		ipv6_prefix_length 48
		ewma_tick_interval 1s
		idle_entry_ttl 10m
	}`

	d := caddyfile.NewTestDispenser(input)
	var h Handler
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}

	if h.GeoIPCityDB != "/etc/caddy/GeoLite2-City.mmdb" {
		t.Errorf("GeoIPCityDB = %q", h.GeoIPCityDB)
	}
	if h.GeoIPASNDB != "/etc/caddy/GeoLite2-ASN.mmdb" {
		t.Errorf("GeoIPASNDB = %q", h.GeoIPASNDB)
	}
	if h.AuthIssuer != "https://sso.example.org/realms/arquivo" {
		t.Errorf("AuthIssuer = %q", h.AuthIssuer)
	}
	if h.AuthJWKSURL != "https://sso.example.org/realms/arquivo/protocol/openid-connect/certs" {
		t.Errorf("AuthJWKSURL = %q", h.AuthJWKSURL)
	}
	if h.AuthAudience != "arquivo-api" {
		t.Errorf("AuthAudience = %q", h.AuthAudience)
	}
	if h.IPv6PrefixLength != 48 {
		t.Errorf("IPv6PrefixLength = %d", h.IPv6PrefixLength)
	}
	if h.EWMATickInterval != time.Second {
		t.Errorf("EWMATickInterval = %v", h.EWMATickInterval)
	}
	if h.IdleEntryTTL != 10*time.Minute {
		t.Errorf("IdleEntryTTL = %v", h.IdleEntryTTL)
	}
}

func TestUnmarshalCaddyfile_IgnoresScoringSubblock(t *testing.T) {
	input := `fairness {
		geoip_city_db /etc/caddy/GeoLite2-City.mmdb

		scoring {
			base_score researcher 100
			base_score anonymous  60
			penalty ip alpha=0.2 soft=20:-10 hard=100:-40
		}
	}`

	d := caddyfile.NewTestDispenser(input)
	var h Handler
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile with scoring sub-block: %v", err)
	}
	if h.GeoIPCityDB != "/etc/caddy/GeoLite2-City.mmdb" {
		t.Errorf("GeoIPCityDB = %q, want directive after scoring block to still parse", h.GeoIPCityDB)
	}
}

func TestUnmarshalCaddyfile_InvalidIPv6PrefixLength(t *testing.T) {
	input := `fairness {
		ipv6_prefix_length 64
	}`
	d := caddyfile.NewTestDispenser(input)
	var h Handler
	if err := h.UnmarshalCaddyfile(d); err == nil {
		t.Fatal("expected error for ipv6_prefix_length 64, got nil")
	}
}

func TestUnmarshalCaddyfile_UnrecognizedDirective(t *testing.T) {
	input := `fairness {
		not_a_real_directive foo
	}`
	d := caddyfile.NewTestDispenser(input)
	var h Handler
	if err := h.UnmarshalCaddyfile(d); err == nil {
		t.Fatal("expected error for unrecognized subdirective, got nil")
	}
}

func TestUnmarshalCaddyfile_ArchivedDomainRegex(t *testing.T) {
	input := `fairness {
		archived_domain_regex ^/wayback/\d+/https?://([^/]+)
	}`
	d := caddyfile.NewTestDispenser(input)
	var h Handler
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	if h.ArchivedDomainRegex != `^/wayback/\d+/https?://([^/]+)` {
		t.Errorf("ArchivedDomainRegex = %q", h.ArchivedDomainRegex)
	}
}

func TestHandler_ServeHTTP_SetsArchivedDomainLogField(t *testing.T) {
	h := Handler{archivedDomainRe: testArchivedDomainRegex}

	req := httptest.NewRequest(http.MethodGet, "/wayback/20230101120000/http://www.CienciaHoje.pt/artigo", nil)
	req.RemoteAddr = "203.0.113.5:1234"
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{})
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })

	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	v := caddyhttp.GetVar(req.Context(), logFieldsVarKey)
	fields, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("log fields var = %#v, want map[string]any", v)
	}
	if fields["archived_domain"] != "cienciahoje.pt" {
		t.Errorf(`log fields["archived_domain"] = %#v, want "cienciahoje.pt"`, fields["archived_domain"])
	}
}

// TestScoringState_ArchivedDomain_ConvergesAcrossManyIdentities is the
// regression test for the motivating incident (many distinct
// IPs/ASNs -- simulating rotating operator identities -- all hammering
// replay of one archived domain): the ip/asn dimensions must stay quiet
// (no single identity individually crosses its own threshold) while
// archived_domain's EWMA converges on the true aggregate rate and its
// penalty fires.
func TestScoringState_ArchivedDomain_ConvergesAcrossManyIdentities(t *testing.T) {
	cfg := resolveScoringConfig(&scoringOverrides{
		EnabledDimensions: map[string]bool{"ip": true, "asn": true, "archived_domain": true},
	})
	s := newScoringState(cfg, time.Second, time.Hour)

	const requesters = 600
	now := time.Now()
	for tick := 0; tick < 25; tick++ {
		for i := 0; i < requesters; i++ {
			c := Classification{
				IP:             fmt.Sprintf("requester-%d", i),
				ASN:            uint(1000 + i), // distinct operator per requester
				ArchivedDomain: "cienciahoje.pt",
			}
			s.track(c, now)
		}
		s.tick(now)
	}

	archivedRPS := s.entryEWMARPS("archived_domain", "cienciahoje.pt")
	if archivedRPS <= cfg.Dimensions["archived_domain"].SoftThreshold {
		t.Fatalf("archived_domain EWMA = %v, want > soft threshold %v (aggregate rate should converge)", archivedRPS, cfg.Dimensions["archived_domain"].SoftThreshold)
	}

	sampleIP := "requester-0"
	if rps := s.entryEWMARPS("ip", sampleIP); rps >= cfg.Dimensions["ip"].SoftThreshold {
		t.Errorf("ip EWMA for %q = %v, want < soft threshold %v", sampleIP, rps, cfg.Dimensions["ip"].SoftThreshold)
	}
	if rps := s.entryEWMARPS("asn", "1000"); rps >= cfg.Dimensions["asn"].SoftThreshold {
		t.Errorf("asn EWMA for asn 1000 = %v, want < soft threshold %v", rps, cfg.Dimensions["asn"].SoftThreshold)
	}

	_, breakdown := s.computeScoreBreakdown(Classification{IP: sampleIP, ASN: 1000, ArchivedDomain: "cienciahoje.pt"})
	if _, ok := breakdown["penalty_ip"]; ok {
		t.Errorf("breakdown = %+v, want no penalty_ip (this requester's own rate never crossed the ip threshold)", breakdown)
	}
	if _, ok := breakdown["penalty_asn"]; ok {
		t.Errorf("breakdown = %+v, want no penalty_asn", breakdown)
	}
	if _, ok := breakdown["penalty_archived_domain"]; !ok {
		t.Errorf("breakdown = %+v, want penalty_archived_domain to fire (aggregate rate against this domain exceeded the soft threshold)", breakdown)
	}
}

func TestHandler_ServeHTTP_SetsClassificationVar(t *testing.T) {
	h := Handler{}
	// No GeoIP/auth acquired (Provision not run) -- ServeHTTP must still
	// work fail-open with nil geo/auth.

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:1234"
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{})
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	called := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		v := caddyhttp.GetVar(r.Context(), classificationVarKey)
		c, ok := v.(Classification)
		if !ok {
			t.Fatalf("classification var = %#v, want Classification", v)
		}
		if c.IP != "203.0.113.5" {
			t.Errorf("Classification.IP = %q, want 203.0.113.5", c.IP)
		}
		if c.Net24 != "203.0.113.0/24" {
			t.Errorf("Classification.Net24 = %q, want 203.0.113.0/24", c.Net24)
		}
		if c.UserClass != UserClassAnonymous {
			t.Errorf("Classification.UserClass = %q, want anonymous", c.UserClass)
		}
		return nil
	})

	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !called {
		t.Fatal("next handler was not called")
	}
}
