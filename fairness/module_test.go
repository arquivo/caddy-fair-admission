package fairness

import (
	"context"
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
