package fairness

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestBucketIPv4(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		want string
	}{
		{"mid-range address", "203.0.113.5", "203.0.113.0/24"},
		{"low boundary .0", "203.0.113.0", "203.0.113.0/24"},
		{"high boundary .255", "203.0.113.255", "203.0.113.0/24"},
		{"different /24", "198.51.100.42", "198.51.100.0/24"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("test bug: invalid IP %q", tc.ip)
			}
			got := bucketIPv4(ip)
			if got != tc.want {
				t.Errorf("bucketIPv4(%q) = %q, want %q", tc.ip, got, tc.want)
			}
		})
	}
}

func TestBucketIPv4_RejectsIPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	if got := bucketIPv4(ip); got != "" {
		t.Errorf("bucketIPv4(IPv6) = %q, want \"\"", got)
	}
}

func TestBucketIPv6(t *testing.T) {
	cases := []struct {
		name      string
		ip        string
		prefixLen int
		want      string
	}{
		{"48-bit bucket", "2001:db8:1234:5678::1", 48, "2001:db8:1234::/48"},
		{"48-bit boundary all-ones tail", "2001:db8:1234:ffff:ffff:ffff:ffff:ffff", 48, "2001:db8:1234::/48"},
		{"56-bit bucket (default)", "2001:db8:1:2300::1", 56, "2001:db8:1:2300::/56"},
		{"56-bit boundary", "2001:db8:1:23ff:ffff:ffff:ffff:ffff", 56, "2001:db8:1:2300::/56"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("test bug: invalid IP %q", tc.ip)
			}
			got := bucketIPv6(ip, tc.prefixLen)
			if got != tc.want {
				t.Errorf("bucketIPv6(%q, %d) = %q, want %q", tc.ip, tc.prefixLen, got, tc.want)
			}
		})
	}
}

func TestBucketIPv6_RejectsIPv4(t *testing.T) {
	ip := net.ParseIP("203.0.113.5")
	if got := bucketIPv6(ip, 56); got != "" {
		t.Errorf("bucketIPv6(IPv4) = %q, want \"\"", got)
	}
}

func TestBucketIPv6_RejectsNil(t *testing.T) {
	if got := bucketIPv6(nil, 56); got != "" {
		t.Errorf("bucketIPv6(nil) = %q, want \"\"", got)
	}
}

func TestBucketIPv4_MalformedInput(t *testing.T) {
	// net.ParseIP("") returns nil; bucketIPv4/bucketIPv6 must not panic.
	var nilIP net.IP
	if got := bucketIPv4(nilIP); got != "" {
		t.Errorf("bucketIPv4(nil) = %q, want \"\"", got)
	}
}

func TestResolveClientIP_FromCaddyVar(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{
		caddyhttp.ClientIPVarKey: "203.0.113.9",
	})
	req = req.WithContext(ctx)

	got := resolveClientIP(req)
	if got == nil || got.String() != "203.0.113.9" {
		t.Errorf("resolveClientIP() = %v, want 203.0.113.9", got)
	}
}

func TestResolveClientIP_FallsBackToRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.7:54321"

	got := resolveClientIP(req)
	if got == nil || got.String() != "198.51.100.7" {
		t.Errorf("resolveClientIP() = %v, want 198.51.100.7", got)
	}
}

func TestResolveClientIP_FallbackNoPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.7" // no port

	got := resolveClientIP(req)
	if got == nil || got.String() != "198.51.100.7" {
		t.Errorf("resolveClientIP() = %v, want 198.51.100.7", got)
	}
}

func TestResolveClientIP_FallbackStripsIPv6Zone(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[fe80::1%eth0]:1234"

	got := resolveClientIP(req)
	if got == nil || got.String() != "fe80::1" {
		t.Errorf("resolveClientIP() = %v, want fe80::1", got)
	}
}

func TestClassify_IPv4(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ip := net.ParseIP("203.0.113.5")

	c := classify(&Config{}, nil, nil, ip, req)

	if c.IP != "203.0.113.5" {
		t.Errorf("IP = %q, want 203.0.113.5", c.IP)
	}
	if c.Net24 != "203.0.113.0/24" {
		t.Errorf("Net24 = %q, want 203.0.113.0/24", c.Net24)
	}
	if c.NetV6 != "" {
		t.Errorf("NetV6 = %q, want \"\"", c.NetV6)
	}
	if c.UserClass != UserClassAnonymous {
		t.Errorf("UserClass = %q, want anonymous", c.UserClass)
	}
	if c.UserID != "" {
		t.Errorf("UserID = %q, want \"\"", c.UserID)
	}
}

func TestClassify_IPv6DefaultPrefix(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ip := net.ParseIP("2001:db8:1:2300::1")

	// Zero-value Config: default IPv6 prefix length (56) applies.
	c := classify(&Config{}, nil, nil, ip, req)

	if c.Net24 != "" {
		t.Errorf("Net24 = %q, want \"\"", c.Net24)
	}
	if c.NetV6 != "2001:db8:1:2300::/56" {
		t.Errorf("NetV6 = %q, want 2001:db8:1:2300::/56", c.NetV6)
	}
}

func TestClassify_IPv6ConfiguredPrefix48(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ip := net.ParseIP("2001:db8:1234:5678::1")

	cfg := &Config{IPv6PrefixLength: 48}
	c := classify(cfg, nil, nil, ip, req)

	if c.NetV6 != "2001:db8:1234::/48" {
		t.Errorf("NetV6 = %q, want 2001:db8:1234::/48", c.NetV6)
	}
}

func TestClassify_NilIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	c := classify(&Config{}, nil, nil, nil, req)

	if c.IP != "" || c.Net24 != "" || c.NetV6 != "" {
		t.Errorf("expected empty IP fields for nil ip, got %+v", c)
	}
	if c.UserClass != UserClassAnonymous {
		t.Errorf("UserClass = %q, want anonymous", c.UserClass)
	}
}

func TestClassify_NilGeoAndAuthFailOpen(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some.token.value")
	ip := net.ParseIP("203.0.113.5")

	// nil geo and nil auth (no verifier configured) must not panic and
	// must fail open to anonymous/no ASN/no country.
	c := classify(&Config{}, nil, nil, ip, req)

	if c.ASN != 0 {
		t.Errorf("ASN = %d, want 0", c.ASN)
	}
	if c.Country != "" {
		t.Errorf("Country = %q, want \"\"", c.Country)
	}
	if c.UserClass != UserClassAnonymous {
		t.Errorf("UserClass = %q, want anonymous (no verifier configured)", c.UserClass)
	}
}
