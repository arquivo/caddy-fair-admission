package fairness

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestParseNetwork(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"192.0.2.0/24", "192.0.2.0/24"},
		{"192.0.2.7", "192.0.2.7/32"},
		{"2001:db8::/32", "2001:db8::/32"},
		{"2001:db8::1", "2001:db8::1/128"},
		{"fe80::1%eth0", "fe80::1/128"}, // zone ignored, as in Caddy's client_ip matcher
		{"::1", "::1/128"},
	}
	for _, tc := range cases {
		got, err := parseNetwork(tc.in)
		if err != nil {
			t.Errorf("parseNetwork(%q): %v", tc.in, err)
			continue
		}
		if got.String() != tc.want {
			t.Errorf("parseNetwork(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestParseNetwork_Invalid(t *testing.T) {
	for _, in := range []string{
		"", "not-an-ip", "192.0.2.0/33", "192.0.2.300",
		"::ffff:192.0.2.0/120", "::ffff:192.0.2.7", // IPv4-mapped
		"192.0.2.7/24", "192.168.1.0/8", // host bits set
		"0.0.0.0/0", "::/0",
	} {
		if p, err := parseNetwork(in); err == nil {
			t.Errorf("parseNetwork(%q) = %s, want an error", in, p)
		}
	}
}

func TestInNetworks(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	cases := []struct {
		ip   net.IP
		want bool
	}{
		{net.ParseIP("192.0.2.200"), true},
		{net.ParseIP("192.0.2.200").To4(), true},
		{net.ParseIP("::ffff:192.0.2.200"), true},
		{net.ParseIP("198.51.100.1"), false},
		{net.ParseIP("2001:db8:1::5"), true},
		{net.ParseIP("2001:db9::5"), false},
		{nil, false},
	}
	for _, tc := range cases {
		if got := inNetworks(prefixes, tc.ip); got != tc.want {
			t.Errorf("inNetworks(%v) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	if inNetworks(nil, net.ParseIP("192.0.2.200")) {
		t.Error("inNetworks with no prefixes = true, want false")
	}
}

// JSON config bypasses the Caddyfile parser, so Provision checks the list.
func TestProvision_RejectsInvalidPriorityNetworksFromJSON(t *testing.T) {
	for _, js := range []string{`[""]`, `["::ffff:10.0.0.0/104"]`, `["192.0.2.7/24"]`, `["::/0"]`} {
		var cfg Config
		if err := json.Unmarshal([]byte(`{"priority_networks":`+js+`}`), &cfg); err != nil {
			t.Fatalf("Unmarshal %s: %v", js, err)
		}
		h := &Handler{Config: cfg}
		err := h.Provision(caddy.Context{})
		if err == nil || !strings.Contains(err.Error(), "priority_network") {
			t.Errorf("Provision with priority_networks %s = %v, want a priority_network error", js, err)
		}
	}
}

func TestUnmarshalCaddyfile_PriorityNetwork_InlineBlockAndRepeatedAccumulate(t *testing.T) {
	input := `fairness {
		priority_network 127.0.0.1 ::1
		priority_network {
			192.0.2.0/24 198.51.100.0/24
			2001:db8::/32
		}
		priority_network 203.0.113.9/32 {
			10.0.0.0/8
		}
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	want := []string{"127.0.0.1/32", "::1/128", "192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32", "203.0.113.9/32", "10.0.0.0/8"}
	if len(h.PriorityNetworks) != len(want) {
		t.Fatalf("PriorityNetworks = %v, want %v", h.PriorityNetworks, want)
	}
	for i, p := range h.PriorityNetworks {
		if p.String() != want[i] {
			t.Errorf("PriorityNetworks[%d] = %s, want %s", i, p, want[i])
		}
	}
}

func TestUnmarshalCaddyfile_PriorityNetwork_Errors(t *testing.T) {
	cases := map[string]string{
		"no networks":    `fairness { priority_network }`,
		"empty block":    "fairness {\n priority_network {\n }\n}",
		"invalid inline": `fairness { priority_network 192.0.2.0/24 nope }`,
		"invalid block":  "fairness {\n priority_network {\n 192.0.2.0/40\n }\n}",
	}
	for name, input := range cases {
		var h Handler
		err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
		if err == nil {
			t.Errorf("%s: UnmarshalCaddyfile succeeded, want an error", name)
			continue
		}
		if !strings.Contains(err.Error(), "priority_network") {
			t.Errorf("%s: error = %v, want it to name priority_network", name, err)
		}
	}
}

func TestConfig_PriorityNetworks_JSONRoundTrip(t *testing.T) {
	in := Config{PriorityNetworks: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("::1/128")}}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(b), `"priority_networks":["192.0.2.0/24","::1/128"]`) {
		t.Errorf("JSON = %s, want priority_networks as CIDR strings", b)
	}
	var out Config
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(out.PriorityNetworks) != 2 || out.PriorityNetworks[0] != in.PriorityNetworks[0] || out.PriorityNetworks[1] != in.PriorityNetworks[1] {
		t.Errorf("round-tripped PriorityNetworks = %v, want %v", out.PriorityNetworks, in.PriorityNetworks)
	}
}

func TestClassify_PriorityNetwork(t *testing.T) {
	cfg := &Config{PriorityNetworks: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	c := classify(cfg, nil, nil, nil, net.ParseIP("192.0.2.10"), req)
	if !c.Priority || c.UserClass != UserClassInternal || c.UserID != "" {
		t.Errorf("listed client: Priority=%v UserClass=%q UserID=%q, want true/internal/\"\"", c.Priority, c.UserClass, c.UserID)
	}

	c = classify(cfg, nil, nil, nil, net.ParseIP("198.51.100.10"), req)
	if c.Priority || c.UserClass != UserClassAnonymous {
		t.Errorf("unlisted client: Priority=%v UserClass=%q, want false/anonymous", c.Priority, c.UserClass)
	}

	c = classify(cfg, nil, nil, nil, nil, req)
	if c.Priority || c.UserClass != UserClassAnonymous {
		t.Errorf("unresolved client IP: Priority=%v UserClass=%q, want false/anonymous", c.Priority, c.UserClass)
	}
}

// An unverifiable bearer token (unknown) from a listed network is still
// classified internal: the address is the stronger signal.
func TestClassify_PriorityNetwork_BeatsUnverifiableToken(t *testing.T) {
	cfg := &Config{PriorityNetworks: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
	v := mustBuildTestVerifier(t, "http://127.0.0.1:1")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some.token.value")

	c := classify(cfg, nil, v, nil, net.ParseIP("192.0.2.10"), req)
	if !c.Priority || c.UserClass != UserClassInternal {
		t.Errorf("Priority=%v UserClass=%q, want true/internal", c.Priority, c.UserClass)
	}
}

// applySession runs after classify, and must not replace the internal class
// a priority network gave, whatever the cookie says.
func TestApplySession_KeepsPriorityNetworkInternalClass(t *testing.T) {
	for _, read := range []sessionRead{{result: sessionValid, id: "abc"}, {result: sessionInvalid}, {result: sessionExpired}} {
		c := Classification{UserClass: UserClassInternal, Priority: true}
		applySession(&c, read)
		if c.UserClass != UserClassInternal || c.UserID != "" {
			t.Errorf("cookie %v: got %q/%q, want internal/\"\"", read.result, c.UserClass, c.UserID)
		}
	}
}

func TestHandler_ServeHTTP_PriorityNetworkSetsVarsAndLogField(t *testing.T) {
	h := &Handler{Config: Config{PriorityNetworks: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}}
	h.scoring = newScoringState(resolveScoringConfig(&scoringOverrides{
		BaseScores: map[UserClass]float64{UserClassAnonymous: 60},
	}), defaultEWMATickInterval, defaultIdleEntryTTL)

	for _, tc := range []struct {
		remoteAddr string
		priority   bool
		score      float64
		class      string
	}{
		{"192.0.2.10:1234", true, 100, "internal"},
		{"198.51.100.10:1234", false, 60, "anonymous"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = tc.remoteAddr
		req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{}))
		next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
		if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}

		if got := caddyhttp.GetVar(req.Context(), priorityVarKey); got != tc.priority {
			t.Errorf("%s: %s var = %#v, want %v", tc.remoteAddr, priorityVarKey, got, tc.priority)
		}
		if got := caddyhttp.GetVar(req.Context(), fairnessScoreVarKey); got != tc.score {
			t.Errorf("%s: score = %#v, want %v", tc.remoteAddr, got, tc.score)
		}
		lf, _ := caddyhttp.GetVar(req.Context(), logFieldsVarKey).(map[string]any)
		if lf["priority"] != tc.priority || lf["user_class"] != tc.class {
			t.Errorf("%s: log fields priority=%#v user_class=%#v, want %v/%s", tc.remoteAddr, lf["priority"], lf["user_class"], tc.priority, tc.class)
		}
	}
}
