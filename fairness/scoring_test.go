package fairness

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// --- 1. Exact EWMA math against a hand-computed sequence -------------------

func TestScoringState_Tick_ExactEWMAMath(t *testing.T) {
	const alpha = 0.2
	const tickInterval = time.Second

	cfg := newDefaultScoringConfig()
	pc := cfg.Dimensions["ip"]
	pc.Alpha = alpha
	cfg.Dimensions["ip"] = pc

	s := newScoringState(cfg, tickInterval, time.Hour)

	counts := []int{10, 10, 10, 0, 0}
	// Hand-computed: ewma(t) = alpha*rate + (1-alpha)*ewma(t-1), rate =
	// count/1s.
	//   t1: 0.2*10 + 0.8*0       = 2.0
	//   t2: 0.2*10 + 0.8*2.0     = 3.6
	//   t3: 0.2*10 + 0.8*3.6     = 4.88
	//   t4: 0.2*0  + 0.8*4.88    = 3.904
	//   t5: 0.2*0  + 0.8*3.904   = 3.1232
	want := []float64{2.0, 3.6, 4.88, 3.904, 3.1232}

	c := Classification{IP: "203.0.113.5"}
	now := time.Unix(1_700_000_000, 0)

	for i, n := range counts {
		for j := 0; j < n; j++ {
			s.track(c, now)
		}
		now = now.Add(tickInterval)
		s.tick(now)

		got := s.entryEWMARPS("ip", "203.0.113.5")
		if diff := math.Abs(got - want[i]); diff > 1e-9 {
			t.Errorf("tick %d: EWMARPS = %v, want %v (diff %v)", i+1, got, want[i], diff)
		}
	}
}

func TestScoringState_Tick_DifferentTickIntervalNormalizesToPerSecondRate(t *testing.T) {
	// tick interval 2s: 10 requests over one tick is a rate of 5 rps, not 10.
	const alpha = 0.5
	cfg := newDefaultScoringConfig()
	pc := cfg.Dimensions["ip"]
	pc.Alpha = alpha
	cfg.Dimensions["ip"] = pc

	s := newScoringState(cfg, 2*time.Second, time.Hour)
	c := Classification{IP: "203.0.113.5"}
	now := time.Unix(1_700_000_000, 0)

	for i := 0; i < 10; i++ {
		s.track(c, now)
	}
	now = now.Add(2 * time.Second)
	s.tick(now)

	want := 0.5*5.0 + 0.5*0.0 // rate = 10/2s = 5
	got := s.entryEWMARPS("ip", "203.0.113.5")
	if diff := math.Abs(got - want); diff > 1e-9 {
		t.Errorf("EWMARPS = %v, want %v", got, want)
	}
}

// --- 2. Exact penalty amounts at/around soft/hard thresholds ----------------

func TestPenaltyContribution_Boundaries(t *testing.T) {
	pc := PenaltyConfig{Alpha: 0.2, SoftThreshold: 20, SoftPenalty: 10, HardThreshold: 100, HardPenalty: 40}

	cases := []struct {
		name string
		rps  float64
		want float64
	}{
		{"well below soft", 5, 0},
		{"just below soft", 19.999, 0},
		{"exactly at soft threshold (exclusive boundary: no penalty yet)", 20, 0},
		{"just above soft", 20.001, 10},
		{"mid-band between soft and hard", 50, 10},
		{"just below hard", 99.999, 10},
		{"exactly at hard threshold (exclusive boundary: still soft penalty)", 100, 10},
		{"just above hard", 100.001, 40},
		{"well above hard", 10000, 40},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := penaltyContribution(pc, tc.rps)
			if got != tc.want {
				t.Errorf("penaltyContribution(rps=%v) = %v, want %v", tc.rps, got, tc.want)
			}
		})
	}
}

// --- 3. Override-merge correctness ------------------------------------------

func TestResolveScoringConfig_OverrideOnlyAffectsItsOwnDimension(t *testing.T) {
	overridden := &scoringOverrides{
		EnabledDimensions: map[string]bool{"ip": true},
		Penalties: map[string]PenaltyConfig{
			"ip": {Alpha: 0.9, SoftThreshold: 1, SoftPenalty: 2, HardThreshold: 3, HardPenalty: 4},
		},
	}

	resolvedA := resolveScoringConfig(overridden)
	resolvedB := resolveScoringConfig(nil) // separately-resolved, no dimensions enabled

	if reflect.DeepEqual(resolvedA.Dimensions["ip"], newDefaultScoringConfig().Dimensions["ip"]) {
		t.Fatalf("expected block A's overridden ip dimension to differ from the hardcoded default")
	}

	// No other dimension was enabled on this block, so none of them should
	// even be present in the resolved config.
	for _, dim := range []string{"ipv4_subnet", "ipv6_subnet", "asn", "country", "user"} {
		if _, ok := resolvedA.Dimensions[dim]; ok {
			t.Errorf("dimension %q on overriding block is present (%+v), want absent (never enabled)", dim, resolvedA.Dimensions[dim])
		}
	}
	// Block B enabled nothing at all: Dimensions must be empty.
	if len(resolvedB.Dimensions) != 0 {
		t.Errorf("block B (nil overrides) Dimensions = %+v, want empty", resolvedB.Dimensions)
	}
}

func TestResolveScoringConfig_MutationIsolation(t *testing.T) {
	overridden := &scoringOverrides{
		EnabledDimensions: map[string]bool{"ip": true},
		Penalties: map[string]PenaltyConfig{
			"ip": {Alpha: 0.9, SoftThreshold: 1, SoftPenalty: 2, HardThreshold: 3, HardPenalty: 4},
		},
	}
	resolvedA := resolveScoringConfig(overridden)
	resolvedB := resolveScoringConfig(nil)

	// Mutate A's map in place; B must be entirely unaffected (no shared
	// underlying map storage).
	mutated := resolvedA.Dimensions["ip"]
	mutated.Alpha = 0.0001
	resolvedA.Dimensions["ip"] = mutated
	resolvedA.BaseScores[UserClassAnonymous] = -999

	if _, ok := resolvedB.Dimensions["ip"]; ok {
		t.Errorf("mutating resolvedA leaked an \"ip\" entry into resolvedB (which enabled nothing): %+v", resolvedB.Dimensions["ip"])
	}
	if resolvedB.BaseScores[UserClassAnonymous] == -999 {
		t.Errorf("mutating resolvedA.BaseScores leaked into resolvedB.BaseScores")
	}
}

func TestResolveScoringConfig_BaseScoreOverride(t *testing.T) {
	overridden := &scoringOverrides{
		BaseScores: map[UserClass]float64{UserClassAnonymous: 42},
	}
	resolved := resolveScoringConfig(overridden)
	if resolved.BaseScores[UserClassAnonymous] != 42 {
		t.Errorf("BaseScores[anonymous] = %v, want 42", resolved.BaseScores[UserClassAnonymous])
	}
	// Untouched classes keep their defaults.
	defaults := newDefaultScoringConfig()
	if resolved.BaseScores[UserClassResearcher] != defaults.BaseScores[UserClassResearcher] {
		t.Errorf("BaseScores[researcher] = %v, want default %v", resolved.BaseScores[UserClassResearcher], defaults.BaseScores[UserClassResearcher])
	}
	// base_score is independent of dimension enablement: no penalty line was
	// given, so no dimension should be active.
	if len(resolved.Dimensions) != 0 {
		t.Errorf("Dimensions = %+v, want empty (no penalty lines given)", resolved.Dimensions)
	}
}

func TestResolveScoringConfig_MinMaxOverride(t *testing.T) {
	minV, maxV := 5.0, 90.0
	overridden := &scoringOverrides{MinScore: &minV, MaxScore: &maxV}
	resolved := resolveScoringConfig(overridden)
	if resolved.MinScore != 5 || resolved.MaxScore != 90 {
		t.Errorf("MinScore/MaxScore = %v/%v, want 5/90", resolved.MinScore, resolved.MaxScore)
	}
	if len(resolved.Dimensions) != 0 {
		t.Errorf("Dimensions = %+v, want empty (no penalty lines given)", resolved.Dimensions)
	}
}

func TestResolveScoringConfig_BarePenaltyUsesDefaultTuning(t *testing.T) {
	overridden := &scoringOverrides{EnabledDimensions: map[string]bool{"asn": true}}
	resolved := resolveScoringConfig(overridden)
	defaults := newDefaultScoringConfig()
	if !reflect.DeepEqual(resolved.Dimensions["asn"], defaults.Dimensions["asn"]) {
		t.Errorf("Dimensions[asn] = %+v, want built-in default %+v", resolved.Dimensions["asn"], defaults.Dimensions["asn"])
	}
	if len(resolved.Dimensions) != 1 {
		t.Errorf("Dimensions = %+v, want exactly {asn: ...}", resolved.Dimensions)
	}
}

func TestResolveScoringConfig_NoScoringBlockEnablesNoDimensions(t *testing.T) {
	resolved := resolveScoringConfig(nil)
	if len(resolved.Dimensions) != 0 {
		t.Errorf("Dimensions = %+v, want empty (no scoring{} block at all)", resolved.Dimensions)
	}
}

func TestComputeScoreBreakdown_NoDimensionsEnabled_AlwaysBaseScoreZeroPenalty(t *testing.T) {
	cfg := resolveScoringConfig(nil)
	s := newScoringState(cfg, time.Second, time.Hour)

	c := Classification{UserClass: UserClassAnonymous, IP: "203.0.113.9", ASN: 64500, Country: "US", UserID: "u1"}
	now := time.Unix(1_700_000_000, 0)

	// Even after tracking/ticking heavily, no dimension exists to accumulate
	// a penalty against.
	for i := 0; i < 1000; i++ {
		s.track(c, now)
	}
	s.tick(now.Add(time.Second))

	score, breakdown := s.computeScoreBreakdown(c)
	base := cfg.BaseScores[UserClassAnonymous]
	if score != base {
		t.Errorf("score = %v, want unpenalized base score %v", score, base)
	}
	if breakdown["total_penalty"] != 0 {
		t.Errorf("total_penalty = %v, want 0", breakdown["total_penalty"])
	}
}

func TestScoringState_NoDimensionsEnabled_TrackTickGCAreNoops(t *testing.T) {
	cfg := resolveScoringConfig(nil)
	s := newScoringState(cfg, time.Second, time.Hour)

	if len(s.dims) != 0 {
		t.Fatalf("newScoringState with no enabled dimensions built s.dims = %+v, want empty", s.dims)
	}

	c := Classification{IP: "203.0.113.9"}
	now := time.Unix(1_700_000_000, 0)
	s.track(c, now)
	s.tick(now.Add(time.Second))
	s.gc(now.Add(time.Hour))

	if counts := s.entryCounts(); len(counts) != 0 {
		t.Errorf("entryCounts = %+v, want empty", counts)
	}
}

// --- 4. GC reclaiming idle entries after TTL --------------------------------

func TestScoringState_GC_ReclaimsIdleEntries(t *testing.T) {
	cfg := newDefaultScoringConfig()
	ttl := 10 * time.Minute
	s := newScoringState(cfg, time.Second, ttl)

	now := time.Unix(1_700_000_000, 0)

	fresh := Classification{IP: "203.0.113.1"}
	stale := Classification{IP: "203.0.113.2"}

	s.track(fresh, now)
	s.track(stale, now)

	// Manipulate the stale entry's LastSeen directly into the past, beyond
	// the TTL; the fresh entry stays at `now`.
	dm := s.dims["ip"]
	dm.mu.Lock()
	dm.entries["203.0.113.2"].LastSeen = now.Add(-ttl - time.Minute)
	dm.mu.Unlock()

	s.gc(now)

	dm.mu.Lock()
	_, freshStillThere := dm.entries["203.0.113.1"]
	_, staleStillThere := dm.entries["203.0.113.2"]
	dm.mu.Unlock()

	if !freshStillThere {
		t.Error("gc reclaimed the fresh (not-idle) entry, want it kept")
	}
	if staleStillThere {
		t.Error("gc did not reclaim the idle entry past TTL")
	}
}

func TestScoringState_GC_ExactlyAtTTLIsNotReclaimed(t *testing.T) {
	// now.Sub(LastSeen) > ttl is the deletion condition (strict >); exactly
	// at the TTL boundary must NOT be reclaimed.
	cfg := newDefaultScoringConfig()
	ttl := 10 * time.Minute
	s := newScoringState(cfg, time.Second, ttl)

	now := time.Unix(1_700_000_000, 0)
	c := Classification{IP: "203.0.113.3"}
	s.track(c, now.Add(-ttl))

	s.gc(now)

	dm := s.dims["ip"]
	dm.mu.Lock()
	_, stillThere := dm.entries["203.0.113.3"]
	dm.mu.Unlock()
	if !stillThere {
		t.Error("gc reclaimed an entry exactly at the TTL boundary, want kept (strict > required)")
	}
}

// --- 5. Exempt-country behavior ---------------------------------------------

func TestComputeScore_ExemptCountry_TracksButNoPenalty(t *testing.T) {
	cfgExempt := newDefaultScoringConfig()
	pcExempt := cfgExempt.Dimensions["country"]
	pcExempt.ExemptCountries = map[string]bool{"PT": true}
	cfgExempt.Dimensions["country"] = pcExempt
	sExempt := newScoringState(cfgExempt, time.Second, time.Hour)

	cfgNotExempt := newDefaultScoringConfig()
	sNotExempt := newScoringState(cfgNotExempt, time.Second, time.Hour)

	c := Classification{UserClass: UserClassAnonymous, Country: "PT"}
	now := time.Unix(1_700_000_000, 0)

	// Directly push the country entity's EWMARPS far above its hard
	// threshold (10000) to simulate sustained heavy load, without waiting
	// through thousands of real ticks.
	for _, s := range []*scoringState{sExempt, sNotExempt} {
		dm := s.dims["country"]
		dm.mu.Lock()
		dm.entries["PT"] = &ClientStats{LastSeen: now, EWMARPS: 20000}
		dm.mu.Unlock()
	}

	scoreExempt := sExempt.computeScore(c)
	scoreNotExempt := sNotExempt.computeScore(c)

	base := cfgExempt.BaseScores[UserClassAnonymous]
	if scoreExempt != base {
		t.Errorf("exempt-country score = %v, want unpenalized base score %v", scoreExempt, base)
	}
	wantPenalized := clamp(base-cfgNotExempt.Dimensions["country"].HardPenalty, cfgNotExempt.MinScore, cfgNotExempt.MaxScore)
	if scoreNotExempt != wantPenalized {
		t.Errorf("non-exempt score = %v, want %v (hard-penalized)", scoreNotExempt, wantPenalized)
	}

	// Observability: track() + tick() must still update EWMARPS normally
	// for an exempt country, even though it's never penalized.
	before := sExempt.entryEWMARPS("country", "PT")
	sExempt.track(c, now)
	sExempt.tick(now.Add(time.Second))
	after := sExempt.entryEWMARPS("country", "PT")
	if after == before {
		t.Errorf("exempt country's EWMARPS did not update on tick: before=%v after=%v", before, after)
	}
}

// TestComputeScoreBreakdown_ExemptCountry_IsPerDimension verifies exemption
// is scoped to the dimension that configures it, not global: a country
// exempt from one dimension's penalty (e.g. "country") still gets penalized
// on a dimension that didn't list it (e.g. "ip") — the Arquivo.pt use case of
// exempting a high-traffic country from subnet/ASN/country penalties while
// still rate-limiting individual abusive IPs from that same country.
func TestComputeScoreBreakdown_ExemptCountry_IsPerDimension(t *testing.T) {
	cfg := ScoringConfig{
		BaseScores: map[UserClass]float64{UserClassAnonymous: 100},
		MinScore:   0,
		MaxScore:   100,
		Dimensions: map[string]PenaltyConfig{
			"ip":      {Alpha: 0.2, SoftThreshold: 20, SoftPenalty: 10, HardThreshold: 100, HardPenalty: 40},
			"country": {Alpha: 0.2, SoftThreshold: 20, SoftPenalty: 10, HardThreshold: 100, HardPenalty: 40, ExemptCountries: map[string]bool{"PT": true}},
		},
	}
	s := newScoringState(cfg, time.Second, time.Hour)

	c := Classification{UserClass: UserClassAnonymous, IP: "203.0.113.9", Country: "PT"}
	now := time.Unix(1_700_000_000, 0)

	for _, dim := range []string{"ip", "country"} {
		dm := s.dims[dim]
		dm.mu.Lock()
		dm.entries[dimensionKeyOrFatal(t, dim, c)] = &ClientStats{LastSeen: now, EWMARPS: 20000}
		dm.mu.Unlock()
	}

	_, breakdown := s.computeScoreBreakdown(c)
	if _, ok := breakdown["penalty_country"]; ok {
		t.Errorf("breakdown = %+v, want no penalty_country (PT is exempt on that dimension)", breakdown)
	}
	if breakdown["penalty_ip"] != cfg.Dimensions["ip"].HardPenalty {
		t.Errorf("penalty_ip = %v, want %v (ip dimension has no exemption for PT)", breakdown["penalty_ip"], cfg.Dimensions["ip"].HardPenalty)
	}
}

func dimensionKeyOrFatal(t *testing.T, dim string, c Classification) string {
	t.Helper()
	key, ok := dimensionKey(dim, c)
	if !ok {
		t.Fatalf("dimensionKey(%q, %+v) ok=false, want a key", dim, c)
	}
	return key
}

// --- 6. Fail-open on uninitialized state ------------------------------------

func TestComputeScore_NilScoringState_FailsOpen(t *testing.T) {
	var s *scoringState // uninitialized, e.g. Handler built without Provision

	c := Classification{UserClass: UserClassResearcher}

	var got float64
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("computeScore panicked on nil scoringState: %v", r)
			}
		}()
		got = s.computeScore(c)
	}()

	defaults := newDefaultScoringConfig()
	want := defaults.BaseScores[UserClassResearcher]
	if got != want {
		t.Errorf("nil-scoringState computeScore = %v, want base score %v", got, want)
	}
}

func TestScoringState_NilMethods_AreNoOps(t *testing.T) {
	var s *scoringState
	// None of these must panic on a nil receiver.
	s.start()
	s.track(Classification{IP: "1.2.3.4"}, time.Now())
	s.tick(time.Now())
	s.gc(time.Now())
	s.stop()
	if got := s.entryEWMARPS("ip", "1.2.3.4"); got != 0 {
		t.Errorf("entryEWMARPS on nil state = %v, want 0", got)
	}
}

func TestHandler_ServeHTTP_SetsFairnessScoreVar_FailOpenWithoutProvision(t *testing.T) {
	// Mirrors TestHandler_ServeHTTP_SetsClassificationVar in module_test.go
	// but asserts the fairness_score var specifically, on a Handler that
	// never had Provision called (h.scoring is nil) -- must fail open
	// rather than panic.
	h := Handler{}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:1234"
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{})
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	})

	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	v := caddyhttp.GetVar(req.Context(), fairnessScoreVarKey)
	score, ok := v.(float64)
	if !ok {
		t.Fatalf("fairness_score var = %#v, want float64", v)
	}
	want := newDefaultScoringConfig().BaseScores[UserClassAnonymous]
	if score != want {
		t.Errorf("fairness_score = %v, want unpenalized base score %v (fail-open)", score, want)
	}
}

// --- helper for boundary math on the clamp function -------------------------

func TestClamp(t *testing.T) {
	cases := []struct {
		v, min, max, want float64
	}{
		{50, 0, 100, 50},
		{-10, 0, 100, 0},
		{150, 0, 100, 100},
		{0, 0, 100, 0},
		{100, 0, 100, 100},
	}
	for _, tc := range cases {
		if got := clamp(tc.v, tc.min, tc.max); got != tc.want {
			t.Errorf("clamp(%v, %v, %v) = %v, want %v", tc.v, tc.min, tc.max, got, tc.want)
		}
	}
}

func TestDimensionKey(t *testing.T) {
	cases := []struct {
		name string
		dim  string
		c    Classification
		key  string
		ok   bool
	}{
		{"ip present", "ip", Classification{IP: "203.0.113.5"}, "203.0.113.5", true},
		{"ip absent", "ip", Classification{}, "", false},
		{"ipv4_subnet present", "ipv4_subnet", Classification{Net24: "203.0.113.0/24"}, "203.0.113.0/24", true},
		{"ipv4_subnet absent (ipv6 request)", "ipv4_subnet", Classification{NetV6: "2001:db8::/56"}, "", false},
		{"ipv6_subnet present", "ipv6_subnet", Classification{NetV6: "2001:db8::/56"}, "2001:db8::/56", true},
		{"ipv6_subnet absent (ipv4 request)", "ipv6_subnet", Classification{Net24: "203.0.113.0/24"}, "", false},
		{"asn present", "asn", Classification{ASN: 64500}, "64500", true},
		{"asn zero (unavailable)", "asn", Classification{ASN: 0}, "", false},
		{"country present", "country", Classification{Country: "PT"}, "PT", true},
		{"country absent", "country", Classification{}, "", false},
		{"user present", "user", Classification{UserID: "u123"}, "u123", true},
		{"user absent (anonymous)", "user", Classification{}, "", false},
		{"unrecognized dimension", "bogus", Classification{IP: "1.2.3.4"}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, ok := dimensionKey(tc.dim, tc.c)
			if key != tc.key || ok != tc.ok {
				t.Errorf("dimensionKey(%q, %+v) = (%q, %v), want (%q, %v)", tc.dim, tc.c, key, ok, tc.key, tc.ok)
			}
		})
	}
}

func TestBaseScoreFor_UnrecognizedClassFallsBackToAnonymous(t *testing.T) {
	baseScores := map[UserClass]float64{
		UserClassAnonymous:  60,
		UserClassResearcher: 100,
	}
	got := baseScoreFor(baseScores, UserClass("some-future-class"))
	if got != 60 {
		t.Errorf("baseScoreFor(unrecognized) = %v, want fallback to anonymous (60)", got)
	}
}

// --- Caddyfile parsing for scoring{} ----------------------------------------

func TestUnmarshalCaddyfile_ScoringBlock_RoundTrips(t *testing.T) {
	input := `fairness {
		scoring {
			base_score researcher 100
			base_score anonymous  60
			penalty ip alpha=0.2 soft=20:-10 hard=100:-40
			penalty ipv4_subnet alpha=0.3 soft=150:-15 hard=600:-45
			min_score 0
			max_score 100
		}
	}`

	d := caddyfile.NewTestDispenser(input)
	var h Handler
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}

	if h.ScoringOverrides == nil {
		t.Fatal("scoringOverrides is nil, want populated")
	}

	resolved := resolveScoringConfig(h.ScoringOverrides)
	if resolved.BaseScores[UserClassResearcher] != 100 {
		t.Errorf("BaseScores[researcher] = %v, want 100", resolved.BaseScores[UserClassResearcher])
	}
	if resolved.BaseScores[UserClassAnonymous] != 60 {
		t.Errorf("BaseScores[anonymous] = %v, want 60", resolved.BaseScores[UserClassAnonymous])
	}
	wantIP := PenaltyConfig{Alpha: 0.2, SoftThreshold: 20, SoftPenalty: 10, HardThreshold: 100, HardPenalty: 40}
	if !reflect.DeepEqual(resolved.Dimensions["ip"], wantIP) {
		t.Errorf("Dimensions[ip] = %+v, want %+v", resolved.Dimensions["ip"], wantIP)
	}
	wantIPv4Subnet := PenaltyConfig{Alpha: 0.3, SoftThreshold: 150, SoftPenalty: 15, HardThreshold: 600, HardPenalty: 45}
	if !reflect.DeepEqual(resolved.Dimensions["ipv4_subnet"], wantIPv4Subnet) {
		t.Errorf("Dimensions[ipv4_subnet] = %+v, want %+v", resolved.Dimensions["ipv4_subnet"], wantIPv4Subnet)
	}
	if resolved.MinScore != 0 || resolved.MaxScore != 100 {
		t.Errorf("MinScore/MaxScore = %v/%v, want 0/100", resolved.MinScore, resolved.MaxScore)
	}
	// Dimensions not mentioned at all are never enabled -- opt-in, not
	// defaulted.
	for _, dim := range []string{"ipv6_subnet", "asn", "country", "user"} {
		if _, ok := resolved.Dimensions[dim]; ok {
			t.Errorf("Dimensions[%s] = %+v, want absent (never enabled by a penalty line)", dim, resolved.Dimensions[dim])
		}
	}
}

func TestUnmarshalCaddyfile_Penalty_Bare_EnablesDefaultTuning(t *testing.T) {
	input := `fairness {
		scoring {
			penalty country
		}
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	resolved := resolveScoringConfig(h.ScoringOverrides)
	defaults := newDefaultScoringConfig()
	if !reflect.DeepEqual(resolved.Dimensions["country"], defaults.Dimensions["country"]) {
		t.Errorf("Dimensions[country] = %+v, want built-in default %+v", resolved.Dimensions["country"], defaults.Dimensions["country"])
	}
	if len(resolved.Dimensions) != 1 {
		t.Errorf("Dimensions = %+v, want exactly {country: ...}", resolved.Dimensions)
	}
}

func TestUnmarshalCaddyfile_Penalty_RepeatedLine_LastWins(t *testing.T) {
	t.Run("explicit then bare resets to default", func(t *testing.T) {
		input := `fairness {
			scoring {
				penalty ip alpha=0.9 soft=1:2 hard=3:4
				penalty ip
			}
		}`
		var h Handler
		if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
			t.Fatalf("UnmarshalCaddyfile: %v", err)
		}
		resolved := resolveScoringConfig(h.ScoringOverrides)
		defaults := newDefaultScoringConfig()
		if !reflect.DeepEqual(resolved.Dimensions["ip"], defaults.Dimensions["ip"]) {
			t.Errorf("Dimensions[ip] = %+v, want built-in default %+v (later bare line should reset the earlier override)", resolved.Dimensions["ip"], defaults.Dimensions["ip"])
		}
	})

	t.Run("bare then explicit applies override", func(t *testing.T) {
		input := `fairness {
			scoring {
				penalty ip
				penalty ip alpha=0.9 soft=1:2 hard=3:4
			}
		}`
		var h Handler
		if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
			t.Fatalf("UnmarshalCaddyfile: %v", err)
		}
		resolved := resolveScoringConfig(h.ScoringOverrides)
		want := PenaltyConfig{Alpha: 0.9, SoftThreshold: 1, SoftPenalty: 2, HardThreshold: 3, HardPenalty: 4}
		if !reflect.DeepEqual(resolved.Dimensions["ip"], want) {
			t.Errorf("Dimensions[ip] = %+v, want %+v (later explicit line should override the earlier bare enable)", resolved.Dimensions["ip"], want)
		}
	})
}

func TestUnmarshalCaddyfile_Penalty_ArgOrderIndependent(t *testing.T) {
	inputInOrder := `fairness {
		scoring {
			penalty ip alpha=0.2 soft=20:-10 hard=100:-40
		}
	}`
	inputShuffled := `fairness {
		scoring {
			penalty ip hard=100:-40 soft=20:-10 alpha=0.2
		}
	}`

	var h1, h2 Handler
	if err := h1.UnmarshalCaddyfile(caddyfile.NewTestDispenser(inputInOrder)); err != nil {
		t.Fatalf("in-order UnmarshalCaddyfile: %v", err)
	}
	if err := h2.UnmarshalCaddyfile(caddyfile.NewTestDispenser(inputShuffled)); err != nil {
		t.Fatalf("shuffled UnmarshalCaddyfile: %v", err)
	}

	r1 := resolveScoringConfig(h1.ScoringOverrides)
	r2 := resolveScoringConfig(h2.ScoringOverrides)
	if !reflect.DeepEqual(r1.Dimensions["ip"], r2.Dimensions["ip"]) {
		t.Errorf("arg order changed the resolved PenaltyConfig: in-order=%+v shuffled=%+v", r1.Dimensions["ip"], r2.Dimensions["ip"])
	}
}

func TestUnmarshalCaddyfile_Penalty_ExemptCountry_Parses(t *testing.T) {
	input := `fairness {
		scoring {
			penalty country alpha=0.2 soft=2000:10 hard=10000:40 exempt_country=PT,ES
		}
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	resolved := resolveScoringConfig(h.ScoringOverrides)
	want := map[string]bool{"PT": true, "ES": true}
	if !reflect.DeepEqual(resolved.Dimensions["country"].ExemptCountries, want) {
		t.Errorf("ExemptCountries = %#v, want %#v", resolved.Dimensions["country"].ExemptCountries, want)
	}
}

func TestUnmarshalCaddyfile_Penalty_ExemptCountry_SingleCode(t *testing.T) {
	input := `fairness {
		scoring {
			penalty asn alpha=0.2 soft=500:10 hard=2000:40 exempt_country=PT
		}
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	resolved := resolveScoringConfig(h.ScoringOverrides)
	want := map[string]bool{"PT": true}
	if !reflect.DeepEqual(resolved.Dimensions["asn"].ExemptCountries, want) {
		t.Errorf("ExemptCountries = %#v, want %#v", resolved.Dimensions["asn"].ExemptCountries, want)
	}
}

func TestUnmarshalCaddyfile_Penalty_ExemptCountry_IsPerDimension(t *testing.T) {
	input := `fairness {
		scoring {
			penalty ip      alpha=0.2 soft=20:10   hard=100:40
			penalty country alpha=0.2 soft=2000:10 hard=10000:40 exempt_country=PT
		}
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	resolved := resolveScoringConfig(h.ScoringOverrides)
	if len(resolved.Dimensions["ip"].ExemptCountries) != 0 {
		t.Errorf("ip dimension ExemptCountries = %#v, want empty — exempt_country was only configured on country", resolved.Dimensions["ip"].ExemptCountries)
	}
	if !resolved.Dimensions["country"].ExemptCountries["PT"] {
		t.Errorf("country dimension ExemptCountries = %#v, want PT present", resolved.Dimensions["country"].ExemptCountries)
	}
}

func TestUnmarshalCaddyfile_Penalty_ExemptCountry_EmptyCodeRejected(t *testing.T) {
	input := `fairness {
		scoring {
			penalty country alpha=0.2 soft=2000:10 hard=10000:40 exempt_country=PT,,ES
		}
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
		t.Fatal("expected error for exempt_country with an empty country code, got nil")
	}
}

func TestUnmarshalCaddyfile_Penalty_ExemptCountry_ArgOrderIndependent(t *testing.T) {
	inputInOrder := `fairness {
		scoring {
			penalty country alpha=0.2 soft=2000:10 hard=10000:40 exempt_country=PT,ES
		}
	}`
	inputShuffled := `fairness {
		scoring {
			penalty country exempt_country=PT,ES hard=10000:40 soft=2000:10 alpha=0.2
		}
	}`

	var h1, h2 Handler
	if err := h1.UnmarshalCaddyfile(caddyfile.NewTestDispenser(inputInOrder)); err != nil {
		t.Fatalf("in-order UnmarshalCaddyfile: %v", err)
	}
	if err := h2.UnmarshalCaddyfile(caddyfile.NewTestDispenser(inputShuffled)); err != nil {
		t.Fatalf("shuffled UnmarshalCaddyfile: %v", err)
	}

	r1 := resolveScoringConfig(h1.ScoringOverrides)
	r2 := resolveScoringConfig(h2.ScoringOverrides)
	if !reflect.DeepEqual(r1.Dimensions["country"], r2.Dimensions["country"]) {
		t.Errorf("arg order changed the resolved PenaltyConfig: in-order=%+v shuffled=%+v", r1.Dimensions["country"], r2.Dimensions["country"])
	}
}

func TestUnmarshalCaddyfile_Scoring_BadDimension(t *testing.T) {
	input := `fairness {
		scoring {
			penalty bogus alpha=0.2 soft=20:-10 hard=100:-40
		}
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
		t.Fatal("expected error for unrecognized penalty dimension, got nil")
	}
}

func TestUnmarshalCaddyfile_Scoring_MissingHard(t *testing.T) {
	input := `fairness {
		scoring {
			penalty ip alpha=0.2 soft=20:-10
		}
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
		t.Fatal("expected error for penalty missing hard=, got nil")
	}
}

func TestUnmarshalCaddyfile_Scoring_NonNumericThreshold(t *testing.T) {
	input := `fairness {
		scoring {
			penalty ip alpha=0.2 soft=abc:-10 hard=100:-40
		}
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
		t.Fatal("expected error for non-numeric soft threshold, got nil")
	}
}

func TestUnmarshalCaddyfile_Scoring_BadBaseScoreClass(t *testing.T) {
	input := `fairness {
		scoring {
			base_score bogus 100
		}
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
		t.Fatal("expected error for unrecognized base_score user class, got nil")
	}
}

func TestUnmarshalCaddyfile_Scoring_NonNumericBaseScore(t *testing.T) {
	input := `fairness {
		scoring {
			base_score researcher notanumber
		}
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
		t.Fatal("expected error for non-numeric base_score value, got nil")
	}
}

func TestUnmarshalCaddyfile_Scoring_UnrecognizedSubdirective(t *testing.T) {
	input := `fairness {
		scoring {
			not_a_real_thing 1
		}
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
		t.Fatal("expected error for unrecognized scoring subdirective, got nil")
	}
}

// --- 7. Priority divisor (§4.3) ---------------------------------------------

func TestResolveScoringConfig_DivisorOverride(t *testing.T) {
	overridden := &scoringOverrides{
		Divisors: map[string]float64{"matchType": 1.25, "timeline": 2},
	}
	resolved := resolveScoringConfig(overridden)
	if resolved.Divisors["matchType"] != 1.25 || resolved.Divisors["timeline"] != 2 {
		t.Errorf("Divisors = %+v, want {matchType:1.25, timeline:2}", resolved.Divisors)
	}
	// Divisors are independent of dimension enablement.
	if len(resolved.Dimensions) != 0 {
		t.Errorf("Dimensions = %+v, want empty (no penalty lines given)", resolved.Dimensions)
	}
}

func TestResolveScoringConfig_NoScoringBlockHasEmptyDivisors(t *testing.T) {
	resolved := resolveScoringConfig(nil)
	if len(resolved.Divisors) != 0 {
		t.Errorf("Divisors = %+v, want empty (no scoring{} block at all)", resolved.Divisors)
	}
}

func TestPriorityDivisor_NoConfiguredDivisors_IsNoOp(t *testing.T) {
	s := newScoringState(resolveScoringConfig(nil), time.Second, time.Hour)
	got := s.priorityDivisor(map[string][]string{"matchType": {"prefix"}})
	if got != 1 {
		t.Errorf("priorityDivisor = %v, want 1 (no divisors configured)", got)
	}
}

func TestPriorityDivisor_AbsentParam_IsNoOp(t *testing.T) {
	cfg := resolveScoringConfig(&scoringOverrides{Divisors: map[string]float64{"matchType": 1.25}})
	s := newScoringState(cfg, time.Second, time.Hour)
	got := s.priorityDivisor(map[string][]string{"other": {"x"}})
	if got != 1 {
		t.Errorf("priorityDivisor = %v, want 1 (configured param not present in query)", got)
	}
}

func TestPriorityDivisor_PresentParam_AppliesConfiguredValue(t *testing.T) {
	cfg := resolveScoringConfig(&scoringOverrides{Divisors: map[string]float64{"matchType": 1.25}})
	s := newScoringState(cfg, time.Second, time.Hour)
	got := s.priorityDivisor(map[string][]string{"matchType": {"prefix"}})
	if got != 1.25 {
		t.Errorf("priorityDivisor = %v, want 1.25", got)
	}
}

func TestPriorityDivisor_MultiplePresentParams_StackMultiplicatively(t *testing.T) {
	cfg := resolveScoringConfig(&scoringOverrides{
		Divisors: map[string]float64{"matchType": 1.25, "timeline": 2, "yearBalance": 1.5},
	})
	s := newScoringState(cfg, time.Second, time.Hour)
	got := s.priorityDivisor(map[string][]string{
		"matchType": {"prefix"},
		"timeline":  {"1"},
		"unrelated": {"x"},
	})
	want := 1.25 * 2.0
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("priorityDivisor = %v, want %v (matchType * timeline, yearBalance absent)", got, want)
	}
}

// priorityDivisor's presence-based contract: divisors are keyed only on
// whether a param name is present in query, never on its value — an empty
// string value must still count as present.
func TestPriorityDivisor_PresenceOnly_ValueIsIgnored(t *testing.T) {
	cfg := resolveScoringConfig(&scoringOverrides{Divisors: map[string]float64{"matchType": 1.25}})
	s := newScoringState(cfg, time.Second, time.Hour)
	got := s.priorityDivisor(map[string][]string{"matchType": {""}})
	if got != 1.25 {
		t.Errorf("priorityDivisor = %v, want 1.25 (presence alone, regardless of value)", got)
	}
}

func TestPriorityDivisor_NilScoringState_IsNoOp(t *testing.T) {
	var s *scoringState
	got := s.priorityDivisor(map[string][]string{"matchType": {"prefix"}})
	if got != 1 {
		t.Errorf("priorityDivisor on nil state = %v, want 1", got)
	}
}

func TestUnmarshalCaddyfile_Divisor_RoundTrips(t *testing.T) {
	input := `fairness {
		scoring {
			divisor param matchType 1.25
			divisor param timeline 2
		}
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	resolved := resolveScoringConfig(h.ScoringOverrides)
	if resolved.Divisors["matchType"] != 1.25 || resolved.Divisors["timeline"] != 2 {
		t.Errorf("Divisors = %+v, want {matchType:1.25, timeline:2}", resolved.Divisors)
	}
}

func TestUnmarshalCaddyfile_Divisor_MissingParamKeyword(t *testing.T) {
	input := `fairness {
		scoring {
			divisor matchType 1.25
		}
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
		t.Fatal("expected error for divisor line missing 'param' keyword, got nil")
	}
}

func TestUnmarshalCaddyfile_Divisor_WrongArgCount(t *testing.T) {
	input := `fairness {
		scoring {
			divisor param matchType
		}
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
		t.Fatal("expected error for divisor line with too few args, got nil")
	}
}

func TestUnmarshalCaddyfile_Divisor_NonNumericValue(t *testing.T) {
	input := `fairness {
		scoring {
			divisor param matchType notanumber
		}
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
		t.Fatal("expected error for non-numeric divisor value, got nil")
	}
}

func TestUnmarshalCaddyfile_Divisor_NonPositiveValueRejected(t *testing.T) {
	for _, v := range []string{"0", "-1.5"} {
		input := `fairness {
			scoring {
				divisor param matchType ` + v + `
			}
		}`
		var h Handler
		if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
			t.Fatalf("divisor value %q: expected error (must be > 0), got nil", v)
		}
	}
}

func TestHandler_ServeHTTP_AppliesDivisorWhenQueryParamPresent(t *testing.T) {
	h := Handler{
		ScoringOverrides: &scoringOverrides{
			Divisors: map[string]float64{"matchType": 2},
		},
	}
	h.scoring = newScoringState(resolveScoringConfig(h.ScoringOverrides), time.Second, time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/?matchType=prefix", nil)
	req.RemoteAddr = "203.0.113.5:1234"
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{})
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })

	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	v := caddyhttp.GetVar(req.Context(), fairnessScoreVarKey)
	score, ok := v.(float64)
	if !ok {
		t.Fatalf("fairness_score var = %#v, want float64", v)
	}
	base := newDefaultScoringConfig().BaseScores[UserClassAnonymous]
	want := base / 2
	if score != want {
		t.Errorf("fairness_score = %v, want %v (base %v / divisor 2)", score, want, base)
	}
}

func TestHandler_ServeHTTP_NoDivisorWhenQueryParamAbsent(t *testing.T) {
	h := Handler{
		ScoringOverrides: &scoringOverrides{
			Divisors: map[string]float64{"matchType": 2},
		},
	}
	h.scoring = newScoringState(resolveScoringConfig(h.ScoringOverrides), time.Second, time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:1234"
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{})
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })

	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	v := caddyhttp.GetVar(req.Context(), fairnessScoreVarKey)
	score := v.(float64)
	base := newDefaultScoringConfig().BaseScores[UserClassAnonymous]
	if score != base {
		t.Errorf("fairness_score = %v, want unpenalized/undivided base score %v", score, base)
	}
}
