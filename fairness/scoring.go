// Package fairness — EWMA-based scoring/penalties (REQUIREMENTS.md §3.2,
// §4.3). Per-entity statistics are aggregated (not raw request logs): a
// fixed-size struct per tracked entity, one map per dimension, updated on a
// fixed tick. This state lives per Handler instance (§7 Q6, decided:
// isolated per backend, never on the App module) and is reinitialized fresh
// on every Provision (§3.3 — config reload resets it, by design).
package fairness

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
)

// scoringDimensions is the fixed, ordered set of dimensions scoring tracks
// (§3.2/§4.3). Order doesn't affect correctness (each dimension's map is
// independent) but keeps tick/gc iteration deterministic for tests/logging.
var scoringDimensions = [...]string{"ip", "net24", "net6", "asn", "country", "user"}

// validScoringDimensions is scoringDimensions as a lookup set, for Caddyfile
// validation.
var validScoringDimensions = map[string]bool{
	"ip": true, "net24": true, "net6": true, "asn": true, "country": true, "user": true,
}

// validUserClasses are the 5 user classes base_score may legitimately be
// configured for (unlike validClaimedUserClasses in classify.go, this
// includes anonymous/unknown since a Caddyfile author configures base scores
// for all identity outcomes, not just JWT-claimed ones).
var validUserClasses = map[UserClass]bool{
	UserClassAnonymous:      true,
	UserClassResearcher:     true,
	UserClassServiceAccount: true,
	UserClassInternal:       true,
	UserClassUnknown:        true,
}

// Scoring-specific defaults (§4.3/§3.2). EWMATickInterval/IdleEntryTTL zero
// values in Config fall back to these via Config's ewmaTickInterval() /
// idleEntryTTL() helpers below.
const (
	defaultEWMATickInterval = 1 * time.Second
	defaultIdleEntryTTL     = 10 * time.Minute
	// gcSweepInterval is how often the idle-entry GC ticker runs. Fixed,
	// not independently Caddyfile-configurable per §3.2/task spec — only
	// the idle_entry_ttl threshold is.
	gcSweepInterval = 1 * time.Minute
)

// ewmaTickInterval returns the configured EWMA tick interval, or the default
// if unset/non-positive. Safe to call on a nil *Config.
func (c *Config) ewmaTickInterval() time.Duration {
	if c == nil || c.EWMATickInterval <= 0 {
		return defaultEWMATickInterval
	}
	return c.EWMATickInterval
}

// idleEntryTTL returns the configured idle-entry TTL, or the default if
// unset/non-positive. Safe to call on a nil *Config.
func (c *Config) idleEntryTTL() time.Duration {
	if c == nil || c.IdleEntryTTL <= 0 {
		return defaultIdleEntryTTL
	}
	return c.IdleEntryTTL
}

// ClientStats is the per-entity aggregated statistic tracked per dimension
// (§3.2). LastSeen and EWMARPS are read-only from Phase 10's eventual admin
// API; Inflight is carried for that same future surface but not touched by
// this phase (adaptive_admission owns concurrency tracking, per §3.1/§4.4).
type ClientStats struct {
	LastSeen time.Time
	EWMARPS  float64
	Inflight int

	// pending counts requests seen since the last completed EWMA tick. Reset
	// to 0 by tick(). Unexported: it's an implementation detail of the
	// fixed-tick counting mechanism, not part of the documented shape.
	pending int
}

// dimensionMap is one dimension's tracked-entity map, guarded by its own
// mutex. Per §3.2, plain per-dimension locking is intentional here — sharded
// mutexes or sync.Map are explicitly deferred until profiling shows this is
// a bottleneck.
type dimensionMap struct {
	mu      sync.Mutex
	entries map[string]*ClientStats
}

// PenaltyConfig is one dimension's EWMA-threshold-to-penalty tuning (§4.3).
// SoftPenalty/HardPenalty are stored as positive magnitudes: the Caddyfile
// grammar writes them as a negative delta (e.g. soft=20:-10) since that
// reads naturally as "a penalty", but internally we always store and sum
// positive magnitudes and subtract the total from the base score
// (final = base - total_penalty) — never a signed accumulator — so this
// file's arithmetic never has to branch on sign.
type PenaltyConfig struct {
	Alpha         float64
	SoftThreshold float64
	SoftPenalty   float64
	HardThreshold float64
	HardPenalty   float64
}

// ScoringConfig is a fairness handler's fully-resolved scoring configuration
// (§4.3): base scores per user class, the score clamp range, and per-
// dimension penalty tuning. §5's config surface is explicitly "illustrative
// only" — see newDefaultScoringConfig for the chosen illustrative defaults.
type ScoringConfig struct {
	BaseScores map[UserClass]float64
	MinScore   float64
	MaxScore   float64
	Dimensions map[string]PenaltyConfig
}

// newDefaultScoringConfig returns a brand-new ScoringConfig with fresh maps
// on every call — deliberately never a shared package-level mutable var —
// so overlaying per-Handler overrides (resolveScoringConfig) can never alias
// another Handler's resolved config, by construction rather than by
// discipline (the Python source's aliasing footgun, per §4.3).
//
// Defaults chosen (documented per the task's "illustrative only" allowance):
//   - BaseScores: researcher/service_account/internal get full trust (100);
//     anonymous gets a lower base (60, matching §5's example); unknown (a
//     present-but-unverifiable token) gets the same base as anonymous, since
//     it shouldn't be trusted *less* than having no token at all, nor
//     rejected outright — scoring/penalties do the rest.
//   - MinScore/MaxScore: 0/100.
//   - Per-dimension alpha/soft/hard, roughly scaled by how many distinct
//     requesters typically share that bucket: ip/user (single entity) use
//     the §5 example's exact ip values; net24/net6 (subnet aggregate) and
//     asn/country (progressively larger aggregates) get proportionally
//     higher thresholds so legitimate aggregated traffic isn't penalized as
//     eagerly as a single misbehaving IP.
func newDefaultScoringConfig() ScoringConfig {
	return ScoringConfig{
		BaseScores: map[UserClass]float64{
			UserClassResearcher:     100,
			UserClassServiceAccount: 100,
			UserClassInternal:       100,
			UserClassAnonymous:      60,
			UserClassUnknown:        60,
		},
		MinScore: 0,
		MaxScore: 100,
		Dimensions: map[string]PenaltyConfig{
			"ip":      {Alpha: 0.2, SoftThreshold: 20, SoftPenalty: 10, HardThreshold: 100, HardPenalty: 40},
			"user":    {Alpha: 0.2, SoftThreshold: 20, SoftPenalty: 10, HardThreshold: 100, HardPenalty: 40},
			"net24":   {Alpha: 0.2, SoftThreshold: 100, SoftPenalty: 10, HardThreshold: 500, HardPenalty: 40},
			"net6":    {Alpha: 0.2, SoftThreshold: 100, SoftPenalty: 10, HardThreshold: 500, HardPenalty: 40},
			"asn":     {Alpha: 0.2, SoftThreshold: 500, SoftPenalty: 10, HardThreshold: 2000, HardPenalty: 40},
			"country": {Alpha: 0.2, SoftThreshold: 2000, SoftPenalty: 10, HardThreshold: 10000, HardPenalty: 40},
		},
	}
}

// scoringOverrides holds only the fields a `scoring { }` Caddyfile sub-block
// actually specified (§4.3/§5's "backend-level overrides deep-merge onto
// global defaults per dimension"). Nil/zero-value fields mean "not
// specified, use the default" — resolveScoringConfig overlays these onto
// newDefaultScoringConfig() rather than replacing it wholesale.
type scoringOverrides struct {
	baseScores map[UserClass]float64
	penalties  map[string]PenaltyConfig
	minScore   *float64
	maxScore   *float64
}

// resolveScoringConfig starts from a fresh newDefaultScoringConfig() and
// overlays only what o explicitly specifies. Because PenaltyConfig and the
// BaseScores values are plain value types, and the base config's maps are
// freshly allocated per call, overlaying here can never cause one Handler's
// resolved config to alias another's (§4.3's aliasing-safety requirement).
// o may be nil (no scoring{} block at all): returns pure defaults.
func resolveScoringConfig(o *scoringOverrides) ScoringConfig {
	cfg := newDefaultScoringConfig()
	if o == nil {
		return cfg
	}
	for uc, v := range o.baseScores {
		cfg.BaseScores[uc] = v
	}
	for dim, pc := range o.penalties {
		cfg.Dimensions[dim] = pc
	}
	if o.minScore != nil {
		cfg.MinScore = *o.minScore
	}
	if o.maxScore != nil {
		cfg.MaxScore = *o.maxScore
	}
	return cfg
}

// baseScoreFor returns baseScores[uc], falling back to
// baseScores[UserClassAnonymous] if uc isn't a recognized key (§4.3
// fail-open: a Caddyfile override could in principle add/remove classes; an
// unrecognized class should never error or fall back to 0/rejection). If
// even the anonymous fallback is missing (a pathological override), returns
// 0 as the last resort.
func baseScoreFor(baseScores map[UserClass]float64, uc UserClass) float64 {
	if v, ok := baseScores[uc]; ok {
		return v
	}
	if v, ok := baseScores[UserClassAnonymous]; ok {
		return v
	}
	return 0
}

// clamp restricts v to [min, max].
func clamp(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// dimensionKey derives the tracked-entity key for dim from a Classification,
// or ok=false if that dimension doesn't apply to this request (§1 of the
// task spec: e.g. net24 for an IPv6 request, asn/country/user when
// unavailable/anonymous).
func dimensionKey(dim string, c Classification) (key string, ok bool) {
	switch dim {
	case "ip":
		if c.IP == "" {
			return "", false
		}
		return c.IP, true
	case "net24":
		if c.Net24 == "" {
			return "", false
		}
		return c.Net24, true
	case "net6":
		if c.NetV6 == "" {
			return "", false
		}
		return c.NetV6, true
	case "asn":
		if c.ASN == 0 {
			return "", false
		}
		return strconv.FormatUint(uint64(c.ASN), 10), true
	case "country":
		if c.Country == "" {
			return "", false
		}
		return c.Country, true
	case "user":
		if c.UserID == "" {
			return "", false
		}
		return c.UserID, true
	default:
		return "", false
	}
}

// penaltyContribution evaluates rps (a dimension's current EWMARPS) against
// pc's thresholds. Boundary is exclusive (>, not >=) on both thresholds,
// matching REQUIREMENTS.md §4.3's pseudocode literally: EWMARPS ==
// SoftThreshold exactly contributes 0 (not yet "soft"), and EWMARPS ==
// HardThreshold exactly contributes SoftPenalty (not yet "hard") — a request
// must exceed a threshold, not merely reach it, to accrue that tier's
// penalty.
func penaltyContribution(pc PenaltyConfig, rps float64) float64 {
	switch {
	case rps > pc.HardThreshold:
		return pc.HardPenalty
	case rps > pc.SoftThreshold:
		return pc.SoftPenalty
	default:
		return 0
	}
}

// scoringState is the per-Handler-instance EWMA scoring state (§3.2/§7 Q6):
// one map per dimension, a fixed-tick EWMA updater, and an idle-entry GC
// sweep, all driven by two background goroutines started in Provision and
// stopped in Cleanup (§3.3 — a config reload's old Handler instance must
// actually stop these or they leak).
type scoringState struct {
	cfg  ScoringConfig
	dims map[string]*dimensionMap

	tickInterval time.Duration
	idleTTL      time.Duration

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// newScoringState builds a fresh scoringState: empty per-dimension maps,
// resolved cfg, and tick/idle intervals (already defaulted by the caller via
// Config.ewmaTickInterval()/idleEntryTTL()). It does not start the
// background goroutines — call start() separately once fully constructed.
func newScoringState(cfg ScoringConfig, tickInterval, idleTTL time.Duration) *scoringState {
	if tickInterval <= 0 {
		tickInterval = defaultEWMATickInterval
	}
	if idleTTL <= 0 {
		idleTTL = defaultIdleEntryTTL
	}
	dims := make(map[string]*dimensionMap, len(scoringDimensions))
	for _, d := range scoringDimensions {
		dims[d] = &dimensionMap{entries: make(map[string]*ClientStats)}
	}
	return &scoringState{
		cfg:          cfg,
		dims:         dims,
		tickInterval: tickInterval,
		idleTTL:      idleTTL,
		stopCh:       make(chan struct{}),
	}
}

// start launches the EWMA-tick and idle-entry-GC background goroutines.
// Nil-safe (no-op on a nil *scoringState) so callers don't need to guard.
func (s *scoringState) start() {
	if s == nil {
		return
	}
	s.wg.Add(2)
	go s.runEWMATicker()
	go s.runGCTicker()
}

func (s *scoringState) runEWMATicker() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case now := <-ticker.C:
			s.tick(now)
		}
	}
}

func (s *scoringState) runGCTicker() {
	defer s.wg.Done()
	ticker := time.NewTicker(gcSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case now := <-ticker.C:
			s.gc(now)
		}
	}
}

// stop signals both background goroutines to exit and waits for them to
// finish. Safe to call multiple times and nil-safe (no-op on a nil
// *scoringState, e.g. a Handler that was never Provisioned).
func (s *scoringState) stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
	s.wg.Wait()
}

// track records one request against every applicable dimension derived from
// c: get-or-create that dimension's entry, set LastSeen=now, increment its
// pending-tick counter. Nil-safe (no-op on a nil *scoringState) so
// ServeHTTP can call it unconditionally even if Provision was never run.
func (s *scoringState) track(c Classification, now time.Time) {
	if s == nil {
		return
	}
	for _, dim := range scoringDimensions {
		key, ok := dimensionKey(dim, c)
		if !ok {
			continue
		}
		dm := s.dims[dim]
		dm.mu.Lock()
		entry, exists := dm.entries[key]
		if !exists {
			entry = &ClientStats{}
			dm.entries[key] = entry
		}
		entry.LastSeen = now
		entry.pending++
		dm.mu.Unlock()
	}
}

// tick runs one EWMA update pass over every dimension's every tracked
// entity (§4.3):
//
//	requests_in_last_tick := swap-and-reset the entity's pending counter
//	rate := float64(requests_in_last_tick) / tickInterval.Seconds()
//	entity.EWMARPS = alpha*rate + (1-alpha)*entity.EWMARPS
//
// alpha is that dimension's configured PenaltyConfig.Alpha, not global.
// Exported as a method taking "now" implicitly unused (the tick doesn't need
// wall-clock time, only the elapsed-tick-interval assumption) so it can be
// invoked directly by tests without waiting on the real ticker.
func (s *scoringState) tick(_ time.Time) {
	if s == nil {
		return
	}
	seconds := s.tickInterval.Seconds()
	for _, dim := range scoringDimensions {
		alpha := s.cfg.Dimensions[dim].Alpha
		dm := s.dims[dim]
		dm.mu.Lock()
		for _, entry := range dm.entries {
			count := entry.pending
			entry.pending = 0
			rate := float64(count) / seconds
			entry.EWMARPS = alpha*rate + (1-alpha)*entry.EWMARPS
		}
		dm.mu.Unlock()
	}
}

// gc sweeps every dimension's map and deletes entries idle longer than
// idleTTL as of now (§3.2). A plain method taking "now" explicitly so tests
// can drive it with a controlled clock instead of sleeping for real.
func (s *scoringState) gc(now time.Time) {
	if s == nil {
		return
	}
	for _, dim := range scoringDimensions {
		dm := s.dims[dim]
		dm.mu.Lock()
		for key, entry := range dm.entries {
			if now.Sub(entry.LastSeen) > s.idleTTL {
				delete(dm.entries, key)
			}
		}
		dm.mu.Unlock()
	}
}

// entryEWMARPS returns the current EWMARPS for dim/key, or 0 if untracked.
// Test/introspection helper (Phase 10's admin API will eventually want
// exactly this per-entity read).
func (s *scoringState) entryEWMARPS(dim, key string) float64 {
	if s == nil {
		return 0
	}
	dm, ok := s.dims[dim]
	if !ok {
		return 0
	}
	dm.mu.Lock()
	defer dm.mu.Unlock()
	if entry, ok := dm.entries[key]; ok {
		return entry.EWMARPS
	}
	return 0
}

// resolvedConfig returns this instance's fully-resolved ScoringConfig, for
// admin introspection (admin.go, §4.10). Safe to call on a nil
// *scoringState (returns fresh defaults). The returned value's maps are the
// live ones held by s — callers must treat them as read-only (they're
// marshaled to JSON immediately, never mutated).
func (s *scoringState) resolvedConfig() ScoringConfig {
	if s == nil {
		return newDefaultScoringConfig()
	}
	return s.cfg
}

// entryCounts returns the number of tracked entities per dimension, for
// admin introspection (admin.go, §4.10) — a size, not the per-entity
// EWMARPS values themselves (see entryEWMARPS for that finer-grained read).
// Safe to call on a nil *scoringState (returns zero counts for every
// dimension).
func (s *scoringState) entryCounts() map[string]int {
	counts := make(map[string]int, len(scoringDimensions))
	for _, dim := range scoringDimensions {
		counts[dim] = 0
	}
	if s == nil {
		return counts
	}
	for _, dim := range scoringDimensions {
		dm := s.dims[dim]
		dm.mu.Lock()
		counts[dim] = len(dm.entries)
		dm.mu.Unlock()
	}
	return counts
}

// computeScore computes the final fairness score for a classified request
// (§4.3). It's a thin wrapper around computeScoreBreakdown that discards the
// per-dimension detail — see that method for the full contract (fail-open
// behavior, exempt-country handling, etc.).
func (s *scoringState) computeScore(c Classification, exemptCountries map[string]bool) float64 {
	score, _ := s.computeScoreBreakdown(c, exemptCountries)
	return score
}

// computeScoreBreakdown computes the final fairness score for a classified
// request (§4.3): final = clamp(base_score[user_class] - total_penalty, min,
// max). Each dimension contributes independently based on its *current*
// EWMARPS (as of the last completed tick — this does not compute a "live"
// EWMA mid-tick, per the task spec). A dimension the request doesn't apply to
// (dimensionKey ok=false) contributes 0. The country dimension is still
// tracked/read normally when exempt, but its penalty is always excluded from
// the sum regardless of its EWMARPS (§4.3 exempt-country behavior).
//
// The returned map (for §4.9's structured logging, via module.go) carries
// "base", "penalty_<dimension>" (only for dimensions that actually
// contributed a non-zero penalty), "total_penalty", and "final" — enough to
// reconstruct exactly how the score was derived without re-running this
// method.
//
// Fail-open (§4.3): a nil *scoringState (e.g. a Handler used without
// Provision, as in some unit tests) returns the class's base score from
// hardcoded defaults with zero penalty, never panics.
func (s *scoringState) computeScoreBreakdown(c Classification, exemptCountries map[string]bool) (float64, map[string]float64) {
	if s == nil {
		defaults := newDefaultScoringConfig()
		base := baseScoreFor(defaults.BaseScores, c.UserClass)
		return base, map[string]float64{"base": base, "total_penalty": 0, "final": base}
	}

	base := baseScoreFor(s.cfg.BaseScores, c.UserClass)
	var totalPenalty float64
	breakdown := map[string]float64{"base": base}

	for _, dim := range scoringDimensions {
		key, ok := dimensionKey(dim, c)
		if !ok {
			continue
		}
		if dim == "country" && exemptCountries[c.Country] {
			// Exempt: still tracked (observability) but never penalized.
			continue
		}
		pc, ok := s.cfg.Dimensions[dim]
		if !ok {
			continue
		}
		rps := s.entryEWMARPS(dim, key)
		penalty := penaltyContribution(pc, rps)
		if penalty != 0 {
			breakdown["penalty_"+dim] = penalty
			totalPenalty += penalty
		}
	}

	final := clamp(base-totalPenalty, s.cfg.MinScore, s.cfg.MaxScore)
	breakdown["total_penalty"] = totalPenalty
	breakdown["final"] = final
	return final, breakdown
}

// parsePenaltyArgs parses the space-separated key=value tokens following
// `penalty <dimension>` (alpha=<float>, soft=<float>:<float>,
// hard=<float>:<float>), in any order — all three required. See
// PenaltyConfig's doc comment for the soft/hard penalty sign convention.
func parsePenaltyArgs(args []string) (PenaltyConfig, error) {
	var pc PenaltyConfig
	var haveAlpha, haveSoft, haveHard bool

	for _, arg := range args {
		key, val, ok := strings.Cut(arg, "=")
		if !ok {
			return pc, fmt.Errorf("expected key=value token, got %q", arg)
		}
		switch key {
		case "alpha":
			f, err := strconv.ParseFloat(val, 64)
			if err != nil {
				return pc, fmt.Errorf("invalid alpha %q: %w", val, err)
			}
			pc.Alpha = f
			haveAlpha = true

		case "soft":
			thr, pen, err := parseThresholdPenalty(val)
			if err != nil {
				return pc, fmt.Errorf("invalid soft %q: %w", val, err)
			}
			pc.SoftThreshold, pc.SoftPenalty = thr, pen
			haveSoft = true

		case "hard":
			thr, pen, err := parseThresholdPenalty(val)
			if err != nil {
				return pc, fmt.Errorf("invalid hard %q: %w", val, err)
			}
			pc.HardThreshold, pc.HardPenalty = thr, pen
			haveHard = true

		default:
			return pc, fmt.Errorf("unrecognized penalty key %q", key)
		}
	}

	if !haveAlpha || !haveSoft || !haveHard {
		return pc, fmt.Errorf("penalty requires alpha=, soft=, and hard= (all three required), got %q", strings.Join(args, " "))
	}
	return pc, nil
}

// parseThresholdPenalty parses a "threshold:penalty" token (e.g. "20:-10")
// into its two float64 components. The penalty component's sign is
// normalized to a positive magnitude here (see PenaltyConfig's doc comment).
func parseThresholdPenalty(val string) (threshold, penalty float64, err error) {
	parts := strings.SplitN(val, ":", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("expected threshold:penalty, got %q", val)
	}
	threshold, err = strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid threshold %q: %w", parts[0], err)
	}
	rawPenalty, err := strconv.ParseFloat(parts[1], 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid penalty %q: %w", parts[1], err)
	}
	penalty = math.Abs(rawPenalty)
	return threshold, penalty, nil
}
