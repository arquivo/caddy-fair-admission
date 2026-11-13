package fairness

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// writeSessionKey writes a valid (>= 32 byte) secret, with a trailing
// newline as an editor would leave it, and returns its path.
func writeSessionKey(t *testing.T, secret string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

const (
	testSecret1 = "0123456789abcdef0123456789abcdef-k1"
	testSecret2 = "fedcba9876543210fedcba9876543210-k2"
)

// fixedClock returns a now func pinned to *at, so a test can advance time.
func fixedClock(at *time.Time) func() time.Time {
	return func() time.Time { return *at }
}

func mustSessionCookies(t *testing.T, cfg *SessionCookieConfig, now *time.Time) *sessionCookies {
	t.Helper()
	sc, err := newSessionCookies(cfg)
	if err != nil {
		t.Fatalf("newSessionCookies: %v", err)
	}
	sc.now = fixedClock(now)
	return sc
}

func TestSessionCookies_SignVerify_RoundTrip(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	sc := mustSessionCookies(t, &SessionCookieConfig{Keys: []SessionKey{{"k1", writeSessionKey(t, testSecret1)}}}, &now)

	value := sc.sign("abc", now.Add(time.Minute))
	got := sc.verify(value)
	if got.result != sessionValid || got.id != "abc" || got.kid != "k1" || !got.expiry.Equal(now.Add(time.Minute)) {
		t.Fatalf("verify = %+v, want valid abc/k1", got)
	}
	if !strings.HasPrefix(value, "v1.k1.") {
		t.Errorf("value = %q, want v1.k1.<expiry>.<id>.<mac>", value)
	}
}

func TestSessionCookies_Verify_RejectsTampering(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	sc := mustSessionCookies(t, &SessionCookieConfig{Keys: []SessionKey{{"k1", writeSessionKey(t, testSecret1)}}}, &now)
	good := sc.sign("abc", now.Add(time.Minute))
	parts := strings.Split(good, ".")

	cases := map[string]string{
		"empty":           "",
		"garbage":         "not-a-cookie",
		"too many parts":  good + ".x",
		"wrong version":   "v2" + good[2:],
		"unknown kid":     strings.Join([]string{parts[0], "nope", parts[2], parts[3], parts[4]}, "."),
		"extended expiry": strings.Join([]string{parts[0], parts[1], "9999999999", parts[3], parts[4]}, "."),
		"swapped id":      strings.Join([]string{parts[0], parts[1], parts[2], "xyz", parts[4]}, "."),
		"bad mac":         strings.Join([]string{parts[0], parts[1], parts[2], parts[3], "AAAA"}, "."),
		"empty id":        sc.sign("", now.Add(time.Minute)),
		"oversized":       good + strings.Repeat("A", maxSessionCookieLen),
	}
	for name, v := range cases {
		if got := sc.verify(v); got.result != sessionInvalid {
			t.Errorf("%s: verify(%q).result = %q, want invalid", name, v, got.result)
		}
	}
}

func TestSessionCookies_Verify_Expired(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	sc := mustSessionCookies(t, &SessionCookieConfig{Keys: []SessionKey{{"k1", writeSessionKey(t, testSecret1)}}}, &now)
	value := sc.sign("abc", now.Add(time.Minute))

	now = now.Add(time.Minute) // exactly at expiry: no longer valid
	if got := sc.verify(value); got.result != sessionExpired {
		t.Errorf("at expiry: result = %q, want expired", got.result)
	}
}

func TestSessionCookies_MultipleInstancesShareKeyFile(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	keyFile := writeSessionKey(t, testSecret1)
	issuer := mustSessionCookies(t, &SessionCookieConfig{Mode: "issue", Keys: []SessionKey{{"k1", keyFile}}}, &now)
	checker := mustSessionCookies(t, &SessionCookieConfig{Mode: "check", Keys: []SessionKey{{"k1", keyFile}}}, &now)

	if got := checker.verify(issuer.sign("abc", now.Add(time.Minute))); got.result != sessionValid {
		t.Errorf("cookie issued by another instance: result = %q, want valid", got.result)
	}
}

func TestSessionCookies_KeyRotation(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	k1 := writeSessionKey(t, testSecret1)
	k2 := writeSessionKey(t, testSecret2)

	old := mustSessionCookies(t, &SessionCookieConfig{Keys: []SessionKey{{"k1", k1}}}, &now)
	rotating := mustSessionCookies(t, &SessionCookieConfig{Keys: []SessionKey{{"k2", k2}, {"k1", k1}}}, &now)
	rotated := mustSessionCookies(t, &SessionCookieConfig{Keys: []SessionKey{{"k2", k2}}}, &now)

	oldCookie := old.sign("abc", now.Add(time.Minute))
	if got := rotating.verify(oldCookie); got.result != sessionValid {
		t.Errorf("k1 cookie during rotation: result = %q, want valid", got.result)
	}
	if got := rotated.verify(oldCookie); got.result != sessionInvalid {
		t.Errorf("k1 cookie after k1 was dropped: result = %q, want invalid", got.result)
	}
	newCookie := rotating.sign("abc", now.Add(time.Minute))
	if !strings.HasPrefix(newCookie, "v1.k2.") {
		t.Errorf("rotating instance signed %q, want the first-listed key k2", newCookie)
	}
	if got := rotated.verify(newCookie); got.result != sessionValid {
		t.Errorf("k2 cookie after rotation: result = %q, want valid", got.result)
	}
}

func TestNewSessionCookies_Errors(t *testing.T) {
	good := writeSessionKey(t, testSecret1)
	short := writeSessionKey(t, "too-short")
	cases := map[string]*SessionCookieConfig{
		"no keys":      {},
		"missing file": {Keys: []SessionKey{{"k1", filepath.Join(t.TempDir(), "absent")}}},
		"short key":    {Keys: []SessionKey{{"k1", short}}},
		"dup kid":      {Keys: []SessionKey{{"k1", good}, {"k1", good}}},
		"bad kid":      {Keys: []SessionKey{{"k.1", good}}},
		"bad mode":     {Mode: "sometimes", Keys: []SessionKey{{"k1", good}}},
	}
	for name, cfg := range cases {
		if _, err := newSessionCookies(cfg); err == nil {
			t.Errorf("%s: newSessionCookies succeeded, want error", name)
		}
	}
}

func TestNewSessionCookies_DefaultsAndTrimming(t *testing.T) {
	sc, err := newSessionCookies(&SessionCookieConfig{Keys: []SessionKey{{"k1", writeSessionKey(t, "  "+testSecret1+"  ")}}})
	if err != nil {
		t.Fatalf("newSessionCookies: %v", err)
	}
	if sc.name != "aac_session" || sc.ttl != 30*time.Minute || !sc.check || sc.issue {
		t.Errorf("defaults = name %q ttl %v check %v issue %v, want aac_session/30m/check-only", sc.name, sc.ttl, sc.check, sc.issue)
	}
	if string(sc.keys["k1"]) != testSecret1 {
		t.Errorf("key = %q, want surrounding whitespace trimmed", sc.keys["k1"])
	}
}

func issuedCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie count = %d, want 1 (%v)", len(cookies), rec.Header().Values("Set-Cookie"))
	}
	return cookies[0]
}

func TestSessionCookies_MaybeIssue(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	k1 := writeSessionKey(t, testSecret1)
	k2 := writeSessionKey(t, testSecret2)
	sc := mustSessionCookies(t, &SessionCookieConfig{Mode: "issue", TTL: 10 * time.Minute, Keys: []SessionKey{{"k2", k2}, {"k1", k1}}}, &now)
	sc.rand = bytes.NewReader(bytes.Repeat([]byte{0x42}, 64))

	t.Run("absent issues a new session with mandatory attributes", func(t *testing.T) {
		rec := httptest.NewRecorder()
		if got := sc.maybeIssue(rec, sessionRead{result: sessionAbsent}); got != sessionIssued {
			t.Fatalf("action = %q, want issued", got)
		}
		c := issuedCookie(t, rec)
		if c.Name != "aac_session" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" || c.MaxAge != 600 {
			t.Errorf("cookie = %+v, want aac_session; Secure; HttpOnly; SameSite=Lax; Path=/; no Domain; Max-Age=600", c)
		}
		if got := sc.verify(c.Value); got.result != sessionValid || got.kid != "k2" {
			t.Errorf("issued cookie verifies as %+v, want valid/k2", got)
		}
	})

	t.Run("fresh valid cookie is not re-sent", func(t *testing.T) {
		rec := httptest.NewRecorder()
		s := sc.verify(sc.sign("abc", now.Add(6*time.Minute)))
		if got := sc.maybeIssue(rec, s); got != "" || len(rec.Header().Values("Set-Cookie")) != 0 {
			t.Errorf("action = %q, Set-Cookie = %v, want none", got, rec.Header().Values("Set-Cookie"))
		}
	})

	t.Run("valid cookie past half its TTL is renewed with the same id", func(t *testing.T) {
		rec := httptest.NewRecorder()
		s := sc.verify(sc.sign("abc", now.Add(4*time.Minute)))
		if got := sc.maybeIssue(rec, s); got != sessionRenewed {
			t.Fatalf("action = %q, want renewed", got)
		}
		r := sc.verify(issuedCookie(t, rec).Value)
		if r.id != "abc" || !r.expiry.Equal(now.Add(10*time.Minute)) {
			t.Errorf("renewed cookie = %+v, want id abc with a fresh full TTL", r)
		}
	})

	t.Run("cookie signed with a non-signing key is re-signed", func(t *testing.T) {
		old := mustSessionCookies(t, &SessionCookieConfig{Keys: []SessionKey{{"k1", k1}}}, &now)
		rec := httptest.NewRecorder()
		s := sc.verify(old.sign("abc", now.Add(9*time.Minute)))
		if got := sc.maybeIssue(rec, s); got != sessionRenewed {
			t.Fatalf("action = %q, want renewed", got)
		}
		if r := sc.verify(issuedCookie(t, rec).Value); r.kid != "k2" || r.id != "abc" {
			t.Errorf("renewed cookie = %+v, want kid k2, id abc", r)
		}
	})

	t.Run("invalid cookie is replaced with a new session", func(t *testing.T) {
		rec := httptest.NewRecorder()
		if got := sc.maybeIssue(rec, sessionRead{result: sessionInvalid}); got != sessionIssued {
			t.Errorf("action = %q, want issued", got)
		}
	})

	t.Run("check-only block never issues", func(t *testing.T) {
		checker := mustSessionCookies(t, &SessionCookieConfig{Mode: "check", Keys: []SessionKey{{"k1", k1}}}, &now)
		rec := httptest.NewRecorder()
		if got := checker.maybeIssue(rec, sessionRead{result: sessionAbsent}); got != "" || len(rec.Header().Values("Set-Cookie")) != 0 {
			t.Errorf("action = %q, Set-Cookie = %v, want none", got, rec.Header().Values("Set-Cookie"))
		}
	})
}

func TestSessionCookies_NilIsNoOp(t *testing.T) {
	var sc *sessionCookies
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := sc.read(req); got.result != sessionAbsent {
		t.Errorf("nil read = %q, want absent", got.result)
	}
	if got := sc.maybeIssue(httptest.NewRecorder(), sessionRead{}); got != "" {
		t.Errorf("nil maybeIssue = %q, want none", got)
	}
	if sc.status() != nil {
		t.Error("nil status() != nil")
	}
}

func TestApplySession(t *testing.T) {
	cases := []struct {
		name      string
		class     UserClass
		userID    string
		read      sessionRead
		wantClass UserClass
		wantID    string
	}{
		{"absent leaves anonymous", UserClassAnonymous, "", sessionRead{result: sessionAbsent}, UserClassAnonymous, ""},
		{"valid upgrades anonymous", UserClassAnonymous, "", sessionRead{result: sessionValid, id: "abc"}, UserClassHumanVerified, "session:abc"},
		{"valid upgrades unknown token", UserClassUnknown, "", sessionRead{result: sessionValid, id: "abc"}, UserClassHumanVerified, "session:abc"},
		{"invalid downgrades anonymous to unknown", UserClassAnonymous, "", sessionRead{result: sessionInvalid}, UserClassUnknown, ""},
		{"expired downgrades anonymous to unknown", UserClassAnonymous, "", sessionRead{result: sessionExpired}, UserClassUnknown, ""},
		{"verified JWT class wins over a valid cookie", UserClassResearcher, "alice", sessionRead{result: sessionValid, id: "abc"}, UserClassResearcher, "alice"},
		{"verified JWT class wins over a bad cookie", UserClassInternal, "svc", sessionRead{result: sessionInvalid}, UserClassInternal, "svc"},
	}
	for _, tc := range cases {
		c := Classification{UserClass: tc.class, UserID: tc.userID}
		applySession(&c, tc.read)
		if c.UserClass != tc.wantClass || c.UserID != tc.wantID {
			t.Errorf("%s: got %q/%q, want %q/%q", tc.name, c.UserClass, c.UserID, tc.wantClass, tc.wantID)
		}
	}
}

// serveSession runs h.ServeHTTP for a request optionally carrying cookie,
// returning the recorder and the request (to read caddyhttp vars back).
func serveSession(t *testing.T, h *Handler, cookie *http.Cookie) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/wayback/", nil)
	req.RemoteAddr = "203.0.113.5:1234"
	if cookie != nil {
		req.AddCookie(cookie)
	}
	req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{}))
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	return rec, req
}

func newSessionHandler(t *testing.T, backend, mode, keyFile string, overrides *scoringOverrides, now *time.Time) *Handler {
	t.Helper()
	h := &Handler{Config: Config{Backend: backend}, ScoringOverrides: overrides}
	h.scoring = newScoringState(resolveScoringConfig(overrides), time.Second, time.Hour)
	h.session = mustSessionCookies(t, &SessionCookieConfig{Mode: mode, Keys: []SessionKey{{"k1", keyFile}}}, now)
	return h
}

func TestHandler_ServeHTTP_SessionCookie_IssueThenCheck(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	keyFile := writeSessionKey(t, testSecret1)
	issuer := newSessionHandler(t, "session-issue", "issue", keyFile, nil, &now)
	checker := newSessionHandler(t, "session-check", "check", keyFile, &scoringOverrides{
		EnabledDimensions: map[string]bool{"user": true},
		Penalties:         map[string]PenaltyConfig{"user": {Alpha: 1, SoftThreshold: 5, SoftPenalty: 10, HardThreshold: 50, HardPenalty: 40}},
	}, &now)

	// Issuing route: sets the cookie but doesn't itself classify by it.
	rec, req := serveSession(t, issuer, nil)
	cookie := issuedCookie(t, rec)
	if c := caddyhttp.GetVar(req.Context(), classificationVarKey).(Classification); c.UserClass != UserClassAnonymous {
		t.Errorf("issue-only block classified as %q, want anonymous", c.UserClass)
	}
	if got := testutil.ToFloat64(fairnessMetrics.sessionCookies.WithLabelValues("session-issue", "issued")); got != 1 {
		t.Errorf("issued counter = %v, want 1", got)
	}

	// Checking route without the cookie: anonymous base score.
	_, req = serveSession(t, checker, nil)
	if got := caddyhttp.GetVar(req.Context(), fairnessScoreVarKey).(float64); got != 60 {
		t.Errorf("no-cookie score = %v, want anonymous base 60", got)
	}

	// Checking route with the cookie: human_verified base score, no Set-Cookie.
	rec, req = serveSession(t, checker, cookie)
	if c := caddyhttp.GetVar(req.Context(), classificationVarKey).(Classification); c.UserClass != UserClassHumanVerified || !strings.HasPrefix(c.UserID, "session:") {
		t.Errorf("classification = %+v, want human_verified with a session: UserID", c)
	}
	if got := caddyhttp.GetVar(req.Context(), fairnessScoreVarKey).(float64); got != 80 {
		t.Errorf("cookie score = %v, want human_verified base 80", got)
	}
	if v := rec.Header().Values("Set-Cookie"); len(v) != 0 {
		t.Errorf("check-only block sent Set-Cookie %v", v)
	}

	// The same session flooding is still penalized via the `user` dimension.
	for range 10 {
		serveSession(t, checker, cookie)
	}
	checker.scoring.tick(now)
	_, req = serveSession(t, checker, cookie)
	if got := caddyhttp.GetVar(req.Context(), fairnessScoreVarKey).(float64); got != 70 {
		t.Errorf("flooding session score = %v, want 80 - soft penalty 10 = 70", got)
	}

	// A forged cookie: unknown, scored like anonymous.
	forged := &http.Cookie{Name: cookie.Name, Value: cookie.Value[:len(cookie.Value)-2] + "AA"}
	_, req = serveSession(t, checker, forged)
	if c := caddyhttp.GetVar(req.Context(), classificationVarKey).(Classification); c.UserClass != UserClassUnknown {
		t.Errorf("forged cookie class = %q, want unknown", c.UserClass)
	}
	if got := testutil.ToFloat64(fairnessMetrics.sessionCookies.WithLabelValues("session-check", "invalid")); got != 1 {
		t.Errorf("invalid counter = %v, want 1", got)
	}
}

func TestUnmarshalCaddyfile_SessionCookie_RoundTrips(t *testing.T) {
	input := `fairness {
		session_cookie {
			mode both
			key  k2 /etc/caddy/aac-k2.key
			key  k1 /etc/caddy/aac-k1.key
			name my_session
			ttl  15m
		}
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	sc := h.SessionCookie
	if sc == nil || sc.Mode != "both" || sc.Name != "my_session" || sc.TTL != 15*time.Minute {
		t.Fatalf("SessionCookie = %+v", sc)
	}
	if len(sc.Keys) != 2 || sc.Keys[0] != (SessionKey{"k2", "/etc/caddy/aac-k2.key"}) || sc.Keys[1] != (SessionKey{"k1", "/etc/caddy/aac-k1.key"}) {
		t.Errorf("Keys = %+v, want k2 then k1 in declaration order", sc.Keys)
	}
}

func TestUnmarshalCaddyfile_SessionCookie_Errors(t *testing.T) {
	cases := map[string]string{
		"no keys":       `session_cookie { mode check }`,
		"bad mode":      `session_cookie { mode sometimes; key k1 /k }`,
		"key arg count": `session_cookie { key k1 }`,
		"bad kid":       `session_cookie { key k.1 /k }`,
		"bad ttl":       `session_cookie { key k1 /k; ttl soon }`,
		"zero ttl":      `session_cookie { key k1 /k; ttl 0s }`,
		"unknown":       `session_cookie { key k1 /k; domain example.org }`,
		"inline arg":    `session_cookie check { key k1 /k }`,
	}
	for name, body := range cases {
		input := "fairness {\n" + strings.ReplaceAll(strings.ReplaceAll(body, "{ ", "{\n"), "; ", "\n") + "\n}"
		input = strings.ReplaceAll(input, " }", "\n}")
		var h Handler
		if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
			t.Errorf("%s: UnmarshalCaddyfile(%q) succeeded, want error", name, input)
		}
	}
}

func TestUnmarshalCaddyfile_Scoring_HumanVerifiedBaseScore(t *testing.T) {
	input := `fairness {
		scoring {
			base_score human_verified 60
		}
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	if got := resolveScoringConfig(h.ScoringOverrides).BaseScores[UserClassHumanVerified]; got != 60 {
		t.Errorf("human_verified base = %v, want 60 (observation mode override)", got)
	}
}
