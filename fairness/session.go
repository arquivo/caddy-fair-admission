// Package fairness — HMAC-signed session cookie (arquivo/pwa-technologies#1664).
// An opt-in, per-block `session_cookie { }` sub-block lets a fairness block
// either *issue* a short-lived signed cookie (on routes that sit behind a
// human-facing challenge such as Anubis — a deployment concern, this module
// knows nothing about Anubis) or *check* it, classifying a request carrying a
// valid cookie as UserClassHumanVerified. Like every other classification
// signal here, the cookie only ever reorders the priority queue: a missing,
// forged, or expired cookie never blocks a request, and a valid one never
// bypasses capacity, penalties, or queue limits.
//
// Cookie value (no JWT, no claims — this module is the only issuer and the
// only checker, so a plain signed string is enough):
//
//	v1.<kid>.<expiry-unix>.<random-id>.<mac>
//	mac = base64url(HMAC-SHA256(secret[kid], "v1.<kid>.<expiry-unix>.<random-id>"))
//
// The value carries no IP, query, or identity. The random-id is the
// session's key in the `user` penalty dimension, so a cookie-holding client
// that floods requests is still penalized per session.
package fairness

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	sessionCookieVersion = "v1"
	// defaultSessionCookieName is the cookie name used when `name` is unset.
	defaultSessionCookieName = "aac_session"
	// defaultSessionCookieTTL is the cookie lifetime used when `ttl` is unset.
	defaultSessionCookieTTL = 30 * time.Minute
	// minSessionKeyBytes is the minimum secret length accepted from a key
	// file (after trimming surrounding whitespace) — 256 bits, matching
	// HMAC-SHA256's output size.
	minSessionKeyBytes = 32
	// sessionIDBytes is the random-id's entropy (128 bits).
	sessionIDBytes = 16
	// maxSessionCookieLen bounds how much attacker-supplied input verify
	// will hash. A legitimate value is ~90 bytes plus the kid.
	maxSessionCookieLen = 256
	// sessionUserIDPrefix namespaces a cookie's random-id when used as
	// Classification.UserID, so it can never collide with a JWT `sub` in
	// the `user` penalty dimension.
	sessionUserIDPrefix = "session:"
)

// Session cookie modes (`mode` in the Caddyfile).
const (
	sessionModeCheck = "check"
	sessionModeIssue = "issue"
	sessionModeBoth  = "both"
)

// SessionKey is one HMAC secret, identified by KID and loaded from File.
type SessionKey struct {
	KID  string `json:"kid"`
	File string `json:"file"`
}

// SessionCookieConfig is the `session_cookie { }` sub-block's configuration.
// Keys[0] signs newly issued cookies; every listed key verifies, so a key can
// be rotated without downtime by prepending the new one and dropping the old
// one once its cookies have expired.
type SessionCookieConfig struct {
	// Mode is "check", "issue", or "both". Empty means "check".
	Mode string `json:"mode,omitempty"`
	// Name is the cookie name. Empty means "aac_session".
	Name string `json:"name,omitempty"`
	// TTL is the lifetime of an issued cookie. Zero means 30m.
	TTL time.Duration `json:"ttl,omitempty"`
	// Keys lists the HMAC secrets, signing key first.
	Keys []SessionKey `json:"keys,omitempty"`
}

// sessionResult is the outcome of reading a request's session cookie, also
// used as the `result` label of fairness_session_cookies_total.
type sessionResult string

const (
	sessionAbsent  sessionResult = "absent"
	sessionValid   sessionResult = "valid"
	sessionInvalid sessionResult = "invalid"
	sessionExpired sessionResult = "expired"
	sessionIssued  sessionResult = "issued"
	sessionRenewed sessionResult = "renewed"
)

// sessionRead is what sessionCookies.read found on a request.
type sessionRead struct {
	result sessionResult
	// id, kid, and expiry are only set when result is sessionValid.
	id     string
	kid    string
	expiry time.Time
}

// sessionCookies is a Handler's provisioned session-cookie state: loaded
// secrets plus the resolved mode/name/TTL. now and rand are injectable for
// tests.
type sessionCookies struct {
	name    string
	ttl     time.Duration
	issue   bool
	check   bool
	signKID string
	keys    map[string][]byte

	now  func() time.Time
	rand io.Reader
}

// newSessionCookies validates cfg and loads its key files. Errors here are
// Provision-time errors: a missing/short key file must fail the config load,
// never silently disable the feature.
func newSessionCookies(cfg *SessionCookieConfig) (*sessionCookies, error) {
	sc := &sessionCookies{
		name: cfg.Name,
		ttl:  cfg.TTL,
		keys: make(map[string][]byte, len(cfg.Keys)),
		now:  time.Now,
		rand: rand.Reader,
	}
	if sc.name == "" {
		sc.name = defaultSessionCookieName
	}
	if sc.ttl <= 0 {
		sc.ttl = defaultSessionCookieTTL
	}
	switch cfg.Mode {
	case "", sessionModeCheck:
		sc.check = true
	case sessionModeIssue:
		sc.issue = true
	case sessionModeBoth:
		sc.check, sc.issue = true, true
	default:
		return nil, fmt.Errorf("fairness: session_cookie mode must be check, issue, or both, got %q", cfg.Mode)
	}
	if len(cfg.Keys) == 0 {
		return nil, fmt.Errorf("fairness: session_cookie requires at least one `key <kid> <file>`")
	}
	for _, k := range cfg.Keys {
		if err := validateSessionKID(k.KID); err != nil {
			return nil, err
		}
		if _, dup := sc.keys[k.KID]; dup {
			return nil, fmt.Errorf("fairness: session_cookie key id %q is listed more than once", k.KID)
		}
		raw, err := os.ReadFile(k.File)
		if err != nil {
			return nil, fmt.Errorf("fairness: session_cookie key %q: %w", k.KID, err)
		}
		secret := bytes.TrimSpace(raw)
		if len(secret) < minSessionKeyBytes {
			return nil, fmt.Errorf("fairness: session_cookie key %q in %q is %d bytes, need at least %d", k.KID, k.File, len(secret), minSessionKeyBytes)
		}
		sc.keys[k.KID] = secret
	}
	sc.signKID = cfg.Keys[0].KID
	return sc, nil
}

// validateSessionKID rejects key IDs that would break the dot-separated
// cookie format or need escaping in a cookie value.
func validateSessionKID(kid string) error {
	if kid == "" {
		return fmt.Errorf("fairness: session_cookie key id must not be empty")
	}
	for _, r := range kid {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return fmt.Errorf("fairness: session_cookie key id %q may only contain letters, digits, '-' and '_'", kid)
		}
	}
	return nil
}

// mac returns base64url(HMAC-SHA256(secret, payload)).
func sessionMAC(secret []byte, payload string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// sign builds a cookie value for id, expiring at expiry, signed with the
// signing key.
func (sc *sessionCookies) sign(id string, expiry time.Time) string {
	payload := sessionCookieVersion + "." + sc.signKID + "." + strconv.FormatInt(expiry.Unix(), 10) + "." + id
	return payload + "." + sessionMAC(sc.keys[sc.signKID], payload)
}

// verify checks a cookie value: well-formed, known kid, MAC matches (constant
// time), not expired. The MAC is checked before expiry, so "expired" is only
// ever reported for an authentic cookie.
func (sc *sessionCookies) verify(value string) sessionRead {
	if len(value) > maxSessionCookieLen {
		return sessionRead{result: sessionInvalid}
	}
	parts := strings.Split(value, ".")
	if len(parts) != 5 || parts[0] != sessionCookieVersion {
		return sessionRead{result: sessionInvalid}
	}
	kid, expStr, id, mac := parts[1], parts[2], parts[3], parts[4]
	secret, ok := sc.keys[kid]
	if !ok || id == "" {
		return sessionRead{result: sessionInvalid}
	}
	payload := value[:len(value)-len(mac)-1]
	if !hmac.Equal([]byte(mac), []byte(sessionMAC(secret, payload))) {
		return sessionRead{result: sessionInvalid}
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return sessionRead{result: sessionInvalid}
	}
	expiry := time.Unix(exp, 0)
	if !sc.now().Before(expiry) {
		return sessionRead{result: sessionExpired}
	}
	return sessionRead{result: sessionValid, id: id, kid: kid, expiry: expiry}
}

// read looks up and verifies r's session cookie. Nil-safe: a nil
// *sessionCookies (feature not configured) always reports sessionAbsent.
func (sc *sessionCookies) read(r *http.Request) sessionRead {
	if sc == nil {
		return sessionRead{result: sessionAbsent}
	}
	c, err := r.Cookie(sc.name)
	if err != nil || c.Value == "" {
		return sessionRead{result: sessionAbsent}
	}
	return sc.verify(c.Value)
}

// newID returns a fresh 128-bit base64url random-id.
func (sc *sessionCookies) newID() (string, error) {
	b := make([]byte, sessionIDBytes)
	if _, err := io.ReadFull(sc.rand, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// maybeIssue sets a Set-Cookie header on w if this is an issuing block and
// the request's current cookie (s) needs one:
//   - absent/invalid/expired → a brand-new session (sessionIssued);
//   - valid but past half its TTL, or signed with a key that's no longer
//     the signing key → re-signed with a fresh expiry, keeping the same
//     random-id so its `user` penalty counter carries over (sessionRenewed);
//   - otherwise nothing is sent (limited renewal: at most one Set-Cookie per
//     half-TTL per session).
//
// Returns the action taken, or "" if none. Never fails the request: a
// random-source error just skips issuing.
func (sc *sessionCookies) maybeIssue(w http.ResponseWriter, s sessionRead) sessionResult {
	if sc == nil || !sc.issue {
		return ""
	}
	now := sc.now()
	id := s.id
	action := sessionRenewed
	if s.result == sessionValid {
		if s.kid == sc.signKID && s.expiry.Sub(now) > sc.ttl/2 {
			return ""
		}
	} else {
		var err error
		if id, err = sc.newID(); err != nil {
			return ""
		}
		action = sessionIssued
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sc.name,
		Value:    sc.sign(id, now.Add(sc.ttl)),
		Path:     "/",
		MaxAge:   int(sc.ttl / time.Second),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return action
}

// applySession folds a checked session cookie into c (only called on
// checking blocks). A JWT-verified trusted class always wins over the
// cookie. Otherwise a valid cookie upgrades the request to
// UserClassHumanVerified with the session's random-id as its UserID (the
// `user` penalty key), and a forged/expired one downgrades anonymous to
// unknown — same base score by default, so no gain and no penalty.
func applySession(c *Classification, s sessionRead) {
	if validClaimedUserClasses[c.UserClass] {
		return
	}
	switch s.result {
	case sessionValid:
		c.UserClass = UserClassHumanVerified
		c.UserID = sessionUserIDPrefix + s.id
	case sessionInvalid, sessionExpired:
		c.UserClass = UserClassUnknown
	}
}
