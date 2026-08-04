// JWT bearer-token verification against a JWKS endpoint (REQUIREMENTS.md
// §3.1, §4.2). This module never rejects a request itself: a missing header
// classifies as anonymous, and any verification failure (bad signature,
// expired, JWKS unreachable, wrong issuer/audience) classifies as unknown —
// never a 401/403 and never a propagated error. The JWKS refresh loop
// (keyfunc.Keyfunc + its background goroutine) is shared across fairness
// blocks that reference the same JWKS URL via the App module's
// caddy.UsagePool (see app.go), matching the GeoIP dedup pattern.
package fairness

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/caddyserver/caddy/v2"
	"github.com/golang-jwt/jwt/v5"
)

// authClaims is the JWT claims shape this module understands: the standard
// registered claims (issuer/audience/subject/expiry, used both for
// validation and to read `sub` as the user ID) plus the identity-only
// user_class claim (REQUIREMENTS.md §4.2 — never a behavior signal).
type authClaims struct {
	jwt.RegisteredClaims
	UserClass string `json:"user_class,omitempty"`
}

// jwksVerifier wraps a keyfunc.Keyfunc plus the CancelFunc that stops its
// background refresh goroutine, so the pair can live in a caddy.UsagePool
// (implements caddy.Destructor). A jwksVerifier with a nil kf fails open:
// authenticate treats it the same as "no verifier configured".
type jwksVerifier struct {
	kf     keyfunc.Keyfunc
	cancel context.CancelFunc
}

// Destruct implements caddy.Destructor.
func (v *jwksVerifier) Destruct() error {
	if v == nil {
		return nil
	}
	if v.cancel != nil {
		v.cancel()
	}
	return nil
}

// verifier is what Handler.ServeHTTP consults to authenticate a request: the
// shared keyfunc.Keyfunc (nil if auth isn't configured for this block) plus
// this block's own issuer/audience expectations.
type verifier struct {
	kf       keyfunc.Keyfunc
	issuer   string
	audience string
}

// openJWKSVerifier returns a caddy.Constructor that starts a fail-open JWKS
// refresh loop for jwksURL. Per REQUIREMENTS.md §4.2, this never fails
// construction: NoErrorReturnFirstHTTPReq tolerates the first fetch failing,
// RefreshErrorHandler swallows background refresh errors (keeping the
// last-known-good, or empty, key set), and even the unexpected case of
// jwkset/keyfunc construction itself erroring yields a verifier with no keys
// rather than propagating an error to Handler.Provision.
func openJWKSVerifier(jwksURL string, refreshInterval time.Duration) caddy.Constructor {
	return func() (caddy.Destructor, error) {
		ctx, cancel := context.WithCancel(context.Background())

		storage, err := jwkset.NewStorageFromHTTP(jwksURL, jwkset.HTTPClientStorageOptions{
			Ctx:                       ctx,
			RefreshInterval:           refreshInterval,
			NoErrorReturnFirstHTTPReq: true,
			RefreshErrorHandler: func(_ context.Context, _ error) {
				// Fail open: swallow background refresh failures and keep
				// serving the last-known-good (or empty) key set.
			},
		})
		if err != nil {
			cancel()
			return &jwksVerifier{}, nil
		}

		kf, err := keyfunc.New(keyfunc.Options{Ctx: ctx, Storage: storage})
		if err != nil {
			cancel()
			return &jwksVerifier{}, nil
		}

		return &jwksVerifier{kf: kf, cancel: cancel}, nil
	}
}

// authenticate extracts and verifies a bearer token per REQUIREMENTS.md
// §4.2. It never returns an error and never rejects the request:
//   - no Authorization header (or not a Bearer token) -> anonymous, no ID
//   - a token is present but no verifier is configured on this block ->
//     anonymous (auth is optional per block)
//   - verification fails for any reason -> unknown, no user ID
//   - verification succeeds -> `sub` as the user ID, and the user_class
//     claim if it's one of the recognized identity classes (otherwise
//     unknown, but the verified user ID is still kept — identity was
//     verified even if the class claim wasn't recognized)
func authenticate(v *verifier, r *http.Request) (UserClass, string) {
	token := bearerToken(r)
	if token == "" {
		return UserClassAnonymous, ""
	}
	if v == nil || v.kf == nil {
		return UserClassAnonymous, ""
	}

	opts := []jwt.ParserOption{jwt.WithValidMethods([]string{"RS256"})}
	if v.issuer != "" {
		opts = append(opts, jwt.WithIssuer(v.issuer))
	}
	if v.audience != "" {
		opts = append(opts, jwt.WithAudience(v.audience))
	}

	var claims authClaims
	parsed, err := jwt.ParseWithClaims(token, &claims, v.kf.Keyfunc, opts...)
	if err != nil || parsed == nil || !parsed.Valid {
		return UserClassUnknown, ""
	}

	class := UserClass(claims.UserClass)
	if !validClaimedUserClasses[class] {
		class = UserClassUnknown
	}
	return class, claims.Subject
}

// bearerToken extracts the token from an "Authorization: Bearer <token>"
// header, or "" if absent/malformed.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}
