package fairness

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthenticate_NoHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	class, userID := authenticate(nil, req)
	if class != UserClassAnonymous || userID != "" {
		t.Errorf("authenticate(no header) = (%q, %q), want (anonymous, \"\")", class, userID)
	}
}

func TestAuthenticate_NoVerifierConfigured(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some.token.value")
	class, userID := authenticate(nil, req)
	if class != UserClassAnonymous || userID != "" {
		t.Errorf("authenticate(no verifier configured) = (%q, %q), want (anonymous, \"\")", class, userID)
	}
}

func TestAuthenticate_MalformedHeader(t *testing.T) {
	cases := []string{"Basic abcdef", "Bearer", "Bearer ", ""}
	for _, h := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if h != "" {
			req.Header.Set("Authorization", h)
		}
		class, userID := authenticate(nil, req)
		if class != UserClassAnonymous || userID != "" {
			t.Errorf("authenticate(%q) = (%q, %q), want (anonymous, \"\")", h, class, userID)
		}
	}
}

// TestAuthenticate_UnreachableJWKS_ServerError points at an httptest.Server
// that always 500s. With NoErrorReturnFirstHTTPReq, constructing the
// verifier must still succeed (fail open), and authenticating a request
// that carries a bearer token against it must classify as unknown rather
// than erroring or rejecting the request (REQUIREMENTS.md §4.2).
func TestAuthenticate_UnreachableJWKS_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	v := mustBuildTestVerifier(t, srv.URL)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some.token.value")
	class, userID := authenticate(v, req)
	if class != UserClassUnknown || userID != "" {
		t.Errorf("authenticate() with unreachable JWKS = (%q, %q), want (unknown, \"\")", class, userID)
	}

	// No token at all must still be anonymous, regardless of JWKS health.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	class2, userID2 := authenticate(v, req2)
	if class2 != UserClassAnonymous || userID2 != "" {
		t.Errorf("authenticate() with no token = (%q, %q), want (anonymous, \"\")", class2, userID2)
	}
}

// TestAuthenticate_UnreachableJWKS_BogusAddress points at an address nothing
// listens on; same fail-open expectation as the 500 case above.
func TestAuthenticate_UnreachableJWKS_BogusAddress(t *testing.T) {
	v := mustBuildTestVerifier(t, "http://127.0.0.1:1")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some.token.value")
	class, userID := authenticate(v, req)
	if class != UserClassUnknown || userID != "" {
		t.Errorf("authenticate() with bogus JWKS address = (%q, %q), want (unknown, \"\")", class, userID)
	}
}

func mustBuildTestVerifier(t *testing.T, jwksURL string) *verifier {
	t.Helper()
	// RefreshInterval 0 disables the background refresh goroutine -- the
	// test only needs the (fail-open) first-request behavior.
	construct := openJWKSVerifier(jwksURL, 0)
	destructor, err := construct()
	if err != nil {
		t.Fatalf("openJWKSVerifier constructor returned error, want fail-open nil error: %v", err)
	}
	jv, ok := destructor.(*jwksVerifier)
	if !ok {
		t.Fatalf("constructor returned %T, want *jwksVerifier", destructor)
	}
	t.Cleanup(func() { _ = jv.Destruct() })
	return &verifier{kf: jv.kf}
}

func TestJWKSVerifier_DestructNilSafe(t *testing.T) {
	var jv *jwksVerifier
	if err := jv.Destruct(); err != nil {
		t.Errorf("Destruct() on nil *jwksVerifier returned error: %v", err)
	}
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{"Bearer abc.def.ghi", "abc.def.ghi"},
		{"bearer abc.def.ghi", "abc.def.ghi"},
		{"", ""},
		{"Basic abcdef", ""},
		{"Bearer", ""},
		{"Bearer ", ""},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if tc.header != "" {
			req.Header.Set("Authorization", tc.header)
		}
		got := bearerToken(req)
		if got != tc.want {
			t.Errorf("bearerToken(%q) = %q, want %q", tc.header, got, tc.want)
		}
	}
}
