package authn_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/specforge/specforge/internal/platform/authn"
)

func newDevIdP(t *testing.T, redirect string) (*authn.DevIdP, *httptest.Server) {
	t.Helper()
	// The issuer must be the server's own URL, so start a placeholder, build the
	// provider against the real URL, then swap in its handler.
	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	idp, err := authn.NewDevIdP(authn.DevIdPOptions{
		Issuer:       srv.URL,
		ClientID:     "specforge-web",
		RedirectURIs: []string{redirect},
		Users:        authn.DefaultDevUsers("11111111-1111-4111-8111-111111111111"),
	})
	if err != nil {
		t.Fatalf("dev idp: %v", err)
	}
	handler = idp.Handler()
	return idp, srv
}

func TestOIDCAuthorizationCodeFlowEndToEnd(t *testing.T) {
	const redirect = "http://localhost:3000/api/v1/auth/callback"
	idp, srv := newDevIdP(t, redirect)
	ctx := context.Background()

	provider, err := authn.NewOIDCProvider(ctx, authn.OIDCConfig{
		Issuer:      srv.URL,
		ClientID:    "specforge-web",
		RedirectURL: redirect,
	})
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}

	state, nonce, err := authn.NewStateNonce()
	if err != nil {
		t.Fatal(err)
	}
	pkce, err := authn.NewPKCE()
	if err != nil {
		t.Fatal(err)
	}

	authURL, err := provider.AuthorizeURL(state, nonce, pkce.Challenge,
		url.Values{"sf_user": {"dev-owner"}})
	if err != nil {
		t.Fatalf("authorize url: %v", err)
	}

	// Follow the authorization request without following the redirect, so we can
	// read the code exactly as a browser would hand it back.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("want a redirect, got %s", resp.Status)
	}

	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Get("state") != state {
		t.Fatal("state was not echoed back")
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no authorization code in %s", loc)
	}

	tokens, err := provider.Exchange(ctx, code, pkce.Verifier)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if tokens.IDToken == "" || tokens.AccessToken == "" {
		t.Fatal("token response is incomplete")
	}

	claims, err := provider.Verify(ctx, tokens.IDToken, nonce)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "dev-owner" {
		t.Fatalf("subject is %q", claims.Subject)
	}
	if claims.Nonce != nonce {
		t.Fatal("nonce binding is missing")
	}
	if got := claims.String("https://specforge.io/tenant"); got == "" {
		t.Fatal("the tenant claim is missing")
	}
	roles := claims.StringSlice("https://specforge.io/roles")
	if len(roles) == 0 || roles[0] != "product_owner" {
		t.Fatalf("roles claim is %v", roles)
	}
	if !containsStr(claims.AMR, "mfa") {
		t.Fatalf("expected an MFA claim for this seeded user, got %v", claims.AMR)
	}

	// The userinfo endpoint agrees with the token.
	ui, err := provider.UserInfo(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	if ui.Subject != "dev-owner" {
		t.Fatalf("userinfo subject is %q", ui.Subject)
	}

	_ = idp
}

func TestAuthorizationCodeIsSingleUse(t *testing.T) {
	const redirect = "http://localhost:3000/cb"
	_, srv := newDevIdP(t, redirect)
	ctx := context.Background()

	provider, err := authn.NewOIDCProvider(ctx, authn.OIDCConfig{
		Issuer: srv.URL, ClientID: "specforge-web", RedirectURL: redirect,
	})
	if err != nil {
		t.Fatal(err)
	}
	code, pkce := authorizeOnce(t, provider, srv, redirect, "dev-dev")

	if _, err := provider.Exchange(ctx, code, pkce.Verifier); err != nil {
		t.Fatalf("first exchange should succeed: %v", err)
	}
	if _, err := provider.Exchange(ctx, code, pkce.Verifier); err == nil {
		t.Fatal("a replayed authorization code was accepted")
	}
}

func TestPKCEVerifierIsEnforced(t *testing.T) {
	const redirect = "http://localhost:3000/cb"
	_, srv := newDevIdP(t, redirect)
	ctx := context.Background()

	provider, err := authn.NewOIDCProvider(ctx, authn.OIDCConfig{
		Issuer: srv.URL, ClientID: "specforge-web", RedirectURL: redirect,
	})
	if err != nil {
		t.Fatal(err)
	}
	code, _ := authorizeOnce(t, provider, srv, redirect, "dev-dev")

	other, err := authn.NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Exchange(ctx, code, other.Verifier); err == nil {
		t.Fatal("an authorization code was exchanged with the wrong PKCE verifier")
	}
}

func TestUnregisteredRedirectURIIsRefused(t *testing.T) {
	const redirect = "http://localhost:3000/cb"
	_, srv := newDevIdP(t, redirect)

	q := url.Values{
		"response_type": {"code"}, "client_id": {"specforge-web"},
		"redirect_uri":          {"https://evil.example/steal"},
		"code_challenge":        {"x"},
		"code_challenge_method": {"S256"},
		"sf_user":               {"dev-owner"},
	}
	resp, err := http.Get(srv.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("an unregistered redirect_uri returned %s; it must be refused", resp.Status)
	}
}

func TestVerifyRejectsUnsafeAlgorithms(t *testing.T) {
	t.Parallel()
	_, srv := newDevIdP(t, "http://localhost:3000/cb")
	src := fetchKeys(t, srv.URL)

	// "alg": "none" with an empty signature — the classic bypass.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		`{"iss":"` + srv.URL + `","sub":"attacker","aud":"specforge-web","exp":9999999999}`))
	if _, err := authn.Verify(header+"."+payload+".", src, authn.VerifyOptions{
		Issuer: srv.URL, Audience: "specforge-web",
	}); err == nil {
		t.Fatal(`a token with "alg":"none" was accepted`)
	}

	// HMAC signed with the public key as the secret — algorithm confusion.
	header = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	if _, err := authn.Verify(header+"."+payload+".AAAA", src, authn.VerifyOptions{
		Issuer: srv.URL, Audience: "specforge-web",
	}); err == nil {
		t.Fatal("an HMAC-signed token was accepted against an asymmetric key set")
	}
}

func TestVerifyChecksRegisteredClaims(t *testing.T) {
	t.Parallel()
	idp, srv := newDevIdP(t, "http://localhost:3000/cb")
	src := fetchKeys(t, srv.URL)

	token, err := idp.IssueTokenFor("dev-owner", "specforge-web", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Correct parameters verify.
	if _, err := authn.Verify(token, src, authn.VerifyOptions{
		Issuer: srv.URL, Audience: "specforge-web",
	}); err != nil {
		t.Fatalf("a valid token failed verification: %v", err)
	}

	cases := []struct {
		name string
		opts authn.VerifyOptions
	}{
		{"wrong issuer", authn.VerifyOptions{Issuer: "https://evil.example", Audience: "specforge-web"}},
		{"wrong audience", authn.VerifyOptions{Issuer: srv.URL, Audience: "another-client"}},
		{"expired", authn.VerifyOptions{
			Issuer: srv.URL, Audience: "specforge-web",
			Now: func() time.Time { return time.Now().Add(48 * time.Hour) },
		}},
		{"not yet issued", authn.VerifyOptions{
			Issuer: srv.URL, Audience: "specforge-web",
			Now: func() time.Time { return time.Now().Add(-48 * time.Hour) },
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := authn.Verify(token, src, tc.opts); err == nil {
				t.Fatalf("verification should have failed: %s", tc.name)
			}
		})
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	t.Parallel()
	idp, srv := newDevIdP(t, "http://localhost:3000/cb")
	src := fetchKeys(t, srv.URL)

	token, err := idp.IssueTokenFor("dev-viewer", "specforge-web", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	// Escalate the roles claim, keeping the original signature.
	claims["https://specforge.io/roles"] = []string{"platform_admin"}
	tampered, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(tampered) + "." + parts[2]

	if _, err := authn.Verify(forged, src, authn.VerifyOptions{
		Issuer: srv.URL, Audience: "specforge-web",
	}); err == nil {
		t.Fatal("a token with an escalated roles claim was accepted")
	}
}

func TestPKCERoundTrip(t *testing.T) {
	t.Parallel()
	p, err := authn.NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	if !authn.VerifyPKCE(p.Verifier, p.Challenge, "S256") {
		t.Fatal("a valid PKCE pair did not verify")
	}
	if authn.VerifyPKCE(p.Verifier, p.Challenge, "plain") {
		t.Fatal("the plain PKCE method must not be accepted")
	}
	if authn.VerifyPKCE("wrong", p.Challenge, "S256") {
		t.Fatal("a wrong verifier passed")
	}
}

func TestAudienceAcceptsBothForms(t *testing.T) {
	t.Parallel()
	var single, many authn.Claims
	if err := json.Unmarshal([]byte(`{"aud":"one"}`), &single); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"aud":["one","two"]}`), &many); err != nil {
		t.Fatal(err)
	}
	if !single.Audience.Contains("one") || !many.Audience.Contains("two") {
		t.Fatal("audience parsing is wrong")
	}
}

// ---------------------------------------------------------------------------

func authorizeOnce(t *testing.T, p *authn.OIDCProvider, srv *httptest.Server, redirect, user string) (string, authn.PKCE) {
	t.Helper()
	state, nonce, err := authn.NewStateNonce()
	if err != nil {
		t.Fatal(err)
	}
	pkce, err := authn.NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	authURL, err := p.AuthorizeURL(state, nonce, pkce.Challenge, url.Values{"sf_user": {user}})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code returned for %s", user)
	}
	return code, pkce
}

func fetchKeys(t *testing.T, issuer string) authn.KeySource {
	t.Helper()
	resp, err := http.Get(issuer + "/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var set authn.JWKSet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatal(err)
	}
	src, err := authn.NewStaticKeySource(set)
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// A tenant id frozen at startup is wrong the moment the database is reseeded,
// and the failure surfaces three layers away as a foreign key violation on the
// principals table. Resolving late is what prevents that, so this asserts the
// resolution actually happens per token rather than once.
func TestDevIdPResolvesTenantAtIssueTime(t *testing.T) {
	t.Parallel()

	current := "11111111-1111-4111-8111-111111111111"
	calls := 0

	idp, err := authn.NewDevIdP(authn.DevIdPOptions{
		Issuer: "http://127.0.0.1:8081", ClientID: "specforge-web",
		RedirectURIs: []string{"http://localhost:3000/api/auth/callback"},
		// The users carry a stale id, as they would after a reseed.
		Users:         authn.DefaultDevUsers("00000000-0000-4000-8000-000000000000"),
		TenantClaim:   "https://specforge.io/tenant",
		RolesClaim:    "https://specforge.io/roles",
		ResolveTenant: func() string { calls++; return current },
	})
	if err != nil {
		t.Fatalf("dev idp: %v", err)
	}

	tenantOf := func() string {
		srv := httptest.NewServer(idp.Handler())
		defer srv.Close()
		resp, err := http.Get(srv.URL + "/users")
		if err != nil {
			t.Fatalf("users: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		var users []authn.DevUser
		if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(users) == 0 {
			t.Fatal("no seeded accounts")
		}
		return users[0].TenantID
	}

	if got := tenantOf(); got != current {
		t.Fatalf("tenant %q, want the resolved %q — a stale id reached the token", got, current)
	}
	if calls == 0 {
		t.Fatal("the resolver was never consulted")
	}

	// Reseed. Without waiting out the cache the old answer is still correct;
	// after it, the new one must win without restarting anything.
	current = "22222222-2222-4222-8222-222222222222"
	time.Sleep(5100 * time.Millisecond)
	if got := tenantOf(); got != current {
		t.Fatalf("after a reseed the tenant is %q, want %q", got, current)
	}
}
