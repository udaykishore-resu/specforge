package authn

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/specforge/specforge/internal/platform/id"
)

// DevIdP is a working OpenID Connect provider for local development.
//
// It is a real implementation of the authorization-code flow with PKCE: it
// publishes a discovery document and a JWKS, issues RS256-signed ID tokens with
// proper claims, enforces the PKCE challenge, expires and single-uses
// authorization codes, and supports RP-initiated logout. That matters because it
// means the platform's authentication path is exercised end to end offline,
// rather than being bypassed by a test hook that production never runs.
//
// It refuses to start when the environment is production (see Serve).
type DevIdP struct {
	issuer  string
	clients map[string]devClient
	users   []DevUser

	key   *rsa.PrivateKey
	keyID string

	tenantClaim string
	rolesClaim  string

	// resolveTenant answers "which tenant do the development accounts belong
	// to" at the moment a token is issued, rather than at startup.
	//
	// A tenant id frozen into the process at boot is wrong the instant the
	// database is reseeded, and it fails four layers away: the provider mints a
	// token naming a tenant that no longer exists, and the API returns a 503
	// from a foreign key on the principals table. Resolving late means the
	// answer is right whenever the question is asked.
	resolveTenant func() string

	tenantMu     sync.Mutex
	tenantCache  string
	tenantCached time.Time

	mu    sync.Mutex
	codes map[string]*devCode
}

type devClient struct {
	ID           string
	Secret       string
	RedirectURIs []string
}

type devCode struct {
	User          DevUser
	ClientID      string
	RedirectURI   string
	Nonce         string
	CodeChallenge string
	Method        string
	IssuedAt      time.Time
	Used          bool
}

// DevUser is a seeded identity with the roles it maps to.
type DevUser struct {
	Subject  string   `json:"sub"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	Groups   []string `json:"groups"`
	TenantID string   `json:"tenant"`
	// MFA controls whether the issued token claims a second factor, so step-up
	// enforcement can be exercised both ways locally.
	MFA bool `json:"mfa"`
}

// DevIdPOptions configures the provider.
type DevIdPOptions struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURIs []string
	Users        []DevUser
	TenantClaim  string
	RolesClaim   string
	// ResolveTenant is consulted when a token is issued. When it is nil, or
	// returns "", each user's own TenantID is used. See DevIdP.resolveTenant.
	ResolveTenant func() string
}

// DefaultDevUsers seeds one identity per platform role, so every authorization
// path can be walked locally without creating users by hand.
func DefaultDevUsers(tenantID string) []DevUser {
	mk := func(name, group string, mfa bool) DevUser {
		return DevUser{
			Subject: "dev-" + name, Email: name + "@specforge.local",
			Name:   strings.ToUpper(name[:1]) + name[1:],
			Groups: []string{group}, TenantID: tenantID, MFA: mfa,
		}
	}
	return []DevUser{
		mk("admin", "tenant_admin", true),
		mk("owner", "product_owner", true),
		mk("analyst", "business_analyst", true),
		mk("architect", "architect", true),
		mk("dev", "developer", false),
		mk("qa", "qa", false),
		mk("ops", "devops", true),
		mk("sec", "security", true),
		mk("compliance", "compliance", true),
		mk("auditor", "auditor", false),
		mk("viewer", "viewer", false),
		mk("platform", "platform_admin", true),
	}
}

// NewDevIdP creates the provider and generates a fresh signing key.
func NewDevIdP(opts DevIdPOptions) (*DevIdP, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("authn: generating dev signing key: %w", err)
	}
	if opts.TenantClaim == "" {
		opts.TenantClaim = "https://specforge.io/tenant"
	}
	if opts.RolesClaim == "" {
		opts.RolesClaim = "https://specforge.io/roles"
	}
	idp := &DevIdP{
		issuer: strings.TrimRight(opts.Issuer, "/"),
		clients: map[string]devClient{
			opts.ClientID: {ID: opts.ClientID, Secret: opts.ClientSecret, RedirectURIs: opts.RedirectURIs},
		},
		users:         opts.Users,
		key:           key,
		keyID:         id.NewToken(8),
		codes:         map[string]*devCode{},
		resolveTenant: opts.ResolveTenant,
		tenantClaim:   opts.TenantClaim,
		rolesClaim:    opts.RolesClaim,
	}
	return idp, nil
}

// Handler returns the provider's HTTP routes.
func (d *DevIdP) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", d.handleDiscovery)
	mux.HandleFunc("GET /jwks.json", d.handleJWKS)
	mux.HandleFunc("GET /authorize", d.handleAuthorize)
	mux.HandleFunc("POST /token", d.handleToken)
	mux.HandleFunc("GET /userinfo", d.handleUserInfo)
	mux.HandleFunc("GET /logout", d.handleLogout)
	mux.HandleFunc("GET /users", d.handleUsers)
	return mux
}

func (d *DevIdP) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, ProviderMetadata{
		Issuer:                d.issuer,
		AuthorizationEndpoint: d.issuer + "/authorize",
		TokenEndpoint:         d.issuer + "/token",
		UserInfoEndpoint:      d.issuer + "/userinfo",
		JWKSURI:               d.issuer + "/jwks.json",
		EndSessionEndpoint:    d.issuer + "/logout",
		ScopesSupported:       []string{"openid", "profile", "email"},
		ResponseTypes:         []string{"code"},
		SigningAlgValues:      []string{"RS256"},
		CodeChallengeMethods:  []string{"S256"},
	})
}

func (d *DevIdP) handleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := d.key.Public().(*rsa.PublicKey)
	writeJSON(w, http.StatusOK, JWKSet{Keys: []JWK{{
		Kty: "RSA", Kid: d.keyID, Use: "sig", Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

// handleAuthorize renders a account chooser, then issues an authorization code.
func (d *DevIdP) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	clientID := q.Get("client_id")
	client, ok := d.clients[clientID]
	if !ok {
		http.Error(w, "unknown client", http.StatusBadRequest)
		return
	}
	redirectURI := q.Get("redirect_uri")
	if !allowedRedirect(client.RedirectURIs, redirectURI) {
		// Never redirect to an unregistered URI: that is how authorization codes
		// get delivered to an attacker.
		http.Error(w, "redirect_uri is not registered for this client", http.StatusBadRequest)
		return
	}
	if q.Get("response_type") != "code" {
		redirectErr(w, r, redirectURI, "unsupported_response_type", q.Get("state"))
		return
	}
	challenge := q.Get("code_challenge")
	if challenge == "" || q.Get("code_challenge_method") != "S256" {
		redirectErr(w, r, redirectURI, "invalid_request", q.Get("state"))
		return
	}

	subject := q.Get("login_hint")
	if subject == "" {
		subject = q.Get("sf_user")
	}
	if subject == "" {
		d.renderChooser(w, r)
		return
	}

	user, found := d.userBySubject(subject)
	if !found {
		d.renderChooser(w, r)
		return
	}

	code := id.NewToken(24)
	d.mu.Lock()
	d.codes[code] = &devCode{
		User: user, ClientID: clientID, RedirectURI: redirectURI,
		Nonce: q.Get("nonce"), CodeChallenge: challenge, Method: "S256",
		IssuedAt: time.Now(),
	}
	d.gcCodesLocked()
	d.mu.Unlock()

	u, _ := url.Parse(redirectURI)
	rq := u.Query()
	rq.Set("code", code)
	if s := q.Get("state"); s != "" {
		rq.Set("state", s)
	}
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// renderChooser shows the seeded accounts so a developer can pick a role.
func (d *DevIdP) renderChooser(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var sb strings.Builder
	sb.WriteString(`<!doctype html><html><head><meta charset="utf-8">`)
	sb.WriteString(`<title>SpecForge development sign-in</title><style>`)
	sb.WriteString(`body{font:14px system-ui,sans-serif;max-width:640px;margin:64px auto;padding:0 16px;color:#111}`)
	sb.WriteString(`h1{font-size:20px}p{color:#555}ul{list-style:none;padding:0}`)
	sb.WriteString(`li{margin:6px 0}a{display:block;padding:10px 12px;border:1px solid #ddd;border-radius:6px;`)
	sb.WriteString(`text-decoration:none;color:#111}a:hover{background:#f6f6f6}small{color:#777}`)
	sb.WriteString(`.warn{background:#fff8e1;border:1px solid #ffe082;padding:10px;border-radius:6px}`)
	sb.WriteString(`</style></head><body>`)
	sb.WriteString(`<h1>SpecForge development sign-in</h1>`)
	sb.WriteString(`<p class="warn">This is the built-in development identity provider. `)
	sb.WriteString(`It is disabled in production.</p><ul>`)

	for _, u := range d.users {
		nq := url.Values{}
		for k, vs := range q {
			nq[k] = vs
		}
		nq.Set("sf_user", u.Subject)
		mfa := "single factor"
		if u.MFA {
			mfa = "MFA satisfied"
		}
		fmt.Fprintf(&sb, `<li><a href="/authorize?%s"><strong>%s</strong> <small>%s &middot; %s &middot; %s</small></a></li>`,
			nq.Encode(), html.EscapeString(u.Name), html.EscapeString(u.Email),
			html.EscapeString(strings.Join(u.Groups, ", ")), mfa)
	}
	sb.WriteString(`</ul></body></html>`)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(sb.String()))
}

func (d *DevIdP) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}

	code := r.PostForm.Get("code")
	d.mu.Lock()
	entry, ok := d.codes[code]
	if ok {
		if entry.Used || time.Since(entry.IssuedAt) > 60*time.Second {
			// A replayed or stale code invalidates the grant entirely.
			delete(d.codes, code)
			ok = false
		} else {
			entry.Used = true
		}
	}
	d.mu.Unlock()

	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	if !VerifyPKCE(r.PostForm.Get("code_verifier"), entry.CodeChallenge, entry.Method) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	if r.PostForm.Get("redirect_uri") != entry.RedirectURI {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}

	idToken, err := d.issueToken(entry.User, entry.ClientID, entry.Nonce, 8*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	accessToken, err := d.issueToken(entry.User, entry.ClientID, "", 1*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, TokenSet{
		AccessToken: accessToken, TokenType: "Bearer",
		ExpiresIn: 3600, IDToken: idToken, Scope: "openid profile email",
	})
}

func (d *DevIdP) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if raw == "" {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	src, err := d.KeySource()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	claims, err := Verify(raw, src, VerifyOptions{Issuer: d.issuer})
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	user, ok := d.userBySubject(claims.Subject)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sub": user.Subject, "email": user.Email, "email_verified": true,
		"name": user.Name, "groups": user.Groups,
		d.tenantClaim: user.TenantID, d.rolesClaim: user.Groups,
	})
}

func (d *DevIdP) handleLogout(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get("post_logout_redirect_uri")
	if redirect == "" {
		writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
		return
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (d *DevIdP) handleUsers(w http.ResponseWriter, r *http.Request) {
	// Report the tenant a token would actually carry, not the one configured at
	// startup — otherwise this endpoint is a way to be confidently misinformed.
	out := make([]DevUser, len(d.users))
	for i, u := range d.users {
		u.TenantID = d.tenantFor(u)
		out[i] = u
	}
	writeJSON(w, http.StatusOK, out)
}

// tenantFor resolves the tenant a token should name.
//
// The five-second cache keeps a burst of sign-ins from becoming a burst of
// queries, while staying short enough that a reseed during development is
// picked up before anyone notices.
func (d *DevIdP) tenantFor(u DevUser) string {
	if d.resolveTenant == nil {
		return u.TenantID
	}
	d.tenantMu.Lock()
	defer d.tenantMu.Unlock()
	if d.tenantCache != "" && time.Since(d.tenantCached) < 5*time.Second {
		return d.tenantCache
	}
	if resolved := d.resolveTenant(); resolved != "" {
		d.tenantCache, d.tenantCached = resolved, time.Now()
		return resolved
	}
	return u.TenantID
}

// issueToken mints an RS256-signed JWT.
func (d *DevIdP) issueToken(u DevUser, audience, nonce string, ttl time.Duration) (string, error) {
	now := time.Now()
	amr := []string{"pwd"}
	if u.MFA {
		amr = append(amr, "mfa", "otp")
	}
	claims := map[string]any{
		"iss": d.issuer, "sub": u.Subject, "aud": audience,
		"exp": now.Add(ttl).Unix(), "iat": now.Unix(), "nbf": now.Unix(),
		"auth_time": now.Unix(), "jti": id.NewToken(12),
		"email": u.Email, "email_verified": true, "name": u.Name,
		"amr": amr, "groups": u.Groups,
		d.tenantClaim: d.tenantFor(u),
		d.rolesClaim:  u.Groups,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return d.sign(Header{Alg: RS256, Typ: "JWT", Kid: d.keyID}, claims)
}

func (d *DevIdP) sign(h Header, claims map[string]any) (string, error) {
	hb, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("authn: encoding header: %w", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("authn: encoding claims: %w", err)
	}
	input := base64.RawURLEncoding.EncodeToString(hb) + "." +
		base64.RawURLEncoding.EncodeToString(cb)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, d.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("authn: signing token: %w", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// KeySource exposes the provider's public key for in-process verification,
// which lets tests verify real tokens without an HTTP round trip.
func (d *DevIdP) KeySource() (KeySource, error) {
	pub := d.key.Public().(*rsa.PublicKey)
	return NewStaticKeySource(JWKSet{Keys: []JWK{{
		Kty: "RSA", Kid: d.keyID, Use: "sig", Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

// IssueTokenFor mints a token for a seeded user. Test and seed helper only.
func (d *DevIdP) IssueTokenFor(subject, audience string, ttl time.Duration) (string, error) {
	u, ok := d.userBySubject(subject)
	if !ok {
		return "", fmt.Errorf("authn: unknown dev user %q", subject)
	}
	return d.issueToken(u, audience, "", ttl)
}

// Users returns the seeded identities.
func (d *DevIdP) Users() []DevUser { return d.users }

// Issuer returns the provider's issuer URL.
func (d *DevIdP) Issuer() string { return d.issuer }

func (d *DevIdP) userBySubject(sub string) (DevUser, bool) {
	for _, u := range d.users {
		if u.Subject == sub || u.Email == sub {
			return u, true
		}
	}
	return DevUser{}, false
}

// gcCodesLocked drops expired authorization codes. Callers hold d.mu.
func (d *DevIdP) gcCodesLocked() {
	for k, c := range d.codes {
		if time.Since(c.IssuedAt) > 5*time.Minute {
			delete(d.codes, k)
		}
	}
}

func allowedRedirect(registered []string, candidate string) bool {
	for _, r := range registered {
		if r == candidate {
			return true
		}
	}
	return false
}

func redirectErr(w http.ResponseWriter, r *http.Request, redirectURI, code, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, code, http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
