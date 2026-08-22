package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/specforge/specforge/internal/platform/errors"
)

// ProviderMetadata is the OpenID Connect discovery document.
type ProviderMetadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	EndSessionEndpoint    string   `json:"end_session_endpoint,omitempty"`
	ScopesSupported       []string `json:"scopes_supported,omitempty"`
	ResponseTypes         []string `json:"response_types_supported,omitempty"`
	SigningAlgValues      []string `json:"id_token_signing_alg_values_supported,omitempty"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported,omitempty"`
}

// TokenSet is the token endpoint response.
type TokenSet struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// IdentityProvider is the port every identity backend implements.
//
// The interface is deliberately protocol-neutral: a SAML adapter implements the
// same five operations, so adding SAML support does not touch anything above
// this package.
type IdentityProvider interface {
	Metadata(ctx context.Context) (*ProviderMetadata, error)
	AuthorizeURL(state, nonce, codeChallenge string, extra url.Values) (string, error)
	Exchange(ctx context.Context, code, codeVerifier string) (*TokenSet, error)
	Verify(ctx context.Context, rawIDToken string, expectNonce string) (*Claims, error)
	UserInfo(ctx context.Context, accessToken string) (*Claims, error)
	EndSessionURL(idTokenHint, postLogoutRedirect string) string
}

// OIDCConfig configures the OIDC client.
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	Audience     string
	ClockSkew    time.Duration
	JWKSTTL      time.Duration
	HTTPClient   *http.Client
}

// OIDCProvider implements IdentityProvider over OpenID Connect.
type OIDCProvider struct {
	cfg    OIDCConfig
	client *http.Client

	mu       sync.RWMutex
	meta     *ProviderMetadata
	metaTime time.Time
	keys     *JWKSCache
}

var _ IdentityProvider = (*OIDCProvider)(nil)

// NewOIDCProvider builds a provider and performs discovery.
func NewOIDCProvider(ctx context.Context, cfg OIDCConfig) (*OIDCProvider, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("authn: OIDC issuer is required")
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = 60 * time.Second
	}
	if cfg.JWKSTTL <= 0 {
		cfg.JWKSTTL = 5 * time.Minute
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	p := &OIDCProvider{cfg: cfg, client: client}
	meta, err := p.Metadata(ctx)
	if err != nil {
		return nil, err
	}
	p.keys = NewJWKSCache(meta.JWKSURI, cfg.JWKSTTL)
	if err := p.keys.Refresh(ctx); err != nil {
		return nil, fmt.Errorf("authn: loading issuer keys: %w", err)
	}
	return p, nil
}

// Metadata fetches (and caches for an hour) the discovery document.
func (p *OIDCProvider) Metadata(ctx context.Context) (*ProviderMetadata, error) {
	p.mu.RLock()
	if p.meta != nil && time.Since(p.metaTime) < time.Hour {
		defer p.mu.RUnlock()
		return p.meta, nil
	}
	p.mu.RUnlock()

	discoveryURL := strings.TrimRight(p.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("authn: building discovery request: %w", err)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authn: OIDC discovery: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authn: OIDC discovery returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("authn: reading discovery document: %w", err)
	}
	var meta ProviderMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, fmt.Errorf("authn: parsing discovery document: %w", err)
	}
	// The issuer in the document must match the configured issuer, or an
	// attacker who can redirect discovery could substitute their own authority.
	if meta.Issuer != p.cfg.Issuer {
		return nil, fmt.Errorf("authn: discovery issuer %q does not match the configured issuer %q",
			meta.Issuer, p.cfg.Issuer)
	}

	p.mu.Lock()
	p.meta = &meta
	p.metaTime = time.Now()
	p.mu.Unlock()
	return &meta, nil
}

// AuthorizeURL builds the authorization request. PKCE is mandatory.
func (p *OIDCProvider) AuthorizeURL(state, nonce, codeChallenge string, extra url.Values) (string, error) {
	meta, err := p.Metadata(context.Background())
	if err != nil {
		return "", err
	}
	if state == "" || nonce == "" || codeChallenge == "" {
		return "", fmt.Errorf("authn: state, nonce and PKCE challenge are all required")
	}

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURL)
	q.Set("scope", strings.Join(p.cfg.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	for k, vs := range extra {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	return meta.AuthorizationEndpoint + "?" + q.Encode(), nil
}

// Exchange trades an authorization code for tokens.
func (p *OIDCProvider) Exchange(ctx context.Context, code, codeVerifier string) (*TokenSet, error) {
	const op = "authn.Exchange"
	meta, err := p.Metadata(ctx)
	if err != nil {
		return nil, err
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", p.cfg.RedirectURL)
	form.Set("client_id", p.cfg.ClientID)
	form.Set("code_verifier", codeVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.TokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("authn: building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.cfg.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.cfg.ClientSecret))
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.KindUnavailable, "auth.idp_unreachable",
			"The identity provider could not be reached.")
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("authn: reading token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// The upstream error body may echo the code; do not surface it verbatim.
		return nil, errors.Unauthorized(op, "auth.code_exchange_failed",
			"The authorization code could not be exchanged.")
	}
	var ts TokenSet
	if err := json.Unmarshal(body, &ts); err != nil {
		return nil, fmt.Errorf("authn: parsing token response: %w", err)
	}
	if ts.IDToken == "" {
		return nil, errors.Unauthorized(op, "auth.no_id_token",
			"The identity provider did not return an ID token.")
	}
	return &ts, nil
}

// Verify validates an ID token, including the nonce binding.
func (p *OIDCProvider) Verify(ctx context.Context, rawIDToken, expectNonce string) (*Claims, error) {
	return Verify(rawIDToken, p.keys, VerifyOptions{
		Issuer:       p.cfg.Issuer,
		Audience:     p.audience(),
		ClockSkew:    p.cfg.ClockSkew,
		RequireNonce: expectNonce != "",
		ExpectNonce:  expectNonce,
	})
}

// VerifyAccessToken validates a bearer access token presented to the API.
func (p *OIDCProvider) VerifyAccessToken(ctx context.Context, raw string) (*Claims, error) {
	return Verify(raw, p.keys, VerifyOptions{
		Issuer:    p.cfg.Issuer,
		Audience:  p.audience(),
		ClockSkew: p.cfg.ClockSkew,
	})
}

func (p *OIDCProvider) audience() string {
	if p.cfg.Audience != "" {
		return p.cfg.Audience
	}
	return p.cfg.ClientID
}

// UserInfo fetches the userinfo claims.
func (p *OIDCProvider) UserInfo(ctx context.Context, accessToken string) (*Claims, error) {
	meta, err := p.Metadata(ctx)
	if err != nil {
		return nil, err
	}
	if meta.UserInfoEndpoint == "" {
		return nil, fmt.Errorf("authn: the issuer publishes no userinfo endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, meta.UserInfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("authn: building userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authn: fetching userinfo: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authn: userinfo returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("authn: reading userinfo: %w", err)
	}
	var c Claims
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, fmt.Errorf("authn: parsing userinfo: %w", err)
	}
	_ = json.Unmarshal(body, &c.Extra)
	return &c, nil
}

// EndSessionURL builds the RP-initiated logout URL.
func (p *OIDCProvider) EndSessionURL(idTokenHint, postLogoutRedirect string) string {
	meta, err := p.Metadata(context.Background())
	if err != nil || meta.EndSessionEndpoint == "" {
		return postLogoutRedirect
	}
	q := url.Values{}
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}
	if postLogoutRedirect != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirect)
	}
	q.Set("client_id", p.cfg.ClientID)
	return meta.EndSessionEndpoint + "?" + q.Encode()
}

// ---------------------------------------------------------------------------
// PKCE
// ---------------------------------------------------------------------------

// PKCE holds a code verifier and its S256 challenge.
type PKCE struct {
	Verifier  string
	Challenge string
}

// NewPKCE generates a PKCE pair (RFC 7636). S256 only: the "plain" method
// offers no protection against an intercepted authorization code.
func NewPKCE() (PKCE, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return PKCE{}, fmt.Errorf("authn: generating PKCE verifier: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	return PKCE{
		Verifier:  verifier,
		Challenge: base64.RawURLEncoding.EncodeToString(sum[:]),
	}, nil
}

// VerifyPKCE checks a verifier against a challenge.
func VerifyPKCE(verifier, challenge, method string) bool {
	if method != "S256" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
}

// NewStateNonce generates the CSRF state and replay nonce for a login attempt.
func NewStateNonce() (state, nonce string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("authn: generating state: %w", err)
	}
	state = base64.RawURLEncoding.EncodeToString(b[:16])
	nonce = base64.RawURLEncoding.EncodeToString(b[16:])
	return state, nonce, nil
}
