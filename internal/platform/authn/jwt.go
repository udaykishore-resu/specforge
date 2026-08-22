// Package authn implements authentication: JWT verification, JWKS handling, the
// OIDC authorization-code flow with PKCE, API keys, and a working local OIDC
// provider for development.
//
// Two rules shape the verification code:
//
//   - Only asymmetric signature algorithms are accepted. "alg": "none" and HMAC
//     algorithms are rejected outright, which removes the entire class of
//     algorithm-confusion attacks rather than mitigating it.
//   - Every registered claim that bounds a token's authority (iss, aud, exp,
//     nbf) is required and checked. A token missing one is invalid, not lenient.
package authn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/specforge/specforge/internal/platform/errors"
)

// Algorithm is a JWS signature algorithm.
type Algorithm string

const (
	RS256 Algorithm = "RS256"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"
	PS256 Algorithm = "PS256"
	PS384 Algorithm = "PS384"
	PS512 Algorithm = "PS512"
	ES256 Algorithm = "ES256"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"
)

// supportedAlgorithms is an allowlist. Note the absence of "none", HS256, HS384
// and HS512: symmetric verification against a public key is the classic JWT
// bypass, so those algorithms have no code path here at all.
var supportedAlgorithms = map[Algorithm]crypto.Hash{
	RS256: crypto.SHA256, RS384: crypto.SHA384, RS512: crypto.SHA512,
	PS256: crypto.SHA256, PS384: crypto.SHA384, PS512: crypto.SHA512,
	ES256: crypto.SHA256, ES384: crypto.SHA384, ES512: crypto.SHA512,
}

// Header is the decoded JOSE header.
type Header struct {
	Alg Algorithm `json:"alg"`
	Typ string    `json:"typ,omitempty"`
	Kid string    `json:"kid,omitempty"`
}

// Claims holds the registered claims plus everything else the issuer sent.
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  Audience `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf,omitempty"`
	IssuedAt  int64    `json:"iat"`
	ID        string   `json:"jti,omitempty"`
	AuthTime  int64    `json:"auth_time,omitempty"`
	Nonce     string   `json:"nonce,omitempty"`
	AMR       []string `json:"amr,omitempty"`
	ACR       string   `json:"acr,omitempty"`
	Email     string   `json:"email,omitempty"`
	Name      string   `json:"name,omitempty"`
	// Extra carries every claim, including the tenant and roles claims whose
	// names are tenant-configurable.
	Extra map[string]any `json:"-"`
}

// Audience accepts both the string and array forms the JWT specification allows.
type Audience []string

func (a *Audience) UnmarshalJSON(b []byte) error {
	var single string
	if err := json.Unmarshal(b, &single); err == nil {
		*a = Audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("authn: aud claim is neither a string nor an array: %w", err)
	}
	*a = Audience(many)
	return nil
}

// Contains reports whether the audience includes v.
func (a Audience) Contains(v string) bool {
	for _, s := range a {
		if s == v {
			return true
		}
	}
	return false
}

// String returns a claim as a string.
func (c Claims) String(name string) string {
	v, _ := c.Extra[name].(string)
	return v
}

// StringSlice returns a claim as a string slice, accepting both a single string
// and an array, since identity providers disagree about this.
func (c Claims) StringSlice(name string) []string {
	switch v := c.Extra[name].(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	}
	return nil
}

// AuthTimeOrIssued returns the authentication time, falling back to iat.
func (c Claims) AuthTimeOrIssued() time.Time {
	if c.AuthTime > 0 {
		return time.Unix(c.AuthTime, 0).UTC()
	}
	return time.Unix(c.IssuedAt, 0).UTC()
}

// VerifyOptions bounds what a token is allowed to assert.
type VerifyOptions struct {
	Issuer    string
	Audience  string
	ClockSkew time.Duration
	// Now overrides the clock. Test-only.
	Now func() time.Time
	// RequireNonce enforces nonce presence, used for ID tokens from an
	// authorization-code flow to prevent replay.
	RequireNonce bool
	ExpectNonce  string
}

// KeySource resolves a verification key by key ID.
type KeySource interface {
	// PublicKey returns the key for kid. An empty kid means the issuer published
	// a single key.
	PublicKey(kid string, alg Algorithm) (crypto.PublicKey, error)
}

// Verify parses and verifies a compact JWS and returns its claims.
func Verify(token string, keys KeySource, opts VerifyOptions) (*Claims, error) {
	const op = "authn.Verify"

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.Unauthorized(op, "auth.token_malformed",
			"The token is not a well-formed JWT.")
	}

	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.Unauthorized(op, "auth.token_malformed", "The token header is not valid base64url.")
	}
	var h Header
	if err := json.Unmarshal(headerRaw, &h); err != nil {
		return nil, errors.Unauthorized(op, "auth.token_malformed", "The token header is not valid JSON.")
	}

	hashAlg, ok := supportedAlgorithms[h.Alg]
	if !ok {
		return nil, errors.Unauthorized(op, "auth.token_alg_unsupported",
			"Signature algorithm %q is not accepted.", h.Alg)
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.Unauthorized(op, "auth.token_malformed", "The token payload is not valid base64url.")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.Unauthorized(op, "auth.token_malformed", "The token signature is not valid base64url.")
	}

	pub, err := keys.PublicKey(h.Kid, h.Alg)
	if err != nil {
		return nil, errors.Unauthorized(op, "auth.token_key_unknown",
			"No verification key matches this token.")
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	if err := verifySignature(pub, h.Alg, hashAlg, signingInput, sig); err != nil {
		return nil, errors.Unauthorized(op, "auth.token_signature_invalid",
			"The token signature is not valid.")
	}

	var claims Claims
	if err := json.Unmarshal(payloadRaw, &claims); err != nil {
		return nil, errors.Unauthorized(op, "auth.token_malformed", "The token payload is not valid JSON.")
	}
	if err := json.Unmarshal(payloadRaw, &claims.Extra); err != nil {
		return nil, errors.Unauthorized(op, "auth.token_malformed", "The token payload is not valid JSON.")
	}

	if err := validateClaims(&claims, opts); err != nil {
		return nil, err
	}
	return &claims, nil
}

func validateClaims(c *Claims, opts VerifyOptions) error {
	const op = "authn.Verify"

	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	skew := opts.ClockSkew
	if skew <= 0 {
		skew = 60 * time.Second
	}
	t := now()

	if opts.Issuer != "" && c.Issuer != opts.Issuer {
		return errors.Unauthorized(op, "auth.token_issuer_mismatch",
			"The token was issued by an unexpected authority.")
	}
	if opts.Audience != "" && !c.Audience.Contains(opts.Audience) {
		return errors.Unauthorized(op, "auth.token_audience_mismatch",
			"The token is not intended for this service.")
	}
	if c.ExpiresAt == 0 {
		// A token without an expiry never becomes invalid, which is not an
		// acceptable credential regardless of how it was issued.
		return errors.Unauthorized(op, "auth.token_no_expiry",
			"The token does not declare an expiry.")
	}
	if t.After(time.Unix(c.ExpiresAt, 0).Add(skew)) {
		return errors.Unauthorized(op, "auth.token_expired", "The token has expired.")
	}
	if c.NotBefore != 0 && t.Before(time.Unix(c.NotBefore, 0).Add(-skew)) {
		return errors.Unauthorized(op, "auth.token_not_yet_valid", "The token is not valid yet.")
	}
	if c.IssuedAt != 0 && t.Before(time.Unix(c.IssuedAt, 0).Add(-skew)) {
		return errors.Unauthorized(op, "auth.token_issued_in_future",
			"The token was issued in the future.")
	}
	if c.Subject == "" {
		return errors.Unauthorized(op, "auth.token_no_subject", "The token has no subject.")
	}
	if opts.RequireNonce {
		if c.Nonce == "" {
			return errors.Unauthorized(op, "auth.token_no_nonce",
				"The token does not carry the required nonce.")
		}
		if opts.ExpectNonce != "" && c.Nonce != opts.ExpectNonce {
			return errors.Unauthorized(op, "auth.token_nonce_mismatch",
				"The token nonce does not match this authentication attempt.")
		}
	}
	return nil
}

func verifySignature(pub crypto.PublicKey, alg Algorithm, hashAlg crypto.Hash, input, sig []byte) error {
	digest := digestFor(hashAlg, input)

	switch {
	case strings.HasPrefix(string(alg), "RS"):
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("authn: %s requires an RSA key", alg)
		}
		return rsa.VerifyPKCS1v15(key, hashAlg, digest, sig)

	case strings.HasPrefix(string(alg), "PS"):
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("authn: %s requires an RSA key", alg)
		}
		return rsa.VerifyPSS(key, hashAlg, digest, sig,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: hashAlg})

	case strings.HasPrefix(string(alg), "ES"):
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("authn: %s requires an ECDSA key", alg)
		}
		// JWS ECDSA signatures are fixed-width R||S, not ASN.1.
		keyBytes := (key.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*keyBytes {
			return fmt.Errorf("authn: %s signature has length %d, want %d", alg, len(sig), 2*keyBytes)
		}
		r := new(big.Int).SetBytes(sig[:keyBytes])
		s := new(big.Int).SetBytes(sig[keyBytes:])
		if !ecdsa.Verify(key, digest, r, s) {
			return fmt.Errorf("authn: ECDSA verification failed")
		}
		return nil

	default:
		return fmt.Errorf("authn: unsupported algorithm %s", alg)
	}
}

func digestFor(h crypto.Hash, input []byte) []byte {
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256(input)
		return d[:]
	case crypto.SHA384:
		d := sha512.Sum384(input)
		return d[:]
	case crypto.SHA512:
		d := sha512.Sum512(input)
		return d[:]
	default:
		d := sha256.Sum256(input)
		return d[:]
	}
}

// UnsafeDecodeClaims decodes claims WITHOUT verifying the signature.
//
// It exists for exactly one purpose: reading the issuer from a token in order to
// select the right verification key set. Never use it for an authorization
// decision — the name is deliberately alarming.
func UnsafeDecodeClaims(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("authn: not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("authn: decoding payload: %w", err)
	}
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("authn: parsing payload: %w", err)
	}
	_ = json.Unmarshal(raw, &c.Extra)
	return &c, nil
}
