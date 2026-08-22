package authn

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// JWK is a JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`

	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// EC
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// JWKSet is a JSON Web Key Set.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// PublicKey converts a JWK into a crypto.PublicKey.
func (k JWK) PublicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("authn: decoding RSA modulus: %w", err)
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("authn: decoding RSA exponent: %w", err)
		}
		if len(e) > 8 {
			return nil, fmt.Errorf("authn: RSA exponent is too large")
		}
		var eb [8]byte
		copy(eb[8-len(e):], e)
		exp := int(binary.BigEndian.Uint64(eb[:]))
		if exp <= 0 {
			return nil, fmt.Errorf("authn: invalid RSA exponent")
		}
		key := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}
		if key.N.BitLen() < 2048 {
			// Below 2048 bits the signature is not a meaningful control.
			return nil, fmt.Errorf("authn: RSA key is %d bits; the minimum is 2048", key.N.BitLen())
		}
		return key, nil

	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("authn: unsupported EC curve %q", k.Crv)
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("authn: decoding EC x: %w", err)
		}
		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("authn: decoding EC y: %w", err)
		}
		key := &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}
		if !curve.IsOnCurve(key.X, key.Y) {
			// An off-curve point can leak private key material in some protocols;
			// rejecting it costs nothing.
			return nil, fmt.Errorf("authn: EC point is not on the declared curve")
		}
		return key, nil

	default:
		return nil, fmt.Errorf("authn: unsupported key type %q", k.Kty)
	}
}

// StaticKeySource serves keys from an in-memory set.
type StaticKeySource struct {
	keys map[string]crypto.PublicKey
	// single is used when the set holds exactly one key and the token omits kid.
	single crypto.PublicKey
}

var _ KeySource = (*StaticKeySource)(nil)

// NewStaticKeySource builds a key source from a key set.
func NewStaticKeySource(set JWKSet) (*StaticKeySource, error) {
	s := &StaticKeySource{keys: map[string]crypto.PublicKey{}}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := k.PublicKey()
		if err != nil {
			// One malformed key must not disable the whole set, but it is worth
			// surfacing, so it is skipped rather than fatal.
			continue
		}
		s.keys[k.Kid] = pub
		s.single = pub
	}
	if len(s.keys) == 0 {
		return nil, fmt.Errorf("authn: key set contains no usable signing keys")
	}
	if len(s.keys) > 1 {
		s.single = nil
	}
	return s, nil
}

func (s *StaticKeySource) PublicKey(kid string, _ Algorithm) (crypto.PublicKey, error) {
	if kid != "" {
		if k, ok := s.keys[kid]; ok {
			return k, nil
		}
		return nil, fmt.Errorf("authn: no key with id %q", kid)
	}
	if s.single != nil {
		return s.single, nil
	}
	return nil, fmt.Errorf("authn: token has no key id and the issuer publishes several keys")
}

// JWKSCache fetches and caches a remote key set.
//
// Rotation handling matters here: when a token presents an unknown kid, the
// cache refreshes once (rate limited) rather than rejecting the token, so a key
// rollover does not cause an outage. The rate limit stops an attacker from
// turning unknown kids into a request amplifier against the identity provider.
type JWKSCache struct {
	url    string
	ttl    time.Duration
	client *http.Client

	mu           sync.RWMutex
	source       *StaticKeySource
	fetchedAt    time.Time
	lastFailure  time.Time
	lastRefresh  time.Time
	minRefreshIn time.Duration
}

var _ KeySource = (*JWKSCache)(nil)

// NewJWKSCache creates a caching key source.
func NewJWKSCache(url string, ttl time.Duration) *JWKSCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &JWKSCache{
		url: url, ttl: ttl,
		minRefreshIn: 30 * time.Second,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        4,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 5 * time.Second,
			},
		},
	}
}

// Refresh fetches the key set.
func (c *JWKSCache) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return fmt.Errorf("authn: building JWKS request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		c.noteFailure()
		return fmt.Errorf("authn: fetching JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		c.noteFailure()
		return fmt.Errorf("authn: JWKS endpoint returned %s", resp.Status)
	}
	// Bound the response so a hostile or broken endpoint cannot exhaust memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		c.noteFailure()
		return fmt.Errorf("authn: reading JWKS: %w", err)
	}

	var set JWKSet
	if err := json.Unmarshal(body, &set); err != nil {
		c.noteFailure()
		return fmt.Errorf("authn: parsing JWKS: %w", err)
	}
	src, err := NewStaticKeySource(set)
	if err != nil {
		c.noteFailure()
		return err
	}

	c.mu.Lock()
	c.source = src
	c.fetchedAt = time.Now()
	c.lastRefresh = c.fetchedAt
	c.mu.Unlock()
	return nil
}

func (c *JWKSCache) noteFailure() {
	c.mu.Lock()
	c.lastFailure = time.Now()
	c.mu.Unlock()
}

func (c *JWKSCache) PublicKey(kid string, alg Algorithm) (crypto.PublicKey, error) {
	c.mu.RLock()
	src, fetched := c.source, c.fetchedAt
	c.mu.RUnlock()

	if src != nil && time.Since(fetched) < c.ttl {
		if key, err := src.PublicKey(kid, alg); err == nil {
			return key, nil
		}
		// Unknown kid with a fresh cache: the issuer probably rotated. Refresh.
	}

	c.mu.RLock()
	canRefresh := time.Since(c.lastRefresh) >= c.minRefreshIn
	c.mu.RUnlock()

	if canRefresh {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := c.Refresh(ctx)
		cancel()
		if err != nil && src == nil {
			return nil, err
		}
		c.mu.RLock()
		src = c.source
		c.mu.RUnlock()
	}

	if src == nil {
		return nil, fmt.Errorf("authn: no key set is available")
	}
	return src.PublicKey(kid, alg)
}

// Stale reports whether the cache is serving keys older than its TTL, for the
// readiness endpoint.
func (c *JWKSCache) Stale() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.source == nil || time.Since(c.fetchedAt) > c.ttl*3
}
