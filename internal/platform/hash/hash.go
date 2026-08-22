// Package hash provides the content addressing and chain hashing primitives.
//
// Two distinct constructions live here and must not be confused:
//
//   - Content(v) pins an artifact version to its canonical bytes. Verified on
//     every read; a mismatch is an integrity violation, not a cache miss.
//   - Chain(prev, payload) links audit records so that any retroactive edit
//     invalidates every subsequent record.
package hash

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/specforge/specforge/internal/platform/jcs"
	"github.com/specforge/specforge/internal/platform/types"
)

// ZeroChainHash is the genesis value of every tenant's audit chain.
const ZeroChainHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Content returns the canonical content hash of v as "sha256:<hex>".
func Content(v any) (types.ContentHash, error) {
	canonical, err := jcs.Canonicalize(v)
	if err != nil {
		return "", fmt.Errorf("hash: canonicalizing content: %w", err)
	}
	return ContentOfBytes(canonical), nil
}

// ContentOfJSON hashes an existing JSON document after canonicalizing it.
func ContentOfJSON(raw []byte) (types.ContentHash, error) {
	canonical, err := jcs.CanonicalizeJSON(raw)
	if err != nil {
		return "", fmt.Errorf("hash: canonicalizing JSON: %w", err)
	}
	return ContentOfBytes(canonical), nil
}

// ContentOfBytes hashes bytes that are already in canonical form.
func ContentOfBytes(canonical []byte) types.ContentHash {
	sum := sha256.Sum256(canonical)
	return types.ContentHash("sha256:" + hex.EncodeToString(sum[:]))
}

// Verify reports whether v hashes to want. Comparison is constant time so that
// a verification endpoint cannot be used as a timing oracle.
func Verify(v any, want types.ContentHash) (bool, error) {
	got, err := Content(v)
	if err != nil {
		return false, err
	}
	return Equal(got, want), nil
}

// VerifyJSON reports whether a JSON document hashes to want.
func VerifyJSON(raw []byte, want types.ContentHash) (bool, error) {
	got, err := ContentOfJSON(raw)
	if err != nil {
		return false, err
	}
	return Equal(got, want), nil
}

// Equal compares two content hashes in constant time.
func Equal(a, b types.ContentHash) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Chain computes the next audit chain hash: SHA-256(prev || canonical(payload)).
//
// prev is the hex chain head (64 lowercase hex characters, ZeroChainHash for the
// first record). Including the previous hash in the digest is what makes the
// chain tamper-evident: editing record n changes its hash, so every record after
// it fails verification.
func Chain(prev string, payload []byte) (string, error) {
	prevBytes, err := hex.DecodeString(prev)
	if err != nil || len(prevBytes) != sha256.Size {
		return "", fmt.Errorf("hash: invalid previous chain hash %q", prev)
	}
	h := sha256.New()
	h.Write(prevBytes)
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ChainOf canonicalizes v and chains it onto prev.
func ChainOf(prev string, v any) (string, error) {
	canonical, err := jcs.Canonicalize(v)
	if err != nil {
		return "", fmt.Errorf("hash: canonicalizing audit payload: %w", err)
	}
	return Chain(prev, canonical)
}

// ValidChainHash reports whether s is a well-formed chain hash.
func ValidChainHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Sum returns the raw SHA-256 hex digest of b, without the "sha256:" prefix.
// Used for object storage keys and evidence digests.
func Sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// StorageKey renders a content-addressed object storage key.
func StorageKey(h types.ContentHash) string {
	hex := strings.TrimPrefix(string(h), "sha256:")
	if len(hex) < 4 {
		return hex
	}
	// Two levels of fan-out keeps directory listings tractable in filesystem-backed
	// stores and spreads keys across S3 partitions.
	return hex[0:2] + "/" + hex[2:4] + "/" + hex
}
