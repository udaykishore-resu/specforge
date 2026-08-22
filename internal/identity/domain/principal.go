// Package domain holds the identity aggregates.
package domain

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/specforge/specforge/internal/platform/authz"
	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/types"
)

// Principal is an authenticated actor: a person, a service account, or the
// platform itself.
type Principal struct {
	ID          types.PrincipalID
	TenantID    types.TenantID
	Kind        authz.PrincipalKind
	Issuer      string
	Subject     string
	Email       string
	DisplayName string
	Status      string // ACTIVE | DISABLED
	Attributes  map[string]any
	LastLoginAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Version     int64
}

// Active reports whether the principal may authenticate.
func (p *Principal) Active() bool { return p.Status == "ACTIVE" }

// NewPrincipal constructs an active principal.
func NewPrincipal(id types.PrincipalID, tenantID types.TenantID, kind authz.PrincipalKind,
	issuer, subject, email, display string) (*Principal, error) {

	const op = "identity.NewPrincipal"

	if issuer == "" || subject == "" {
		return nil, errors.Invalid(op, "principal.identity_required",
			"A principal must carry an issuer and a subject.")
	}
	now := types.Now()
	return &Principal{
		ID: id, TenantID: tenantID, Kind: kind,
		Issuer: issuer, Subject: subject, Email: email, DisplayName: display,
		Status: "ACTIVE", Attributes: map[string]any{},
		CreatedAt: now, UpdatedAt: now, Version: 1,
	}, nil
}

// RoleAssignment grants a role at tenant or project scope.
type RoleAssignment struct {
	ID          string
	TenantID    types.TenantID
	PrincipalID types.PrincipalID
	// ProjectID is empty for a tenant-wide grant.
	ProjectID string
	Role      authz.Role
	GrantedBy types.PrincipalID
	GrantedAt time.Time
	ExpiresAt *time.Time
}

// Active reports whether the grant is currently in force.
func (r *RoleAssignment) Active(now time.Time) bool {
	return r.ExpiresAt == nil || now.Before(*r.ExpiresAt)
}

// APIKey is a service-account credential.
type APIKey struct {
	ID          string
	TenantID    types.TenantID
	KeyID       string
	PrincipalID types.PrincipalID
	Name        string
	SecretHash  string
	Permissions []string
	ProjectID   string
	CreatedBy   types.PrincipalID
	CreatedAt   time.Time
	ExpiresAt   *time.Time
	RevokedAt   *time.Time
	LastUsedAt  *time.Time
}

// keyPrefix distinguishes SpecForge keys in logs and secret scanners.
const keyPrefix = "sf"

// NewAPIKey mints a key and returns the plaintext secret exactly once.
//
// Approval permissions are refused at construction (SoD-6). A credential that
// can be copied into a CI configuration must never be able to approve anything.
func NewAPIKey(id string, tenantID types.TenantID, principalID types.PrincipalID,
	name, env, projectID string, permissions []string, by types.PrincipalID,
	expiresAt *time.Time) (*APIKey, string, error) {

	const op = "identity.NewAPIKey"

	if name == "" {
		return nil, "", errors.Invalid(op, "apikey.name_required", "An API key name is required.")
	}
	set, err := authz.FromNames(permissions)
	if err != nil {
		return nil, "", errors.Invalid(op, "apikey.permissions_invalid", "%s", err.Error())
	}
	for _, n := range authz.ApprovalPermissionNames() {
		p, _ := authz.ParsePermission(n)
		if set.Has(p) {
			return nil, "", errors.Forbidden(op, "sod.violation",
				"An API key cannot hold the %s permission.", n)
		}
	}
	if expiresAt == nil {
		// An API key with no expiry is a permanent credential; require one.
		return nil, "", errors.Invalid(op, "apikey.expiry_required",
			"An API key must declare an expiry.")
	}
	if expiresAt.After(time.Now().AddDate(1, 0, 0)) {
		return nil, "", errors.Invalid(op, "apikey.expiry_too_far",
			"An API key may not be valid for more than one year.")
	}

	keyID := randomToken(6)
	secret := randomToken(24)
	plaintext := fmt.Sprintf("%s_%s_%s_%s", keyPrefix, env, keyID, secret)

	return &APIKey{
		ID: id, TenantID: tenantID, KeyID: keyID, PrincipalID: principalID,
		Name: name, SecretHash: hashSecret(secret), Permissions: permissions,
		ProjectID: projectID, CreatedBy: by, CreatedAt: types.Now(),
		ExpiresAt: expiresAt,
	}, plaintext, nil
}

// ParseAPIKey splits a presented key into its identifier and secret.
func ParseAPIKey(presented string) (keyID, secret string, ok bool) {
	parts := strings.Split(presented, "_")
	if len(parts) != 4 || parts[0] != keyPrefix {
		return "", "", false
	}
	return parts[2], parts[3], true
}

// Verify checks a presented secret in constant time and confirms the key is live.
func (k *APIKey) Verify(secret string, now time.Time) error {
	const op = "identity.VerifyAPIKey"

	if subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(k.SecretHash)) != 1 {
		return errors.Unauthorized(op, "auth.api_key_invalid", "The API key is not valid.")
	}
	if k.RevokedAt != nil {
		return errors.Unauthorized(op, "auth.api_key_revoked", "The API key has been revoked.")
	}
	if k.ExpiresAt != nil && now.After(*k.ExpiresAt) {
		return errors.Unauthorized(op, "auth.api_key_expired", "The API key has expired.")
	}
	return nil
}

// hashSecret derives the stored verifier.
//
// A high-entropy random secret is not password material, so a salted SHA-256 is
// the right construction here: the input has 192 bits of entropy, which makes
// an offline guessing attack irrelevant and a slow KDF pure latency on every
// API request.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte("specforge/apikey/v1|" + secret))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("identity: crypto/rand unavailable: %v", err))
	}
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(b), "=")
}

// IdPRoleMapping maps an identity-provider group onto a platform role.
type IdPRoleMapping struct {
	ID             string
	TenantID       types.TenantID
	IdPGroup       string
	Role           authz.Role
	ProjectKey     string
	MappingVersion int
	CreatedBy      types.PrincipalID
	CreatedAt      time.Time
}

// MapGroups resolves identity-provider groups to grants.
//
// Unmapped groups grant nothing. That is the important half: a customer adding
// a group in their directory must not silently acquire platform access.
func MapGroups(groups []string, mappings []IdPRoleMapping) []authz.Grant {
	byGroup := make(map[string][]IdPRoleMapping, len(mappings))
	for _, m := range mappings {
		byGroup[strings.ToLower(m.IdPGroup)] = append(byGroup[strings.ToLower(m.IdPGroup)], m)
	}

	var grants []authz.Grant
	seen := map[string]bool{}
	for _, g := range groups {
		for _, m := range byGroup[strings.ToLower(g)] {
			key := string(m.Role) + "|" + m.ProjectKey
			if seen[key] {
				continue
			}
			seen[key] = true
			grants = append(grants, authz.Grant{Role: m.Role, ProjectID: m.ProjectKey})
		}
	}
	return grants
}
