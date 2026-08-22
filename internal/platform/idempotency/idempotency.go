// Package idempotency makes mutating requests safe to retry.
//
// Records live in PostgreSQL rather than the cache, so a replay still resolves
// correctly after a cache flush or a failover. That matters most for the
// operations this platform cares about: an approval that a client retried after
// a timeout must not seal a second version.
package idempotency

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/specforge/specforge/internal/platform/db"
	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/obs"
	"github.com/specforge/specforge/internal/platform/types"
)

// TTL is how long a completed record is replayable.
const TTL = 24 * time.Hour

// Record is a stored idempotent response.
type Record struct {
	Key         string
	RequestHash string
	Status      string // IN_PROGRESS | COMPLETED
	HTTPStatus  int
	Body        []byte
	CompletedAt *time.Time
}

// Store persists idempotency records.
type Store struct{ db *db.DB }

// NewStore builds the store.
func NewStore(database *db.DB) *Store { return &Store{db: database} }

// HashRequest fingerprints a request body so a repeated key with different
// content can be rejected rather than silently returning the wrong response.
func HashRequest(method, path string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte{0})
	h.Write([]byte(path))
	h.Write([]byte{0})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// Begin claims a key.
//
// Returns replay=true with the stored response when the same key and body have
// already completed. Returns a conflict when the same key arrives with a
// different body, or while an earlier attempt is still in flight.
func (s *Store) Begin(ctx context.Context, key, requestHash string) (rec *Record, replay bool, err error) {
	const op = "idempotency.Begin"

	tc, err := db.MustTenant(ctx)
	if err != nil {
		return nil, false, err
	}

	err = s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		var (
			existingHash  string
			status        string
			httpStatus    *int64
			body          []byte
			completedAt   *time.Time
			expires       time.Time
			foundExisting bool
		)
		row := tx.QueryRowContext(ctx, `
			SELECT request_hash, status, http_status, response_body, completed_at, expires_at
			  FROM idempotency_keys
			 WHERE tenant_id = $1 AND key = $2
			 FOR UPDATE`, tc.TenantID.String(), key)

		scanErr := row.Scan(&existingHash, &status, &httpStatus, &body, &completedAt, &expires)
		switch {
		case scanErr == nil:
			foundExisting = true
		case db.IsNoRows(scanErr):
			foundExisting = false
		default:
			return errors.Wrap(scanErr, op, errors.KindUnavailable, "idempotency.read_failed",
				"Could not read the idempotency record.")
		}

		if foundExisting && time.Now().After(expires) {
			// Expired: treat as a fresh key.
			if _, delErr := tx.ExecContext(ctx,
				`DELETE FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`,
				tc.TenantID.String(), key); delErr != nil {
				return errors.Wrap(delErr, op, errors.KindUnavailable, "idempotency.write_failed",
					"Could not clear the expired idempotency record.")
			}
			foundExisting = false
		}

		if foundExisting {
			if existingHash != requestHash {
				return errors.Conflict(op, "idempotency.key_reuse",
					"This Idempotency-Key was already used with a different request body.")
			}
			if status == "IN_PROGRESS" {
				return errors.Conflict(op, "idempotency.in_progress",
					"An identical request is still being processed. Retry shortly.")
			}
			rec = &Record{Key: key, RequestHash: existingHash, Status: status, Body: body, CompletedAt: completedAt}
			if httpStatus != nil {
				rec.HTTPStatus = int(*httpStatus)
			}
			replay = true
			return nil
		}

		principal := tc.PrincipalID
		if principal == "" {
			principal = types.PrincipalID("00000000-0000-4000-8000-000000000000")
		}
		if _, insErr := tx.ExecContext(ctx, `
			INSERT INTO idempotency_keys (tenant_id, key, request_hash, status, principal_id, expires_at)
			VALUES ($1, $2, $3, 'IN_PROGRESS', $4, $5)`,
			tc.TenantID.String(), key, requestHash, principal.String(),
			time.Now().Add(TTL)); insErr != nil {
			if db.IsUniqueViolation(insErr) {
				// Another request claimed the key between our read and insert.
				return errors.Conflict(op, "idempotency.in_progress",
					"An identical request is still being processed. Retry shortly.")
			}
			return errors.Wrap(insErr, op, errors.KindUnavailable, "idempotency.write_failed",
				"Could not record the idempotency key.")
		}
		rec = &Record{Key: key, RequestHash: requestHash, Status: "IN_PROGRESS"}
		return nil
	})
	if err != nil {
		return nil, false, err
	}

	if replay {
		obs.Counter("sf_idempotency_replays_total", "Idempotent request replays", nil)
	}
	return rec, replay, nil
}

// Complete stores the final response for replay.
func (s *Store) Complete(ctx context.Context, key string, status int, body []byte) error {
	const op = "idempotency.Complete"

	tc, err := db.MustTenant(ctx)
	if err != nil {
		return err
	}
	// Do not store enormous bodies; a replay of a large export is better served
	// by re-running the request than by duplicating megabytes per key.
	if len(body) > 256*1024 {
		body = nil
	}
	return s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE idempotency_keys
			   SET status = 'COMPLETED', http_status = $3, response_body = $4, completed_at = now()
			 WHERE tenant_id = $1 AND key = $2`,
			tc.TenantID.String(), key, int64(status), body)
		if err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "idempotency.write_failed",
				"Could not store the idempotent response.")
		}
		return nil
	})
}

// Abandon releases a key after a failure, so the client can retry immediately
// rather than waiting out the in-progress window.
func (s *Store) Abandon(ctx context.Context, key string) error {
	tc, err := db.MustTenant(ctx)
	if err != nil {
		return err
	}
	return s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.ExecContext(ctx,
			`DELETE FROM idempotency_keys WHERE tenant_id = $1 AND key = $2 AND status = 'IN_PROGRESS'`,
			tc.TenantID.String(), key)
		return err
	})
}

// Middleware applies idempotency to mutating requests.
//
// Requests without an Idempotency-Key are passed through: the header is required
// by the API contract for mutations, and the route handlers that must have one
// enforce it, but the middleware does not silently invent keys.
func Middleware(store *Store, required bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			key := r.Header.Get("Idempotency-Key")
			if key == "" {
				if required {
					writeProblem(w, errors.Invalid("idempotency.Middleware",
						"idempotency.key_required",
						"An Idempotency-Key header is required for this request."))
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			if len(key) > 255 {
				writeProblem(w, errors.Invalid("idempotency.Middleware",
					"idempotency.key_too_long", "The Idempotency-Key must be at most 255 characters."))
				return
			}
			// The handler chain reads the body; buffering here would duplicate
			// that work, so the request hash is computed by the handler wrapper
			// in server wiring, which already has the decoded body.
			next.ServeHTTP(w, r)
		})
	}
}

func writeProblem(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(errors.HTTPStatus(err))
	_, _ = w.Write([]byte(`{"code":"` + errors.CodeOf(err) + `","detail":"` + errors.MessageOf(err) + `"}`))
}

// GC removes expired records. Run from the worker's scheduler.
func (s *Store) GC(ctx context.Context) (int64, error) {
	res, err := s.db.SQL().ExecContext(ctx,
		`DELETE FROM idempotency_keys WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
