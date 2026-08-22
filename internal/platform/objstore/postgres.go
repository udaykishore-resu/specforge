package objstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/hash"
	"github.com/specforge/specforge/internal/platform/types"
)

// Postgres stores objects in the database.
//
// This is the adapter to reach for when there is no object store to point at —
// a laptop, a single-node deployment, an air-gapped install — and it is not a
// lesser one. Write-once retention is enforced by a trigger in migration 0005,
// so a locked object survives an application bug, a stray migration and a
// direct psql session alike. The filesystem adapter enforces the same rule in
// application code, which is a weaker place to enforce it.
//
// The trade-off is size. Blobs live in a bytea column, so this is right for
// artifact content and evidence documents (kilobytes) and wrong for large
// binaries. PutAt refuses anything over MaxObjectBytes rather than letting a
// caller discover the limit as a slow query months later.
type Postgres struct {
	db *sql.DB
}

var _ Store = (*Postgres)(nil)

// MaxObjectBytes bounds a single stored object. Artifact content and evidence
// documents are JSON in the low kilobytes; a megabyte is generous, and a
// deployment that needs more should be pointed at a real object store.
const MaxObjectBytes = 1 << 20

// NewPostgres builds a database-backed store.
//
// It takes *sql.DB rather than the platform's *db.DB deliberately: the store is
// used from paths that are not inside a tenant transaction (evidence is written
// before the sealing transaction opens), and taking the raw handle makes that
// visible at the call site instead of implying a tenant scope that is not there.
func NewPostgres(sdb *sql.DB) *Postgres { return &Postgres{db: sdb} }

// tenantFromKey extracts the tenant id that objstore.TenantKey placed at the
// front of the key. It is recorded on the row so that cross-tenant access is
// visible in a query, and so that a tenant's objects can be found without
// pattern-matching keys.
func tenantFromKey(key string) any {
	head, _, found := strings.Cut(strings.TrimPrefix(key, "/"), "/")
	if !found {
		return nil
	}
	if _, err := types.ParseTenantID(head); err != nil {
		return nil
	}
	return head
}

func (p *Postgres) Put(ctx context.Context, bucket string, data []byte, opts PutOptions) (Object, error) {
	digest := hash.ContentOfBytes(data)
	return p.PutAt(ctx, bucket, hash.StorageKey(digest), data, opts)
}

func (p *Postgres) PutAt(ctx context.Context, bucket, key string, data []byte, opts PutOptions) (Object, error) {
	const op = "objstore.Put"

	if bucket == "" {
		return Object{}, errors.Invalid(op, "objstore.bucket_required", "A bucket is required.")
	}
	if key == "" {
		return Object{}, errors.Invalid(op, "objstore.invalid_key", "An object key is required.")
	}
	if len(data) > MaxObjectBytes {
		return Object{}, errors.Invalid(op, "objstore.too_large",
			"Object %s is %d bytes; the database-backed store holds at most %d.",
			key, len(data), MaxObjectBytes)
	}

	sum := sha256.Sum256(data)
	digest := types.ContentHash("sha256:" + hex.EncodeToString(sum[:]))

	mediaType := opts.MediaType
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	meta := opts.Metadata
	if meta == nil {
		meta = map[string]string{}
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return Object{}, errors.Wrap(err, op, errors.KindInternal, "objstore.meta_failed",
			"Could not encode object metadata.")
	}

	var retain any
	if opts.Lock {
		until := opts.RetainUntil
		if until.IsZero() {
			return Object{}, errors.Invalid(op, "objstore.retention_required",
				"A locked object needs a retention date; %s was given none.", key)
		}
		retain = until.UTC()
	}

	// ON CONFLICT makes an identical re-write a no-op, which is what the
	// approval path needs when a request is retried. A conflicting write to a
	// locked key reaches the UPDATE and the trigger refuses it — the refusal
	// belongs in the database, not in a pre-flight SELECT that a concurrent
	// writer could race.
	const q = `
		INSERT INTO objects
		    (bucket, key, tenant_id, digest, size_bytes, media_type, body, metadata,
		     locked, retain_until, stored_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())
		ON CONFLICT (bucket, key) DO UPDATE SET
		    digest       = EXCLUDED.digest,
		    size_bytes   = EXCLUDED.size_bytes,
		    media_type   = EXCLUDED.media_type,
		    body         = EXCLUDED.body,
		    metadata     = EXCLUDED.metadata,
		    locked       = objects.locked OR EXCLUDED.locked,
		    retain_until = GREATEST(objects.retain_until, EXCLUDED.retain_until)
		RETURNING stored_at, locked, retain_until`

	var storedAt time.Time
	var locked bool
	var retainUntil sql.NullTime

	err = p.db.QueryRowContext(ctx, q,
		bucket, key, tenantFromKey(key), digest.String(), len(data), mediaType,
		data, string(metaJSON), opts.Lock, retain,
	).Scan(&storedAt, &locked, &retainUntil)
	if err != nil {
		if isObjectLocked(err) {
			return Object{}, errors.Forbidden(op, "objstore.object_locked",
				"Object %s is write-once and cannot be modified.", key)
		}
		return Object{}, errors.Wrap(err, op, errors.KindUnavailable, "objstore.write_failed",
			"Could not write the object.")
	}

	return Object{
		Key: key, Digest: digest, Size: int64(len(data)), MediaType: mediaType,
		StoredAt: storedAt.UTC(), Locked: locked,
		RetainUntil: retainUntil.Time.UTC(), Metadata: meta,
	}, nil
}

// isObjectLocked reports whether err is the write-once trigger refusing.
//
// The trigger raises with SQLSTATE 23514, which the driver surfaces in the
// message. Matching on the message rather than a typed error is deliberate: the
// alternative is exposing the driver's error type through this package, and the
// refusal text is asserted by TestPostgresObjectLock so a change to it fails a
// test rather than silently turning a refusal into a 503.
func isObjectLocked(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "under retention") ||
		strings.Contains(msg, "cannot be modified") ||
		strings.Contains(msg, "lock on")
}

func (p *Postgres) Get(ctx context.Context, bucket, key string) ([]byte, Object, error) {
	const op = "objstore.Get"

	var (
		body        []byte
		digest      string
		size        int64
		mediaType   string
		metaJSON    []byte
		locked      bool
		retainUntil sql.NullTime
		storedAt    time.Time
	)
	err := p.db.QueryRowContext(ctx, `
		SELECT body, digest, size_bytes, media_type, metadata, locked, retain_until, stored_at
		  FROM objects WHERE bucket = $1 AND key = $2`, bucket, key).
		Scan(&body, &digest, &size, &mediaType, &metaJSON, &locked, &retainUntil, &storedAt)
	if err == sql.ErrNoRows {
		return nil, Object{}, errors.NotFound(op, "objstore.not_found",
			"Object %s was not found.", key)
	}
	if err != nil {
		return nil, Object{}, errors.Wrap(err, op, errors.KindUnavailable, "objstore.read_failed",
			"Could not read the object.")
	}

	meta := map[string]string{}
	_ = json.Unmarshal(metaJSON, &meta)

	return body, Object{
		Key: key, Digest: types.ContentHash(digest), Size: size, MediaType: mediaType,
		StoredAt: storedAt.UTC(), Locked: locked,
		RetainUntil: retainUntil.Time.UTC(), Metadata: meta,
	}, nil
}

func (p *Postgres) GetVerified(ctx context.Context, bucket, key string, want types.ContentHash) ([]byte, Object, error) {
	const op = "objstore.GetVerified"
	data, obj, err := p.Get(ctx, bucket, key)
	if err != nil {
		return nil, Object{}, err
	}
	got := hash.ContentOfBytes(data)
	if !hash.Equal(got, want) {
		// Fail closed. Unverifiable bytes are a security event, not a cache miss.
		return nil, Object{}, errors.Tampered(op, "objstore.integrity_violation",
			"Stored object %s does not match its recorded digest.", key).
			WithDetail("expected", want.Short()).
			WithDetail("actual", got.Short())
	}
	return data, obj, nil
}

func (p *Postgres) Stat(ctx context.Context, bucket, key string) (Object, error) {
	const op = "objstore.Stat"

	var (
		digest      string
		size        int64
		mediaType   string
		metaJSON    []byte
		locked      bool
		retainUntil sql.NullTime
		storedAt    time.Time
	)
	err := p.db.QueryRowContext(ctx, `
		SELECT digest, size_bytes, media_type, metadata, locked, retain_until, stored_at
		  FROM objects WHERE bucket = $1 AND key = $2`, bucket, key).
		Scan(&digest, &size, &mediaType, &metaJSON, &locked, &retainUntil, &storedAt)
	if err == sql.ErrNoRows {
		return Object{}, errors.NotFound(op, "objstore.not_found",
			"Object %s was not found.", key)
	}
	if err != nil {
		return Object{}, errors.Wrap(err, op, errors.KindUnavailable, "objstore.read_failed",
			"Could not read object metadata.")
	}

	meta := map[string]string{}
	_ = json.Unmarshal(metaJSON, &meta)

	return Object{
		Key: key, Digest: types.ContentHash(digest), Size: size, MediaType: mediaType,
		StoredAt: storedAt.UTC(), Locked: locked,
		RetainUntil: retainUntil.Time.UTC(), Metadata: meta,
	}, nil
}

func (p *Postgres) List(ctx context.Context, bucket, prefix string, limit int) ([]Object, error) {
	const op = "objstore.List"
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}

	rows, err := p.db.QueryContext(ctx, `
		SELECT key, digest, size_bytes, media_type, metadata, locked, retain_until, stored_at
		  FROM objects
		 WHERE bucket = $1 AND key LIKE $2 || '%'
		 ORDER BY key
		 LIMIT $3`, bucket, prefix, limit)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.KindUnavailable, "objstore.list_failed",
			"Could not list objects.")
	}
	defer func() { _ = rows.Close() }()

	var out []Object
	for rows.Next() {
		var (
			key, digest, mediaType string
			size                   int64
			metaJSON               []byte
			locked                 bool
			retainUntil            sql.NullTime
			storedAt               time.Time
		)
		if err := rows.Scan(&key, &digest, &size, &mediaType, &metaJSON,
			&locked, &retainUntil, &storedAt); err != nil {
			return nil, errors.Wrap(err, op, errors.KindUnavailable, "objstore.list_failed",
				"Could not read an object row.")
		}
		meta := map[string]string{}
		_ = json.Unmarshal(metaJSON, &meta)
		out = append(out, Object{
			Key: key, Digest: types.ContentHash(digest), Size: size, MediaType: mediaType,
			StoredAt: storedAt.UTC(), Locked: locked,
			RetainUntil: retainUntil.Time.UTC(), Metadata: meta,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, op, errors.KindUnavailable, "objstore.list_failed",
			"Could not list objects.")
	}
	return out, nil
}

func (p *Postgres) Delete(ctx context.Context, bucket, key string) error {
	const op = "objstore.Delete"
	_, err := p.db.ExecContext(ctx,
		`DELETE FROM objects WHERE bucket = $1 AND key = $2`, bucket, key)
	if err != nil {
		if isObjectLocked(err) {
			return errors.Forbidden(op, "objstore.object_locked",
				"Object %s is under retention and cannot be deleted.", key)
		}
		return errors.Wrap(err, op, errors.KindUnavailable, "objstore.delete_failed",
			"Could not delete the object.")
	}
	return nil
}

func (p *Postgres) Health(ctx context.Context) error {
	return p.db.PingContext(ctx)
}
