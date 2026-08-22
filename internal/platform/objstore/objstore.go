// Package objstore is the content and evidence store.
//
// Two properties matter more than throughput:
//
//   - Content addressing. Objects are keyed by their SHA-256 digest, so a write
//     is idempotent and a read can be verified. GetVerified refuses to return
//     bytes whose digest does not match the key.
//   - Write-once evidence. Approval evidence is written with object-lock
//     semantics. Evidence that can be overwritten is not evidence, so the store
//     refuses to replace a locked object even with identical-looking content.
package objstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/hash"
	"github.com/specforge/specforge/internal/platform/types"
)

// Object is a stored blob plus its metadata.
type Object struct {
	Key         string
	Digest      types.ContentHash
	Size        int64
	MediaType   string
	StoredAt    time.Time
	Locked      bool
	RetainUntil time.Time
	Metadata    map[string]string
}

// PutOptions controls a write.
type PutOptions struct {
	MediaType string
	Metadata  map[string]string
	// Lock applies write-once retention. Required for approval evidence.
	Lock        bool
	RetainUntil time.Time
}

// Store is the object storage port. Adapters: FS (local/dev), S3 (production).
type Store interface {
	// Put writes content-addressed bytes and returns the stored object.
	// Writing identical bytes to the same key is a successful no-op.
	Put(ctx context.Context, bucket string, data []byte, opts PutOptions) (Object, error)
	// PutAt writes to an explicit key rather than a content-derived one.
	PutAt(ctx context.Context, bucket, key string, data []byte, opts PutOptions) (Object, error)
	// Get returns the bytes at a key.
	Get(ctx context.Context, bucket, key string) ([]byte, Object, error)
	// GetVerified returns the bytes only if they hash to want.
	GetVerified(ctx context.Context, bucket, key string, want types.ContentHash) ([]byte, Object, error)
	// Stat returns metadata without the body.
	Stat(ctx context.Context, bucket, key string) (Object, error)
	// List enumerates keys under a prefix.
	List(ctx context.Context, bucket, prefix string, limit int) ([]Object, error)
	// Delete removes an object. Locked objects are refused.
	Delete(ctx context.Context, bucket, key string) error
	// Health checks reachability.
	Health(ctx context.Context) error
}

// TenantKey builds a tenant-scoped storage key. Every caller uses this, so a
// key cannot be constructed outside a tenant's prefix by accident.
func TenantKey(tenantID types.TenantID, projectID *types.ProjectID, suffix string) string {
	var sb strings.Builder
	sb.WriteString(tenantID.String())
	sb.WriteByte('/')
	if projectID != nil {
		sb.WriteString(projectID.String())
		sb.WriteByte('/')
	}
	sb.WriteString(strings.TrimPrefix(suffix, "/"))
	return sb.String()
}

// ContentKey builds a content-addressed key under a tenant prefix.
func ContentKey(tenantID types.TenantID, projectID *types.ProjectID, digest types.ContentHash) string {
	return TenantKey(tenantID, projectID, "content/"+hash.StorageKey(digest))
}

// ---------------------------------------------------------------------------
// Filesystem adapter
// ---------------------------------------------------------------------------

// FS stores objects on the local filesystem. Used for development, tests and
// single-node deployments. Object-lock is enforced by making locked files
// read-only and refusing overwrite and delete at the application layer.
type FS struct {
	root string
	mu   sync.RWMutex
}

var _ Store = (*FS)(nil)

// NewFS creates a filesystem-backed store rooted at dir.
func NewFS(dir string) (*FS, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("objstore: creating root %s: %w", dir, err)
	}
	return &FS{root: dir}, nil
}

func (f *FS) path(bucket, key string) (string, error) {
	if bucket == "" {
		return "", errors.Invalid("objstore.path", "objstore.bucket_required", "A bucket is required.")
	}
	clean := filepath.Clean("/" + key)
	if strings.Contains(clean, "..") {
		return "", errors.Invalid("objstore.path", "objstore.invalid_key",
			"Object key %q escapes the bucket.", key)
	}
	full := filepath.Join(f.root, bucket, clean)
	// Defence in depth: confirm the resolved path is inside the bucket even if
	// Clean behaved unexpectedly on some platform.
	base := filepath.Join(f.root, bucket)
	if !strings.HasPrefix(full, base+string(os.PathSeparator)) && full != base {
		return "", errors.Invalid("objstore.path", "objstore.invalid_key",
			"Object key %q escapes the bucket.", key)
	}
	return full, nil
}

func (f *FS) metaPath(p string) string { return p + ".meta.json" }

func (f *FS) Put(ctx context.Context, bucket string, data []byte, opts PutOptions) (Object, error) {
	digest := hash.ContentOfBytes(data)
	return f.PutAt(ctx, bucket, hash.StorageKey(digest), data, opts)
}

func (f *FS) PutAt(ctx context.Context, bucket, key string, data []byte, opts PutOptions) (Object, error) {
	const op = "objstore.Put"
	p, err := f.path(bucket, key)
	if err != nil {
		return Object{}, err
	}

	sum := sha256.Sum256(data)
	digest := types.ContentHash("sha256:" + hex.EncodeToString(sum[:]))

	f.mu.Lock()
	defer f.mu.Unlock()

	if existing, err := f.statLocked(bucket, key); err == nil {
		if existing.Locked {
			// Idempotent re-write of identical content is fine; anything else is
			// an attempt to mutate write-once evidence.
			if existing.Digest == digest {
				return existing, nil
			}
			return Object{}, errors.Forbidden(op, "objstore.object_locked",
				"Object %s is under retention until %s and cannot be modified.",
				key, existing.RetainUntil.Format(time.RFC3339))
		}
	}

	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return Object{}, errors.Wrap(err, op, errors.KindUnavailable, "objstore.write_failed",
			"Could not create the storage directory.")
	}

	// Write to a temporary file and rename, so a reader never sees a partial object.
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return Object{}, errors.Wrap(err, op, errors.KindUnavailable, "objstore.write_failed",
			"Could not create a temporary object file.")
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return Object{}, errors.Wrap(err, op, errors.KindUnavailable, "objstore.write_failed",
			"Could not write the object.")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return Object{}, errors.Wrap(err, op, errors.KindUnavailable, "objstore.write_failed",
			"Could not flush the object to disk.")
	}
	if err := tmp.Close(); err != nil {
		return Object{}, errors.Wrap(err, op, errors.KindUnavailable, "objstore.write_failed",
			"Could not close the object file.")
	}
	if err := os.Rename(tmpName, p); err != nil {
		return Object{}, errors.Wrap(err, op, errors.KindUnavailable, "objstore.write_failed",
			"Could not commit the object.")
	}

	obj := Object{
		Key: key, Digest: digest, Size: int64(len(data)),
		MediaType: opts.MediaType, StoredAt: types.Now(),
		Locked: opts.Lock, RetainUntil: opts.RetainUntil, Metadata: opts.Metadata,
	}
	if obj.MediaType == "" {
		obj.MediaType = "application/octet-stream"
	}

	meta, err := json.Marshal(obj)
	if err != nil {
		return Object{}, errors.Wrap(err, op, errors.KindInternal, "objstore.meta_failed",
			"Could not encode object metadata.")
	}
	if err := os.WriteFile(f.metaPath(p), meta, 0o640); err != nil {
		return Object{}, errors.Wrap(err, op, errors.KindUnavailable, "objstore.meta_failed",
			"Could not write object metadata.")
	}

	if opts.Lock {
		// Read-only on disk mirrors the object-lock behaviour of the S3 adapter.
		_ = os.Chmod(p, 0o440)
		_ = os.Chmod(f.metaPath(p), 0o440)
	}
	return obj, nil
}

func (f *FS) Get(ctx context.Context, bucket, key string) ([]byte, Object, error) {
	const op = "objstore.Get"
	p, err := f.path(bucket, key)
	if err != nil {
		return nil, Object{}, err
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, Object{}, errors.NotFound(op, "objstore.not_found",
				"Object %s was not found.", key)
		}
		return nil, Object{}, errors.Wrap(err, op, errors.KindUnavailable, "objstore.read_failed",
			"Could not read the object.")
	}
	obj, err := f.statLocked(bucket, key)
	if err != nil {
		// Metadata loss should not make content unreadable; reconstruct what we can.
		obj = Object{Key: key, Size: int64(len(data)), Digest: hash.ContentOfBytes(data)}
	}
	return data, obj, nil
}

func (f *FS) GetVerified(ctx context.Context, bucket, key string, want types.ContentHash) ([]byte, Object, error) {
	const op = "objstore.GetVerified"
	data, obj, err := f.Get(ctx, bucket, key)
	if err != nil {
		return nil, Object{}, err
	}
	got := hash.ContentOfBytes(data)
	if !hash.Equal(got, want) {
		// Failing closed here is the point: an unverifiable artifact body must
		// never be served, and this is a security event, not a cache miss.
		return nil, Object{}, errors.Tampered(op, "objstore.integrity_violation",
			"Stored object %s does not match its recorded digest.", key).
			WithDetail("expected", want.Short()).
			WithDetail("actual", got.Short())
	}
	return data, obj, nil
}

func (f *FS) Stat(ctx context.Context, bucket, key string) (Object, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.statLocked(bucket, key)
}

func (f *FS) statLocked(bucket, key string) (Object, error) {
	const op = "objstore.Stat"
	p, err := f.path(bucket, key)
	if err != nil {
		return Object{}, err
	}
	meta, err := os.ReadFile(f.metaPath(p))
	if err != nil {
		if os.IsNotExist(err) {
			return Object{}, errors.NotFound(op, "objstore.not_found",
				"Object %s was not found.", key)
		}
		return Object{}, errors.Wrap(err, op, errors.KindUnavailable, "objstore.read_failed",
			"Could not read object metadata.")
	}
	var obj Object
	if err := json.Unmarshal(meta, &obj); err != nil {
		return Object{}, errors.Wrap(err, op, errors.KindInternal, "objstore.meta_corrupt",
			"Object metadata is unreadable.")
	}
	return obj, nil
}

func (f *FS) List(ctx context.Context, bucket, prefix string, limit int) ([]Object, error) {
	const op = "objstore.List"
	base, err := f.path(bucket, prefix)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	var out []Object
	root := filepath.Join(f.root, bucket)
	err = filepath.Walk(base, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.IsDir() || strings.HasSuffix(p, ".meta.json") || strings.Contains(filepath.Base(p), ".tmp-") {
			return nil
		}
		if len(out) >= limit {
			return io.EOF
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return nil
		}
		obj, statErr := f.statLocked(bucket, filepath.ToSlash(rel))
		if statErr != nil {
			obj = Object{Key: filepath.ToSlash(rel), Size: info.Size(), StoredAt: info.ModTime()}
		}
		out = append(out, obj)
		return nil
	})
	if err != nil && err != io.EOF {
		return nil, errors.Wrap(err, op, errors.KindUnavailable, "objstore.list_failed",
			"Could not list objects.")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (f *FS) Delete(ctx context.Context, bucket, key string) error {
	const op = "objstore.Delete"
	p, err := f.path(bucket, key)
	if err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	obj, err := f.statLocked(bucket, key)
	if err == nil && obj.Locked && time.Now().Before(obj.RetainUntil) {
		return errors.Forbidden(op, "objstore.object_locked",
			"Object %s is under retention until %s and cannot be deleted.",
			key, obj.RetainUntil.Format(time.RFC3339))
	}
	_ = os.Chmod(p, 0o640)
	_ = os.Chmod(f.metaPath(p), 0o640)
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return errors.Wrap(err, op, errors.KindUnavailable, "objstore.delete_failed",
			"Could not delete the object.")
	}
	_ = os.Remove(f.metaPath(p))
	return nil
}

func (f *FS) Health(ctx context.Context) error {
	probe := filepath.Join(f.root, ".health")
	if err := os.WriteFile(probe, []byte("ok"), 0o640); err != nil {
		return fmt.Errorf("objstore: health check write: %w", err)
	}
	return os.Remove(probe)
}
