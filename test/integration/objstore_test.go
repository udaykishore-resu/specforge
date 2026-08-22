package integration

// Object store conformance.
//
// Two adapters back the same interface, and the moment there are two, the risk
// stops being "does it work" and becomes "do they agree". So the assertions
// below run against both, from one table: a behaviour that holds for the
// filesystem store and not the database store is a bug in whichever one is
// wrong, and this is what says so.
//
// The write-once assertions matter most. Approval evidence that can be
// overwritten is not evidence, and the guarantee is only as good as the last
// test that tried to break it.

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/specforge/specforge/internal/platform/db/migrate"
	"github.com/specforge/specforge/internal/platform/db/pgwire"
	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/hash"
	"github.com/specforge/specforge/internal/platform/log"
	"github.com/specforge/specforge/internal/platform/objstore"
)

func objstoreAdapters(t *testing.T) map[string]objstore.Store {
	t.Helper()

	dsn := os.Getenv("SF_TEST_DSN")
	if dsn == "" {
		t.Skip("SF_TEST_DSN not set; skipping integration tests")
	}

	sdb, err := sql.Open(pgwire.DriverName, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	sdb.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = sdb.Close() })

	migrations, err := migrate.Load(repoPath(t, "migrations"))
	if err != nil {
		t.Fatalf("loading migrations: %v", err)
	}
	logger := log.New(log.Options{Level: "error", Format: "text", Output: os.Stderr})
	if _, err := migrate.New(sdb, logger).Up(context.Background(), migrations); err != nil {
		t.Fatalf("applying migrations: %v", err)
	}

	// The filesystem root sits inside a sandbox directory so the traversal
	// assertion can check that nothing was written above it.
	sandbox := t.TempDir()
	fsRoot := filepath.Join(sandbox, "root")
	fs, err := objstore.NewFS(fsRoot)
	if err != nil {
		t.Fatalf("fs store: %v", err)
	}
	fsSandbox = sandbox
	return map[string]objstore.Store{
		"fs": fs,
		"db": objstore.NewPostgres(sdb),
	}
}

// fsSandbox is the directory containing the filesystem store's root, so a test
// can assert that a traversal key wrote nothing outside it.
var fsSandbox string

func TestObjectStoreConformance(t *testing.T) {
	ctx := context.Background()

	for name, store := range objstoreAdapters(t) {
		t.Run(name, func(t *testing.T) {
			// Keys are namespaced per adapter and per run so a re-run against a
			// database that already holds rows does not collide with itself.
			prefix := "conformance/" + name + "/" + hash.ContentOfBytes(
				[]byte(t.Name()+time.Now().Format(time.RFC3339Nano))).Short() + "/"
			body := []byte(`{"artifact":"REQ-1","title":"Refunds"}`)
			digest := hash.ContentOfBytes(body)

			t.Run("put is content addressed and round-trips", func(t *testing.T) {
				obj, err := store.Put(ctx, "sf-content", body, objstore.PutOptions{
					MediaType: "application/json",
					Metadata:  map[string]string{"artifact_id": "REQ-1"},
				})
				if err != nil {
					t.Fatalf("put: %v", err)
				}
				if obj.Digest != digest {
					t.Fatalf("digest %s, want %s", obj.Digest, digest)
				}
				if obj.Size != int64(len(body)) {
					t.Fatalf("size %d, want %d", obj.Size, len(body))
				}

				got, meta, err := store.Get(ctx, "sf-content", obj.Key)
				if err != nil {
					t.Fatalf("get: %v", err)
				}
				if !bytes.Equal(got, body) {
					t.Fatalf("body round-trip mismatch: %q", got)
				}
				if meta.MediaType != "application/json" {
					t.Fatalf("media type %q", meta.MediaType)
				}
			})

			t.Run("get verified fails closed on the wrong digest", func(t *testing.T) {
				obj, err := store.Put(ctx, "sf-content", body, objstore.PutOptions{})
				if err != nil {
					t.Fatalf("put: %v", err)
				}
				if _, _, err := store.GetVerified(ctx, "sf-content", obj.Key, digest); err != nil {
					t.Fatalf("verified get of matching content: %v", err)
				}
				wrong := hash.ContentOfBytes([]byte("something else entirely"))
				_, _, err = store.GetVerified(ctx, "sf-content", obj.Key, wrong)
				if err == nil {
					t.Fatal("a digest mismatch was served rather than refused")
				}
				if errors.KindOf(err) != errors.KindTampered {
					t.Fatalf("kind %v, want Tampered — a mismatch is a security event, not a miss",
						errors.KindOf(err))
				}
			})

			t.Run("missing keys are not found", func(t *testing.T) {
				_, _, err := store.Get(ctx, "sf-content", prefix+"absent")
				if errors.KindOf(err) != errors.KindNotFound {
					t.Fatalf("kind %v, want NotFound", errors.KindOf(err))
				}
			})

			// ---- write-once ------------------------------------------------

			evidenceKey := prefix + "evidence/approval"
			evidence := []byte(`{"evidence_id":"EVD-1","approver":"alice"}`)
			retain := time.Now().Add(7 * 24 * time.Hour)

			t.Run("locked evidence is written once", func(t *testing.T) {
				if _, err := store.PutAt(ctx, "sf-evidence", evidenceKey, evidence,
					objstore.PutOptions{
						MediaType: "application/vnd.specforge.approval+json",
						Lock:      true, RetainUntil: retain,
					}); err != nil {
					t.Fatalf("put evidence: %v", err)
				}

				// Identical bytes: a retried approval must not fail merely for
				// being a retry.
				if _, err := store.PutAt(ctx, "sf-evidence", evidenceKey, evidence,
					objstore.PutOptions{Lock: true, RetainUntil: retain}); err != nil {
					t.Fatalf("identical re-write of locked evidence was refused: %v", err)
				}

				// One byte different: refused.
				tampered := []byte(`{"evidence_id":"EVD-1","approver":"mallory"}`)
				_, err := store.PutAt(ctx, "sf-evidence", evidenceKey, tampered,
					objstore.PutOptions{Lock: true, RetainUntil: retain})
				if err == nil {
					t.Fatal("LOCKED EVIDENCE WAS OVERWRITTEN")
				}
				if errors.KindOf(err) != errors.KindForbidden {
					t.Fatalf("kind %v, want Forbidden (%v)", errors.KindOf(err), err)
				}

				// And the original survived the attempt.
				got, _, err := store.Get(ctx, "sf-evidence", evidenceKey)
				if err != nil {
					t.Fatalf("get after refused overwrite: %v", err)
				}
				if !bytes.Equal(got, evidence) {
					t.Fatalf("evidence changed despite the refusal: %q", got)
				}
			})

			t.Run("locked evidence cannot be deleted", func(t *testing.T) {
				err := store.Delete(ctx, "sf-evidence", evidenceKey)
				if err == nil {
					t.Fatal("LOCKED EVIDENCE WAS DELETED")
				}
				if errors.KindOf(err) != errors.KindForbidden {
					t.Fatalf("kind %v, want Forbidden (%v)", errors.KindOf(err), err)
				}
				if _, err := store.Stat(ctx, "sf-evidence", evidenceKey); err != nil {
					t.Fatalf("evidence went missing after a refused delete: %v", err)
				}
			})

			t.Run("unlocked content can be deleted", func(t *testing.T) {
				key := prefix + "content/scratch"
				if _, err := store.PutAt(ctx, "sf-content", key, []byte("scratch"),
					objstore.PutOptions{}); err != nil {
					t.Fatalf("put: %v", err)
				}
				if err := store.Delete(ctx, "sf-content", key); err != nil {
					t.Fatalf("delete of unlocked content: %v", err)
				}
				if _, err := store.Stat(ctx, "sf-content", key); errors.KindOf(err) != errors.KindNotFound {
					t.Fatalf("kind %v, want NotFound after delete", errors.KindOf(err))
				}
			})

			t.Run("stat reports the lock and its retention", func(t *testing.T) {
				obj, err := store.Stat(ctx, "sf-evidence", evidenceKey)
				if err != nil {
					t.Fatalf("stat: %v", err)
				}
				if !obj.Locked {
					t.Fatal("evidence does not report itself as locked")
				}
				if obj.RetainUntil.Before(time.Now()) {
					t.Fatalf("retention %s is already in the past", obj.RetainUntil)
				}
			})

			t.Run("list is scoped to its prefix", func(t *testing.T) {
				for _, n := range []string{"a", "b", "c"} {
					if _, err := store.PutAt(ctx, "sf-content", prefix+"list/"+n,
						[]byte("body-"+n), objstore.PutOptions{}); err != nil {
						t.Fatalf("put %s: %v", n, err)
					}
				}
				out, err := store.List(ctx, "sf-content", prefix+"list/", 100)
				if err != nil {
					t.Fatalf("list: %v", err)
				}
				if len(out) != 3 {
					t.Fatalf("listed %d objects, want 3", len(out))
				}
				for _, o := range out {
					if !strings.Contains(o.Key, prefix+"list/") {
						t.Fatalf("list returned %q, which is outside the prefix", o.Key)
					}
				}
			})

			t.Run("buckets are separate namespaces", func(t *testing.T) {
				key := prefix + "same-key"
				if _, err := store.PutAt(ctx, "sf-content", key, []byte("content side"),
					objstore.PutOptions{}); err != nil {
					t.Fatalf("put content: %v", err)
				}
				if _, err := store.PutAt(ctx, "sf-evidence", key, []byte("evidence side"),
					objstore.PutOptions{}); err != nil {
					t.Fatalf("put evidence: %v", err)
				}
				got, _, err := store.Get(ctx, "sf-content", key)
				if err != nil {
					t.Fatalf("get: %v", err)
				}
				if string(got) != "content side" {
					t.Fatalf("bucket bleed: sf-content/%s returned %q", key, got)
				}
			})

			t.Run("a traversal key cannot write outside the bucket", func(t *testing.T) {
				// Neither adapter has to refuse the key. What neither may do is
				// let it land outside the store: the filesystem adapter cleans
				// the path into the bucket, and the database adapter has no
				// filesystem to escape into. This asserts the outcome rather
				// than the mechanism, because the mechanism differs.
				_, err := store.PutAt(ctx, "sf-content", "../../escaped",
					[]byte("nope"), objstore.PutOptions{})
				if err != nil && errors.KindOf(err) != errors.KindInvalid {
					t.Fatalf("kind %v, want Invalid if it refuses at all (%v)",
						errors.KindOf(err), err)
				}
				if name != "fs" {
					return
				}
				var escaped []string
				_ = filepath.Walk(fsSandbox, func(p string, info os.FileInfo, walkErr error) error {
					if walkErr != nil || info.IsDir() {
						return nil
					}
					// Anything not under <sandbox>/root escaped the store.
					if !strings.HasPrefix(p, filepath.Join(fsSandbox, "root")+string(os.PathSeparator)) {
						escaped = append(escaped, p)
					}
					return nil
				})
				if len(escaped) > 0 {
					t.Fatalf("A TRAVERSAL KEY WROTE OUTSIDE THE STORE: %v", escaped)
				}
			})
		})
	}
}

// TestLockedEvidenceRequiresRetention guards the case that would silently
// create an object locked forever: a lock with no retention date.
func TestLockedEvidenceRequiresRetention(t *testing.T) {
	ctx := context.Background()
	for name, store := range objstoreAdapters(t) {
		if name != "db" {
			continue
		}
		_, err := store.PutAt(ctx, "sf-evidence", "conformance/no-retention",
			[]byte("x"), objstore.PutOptions{Lock: true})
		if err == nil {
			t.Fatal("a locked object was accepted with no retention date")
		}
		if errors.KindOf(err) != errors.KindInvalid {
			t.Fatalf("kind %v, want Invalid (%v)", errors.KindOf(err), err)
		}
	}
}
