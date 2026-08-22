-- 0005_object_store.sql
-- Database-backed object storage with genuine write-once retention.
--
-- SpecForge stores three kinds of blob: canonical artifact content, approval
-- evidence, and audit anchors. The last two must be write-once, and "write-once"
-- has to be a property of the store rather than a promise made by the code that
-- writes to it — evidence that the application can overwrite is not evidence.
--
-- S3 Object Lock provides that in a cloud deployment. This table provides it
-- here, by the same mechanism the rest of the platform uses for immutability: a
-- trigger that refuses the write, so an application bug, a stray migration or a
-- direct psql session all hit the same wall.
--
-- See docs/architecture/12-data-architecture.md.

BEGIN;

CREATE TABLE objects (
  bucket       text        NOT NULL,
  key          text        NOT NULL,
  tenant_id    uuid,
  digest       text        NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
  size_bytes   bigint      NOT NULL CHECK (size_bytes >= 0),
  media_type   text        NOT NULL DEFAULT 'application/octet-stream',
  body         bytea       NOT NULL,
  metadata     jsonb       NOT NULL DEFAULT '{}'::jsonb,
  locked       boolean     NOT NULL DEFAULT false,
  retain_until timestamptz,
  stored_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (bucket, key),

  -- A locked object without a retention date would be locked forever by
  -- accident rather than by policy. Make the policy explicit at write time.
  CONSTRAINT objects_lock_needs_retention
    CHECK (NOT locked OR retain_until IS NOT NULL)
);

COMMENT ON TABLE objects IS
  'Content-addressed blob storage. Locked rows are write-once until retain_until.';

-- Listing is by prefix within a bucket, which is what the pattern index serves.
CREATE INDEX objects_bucket_key_idx ON objects (bucket, key text_pattern_ops);
CREATE INDEX objects_tenant_idx     ON objects (tenant_id) WHERE tenant_id IS NOT NULL;
CREATE INDEX objects_locked_idx     ON objects (retain_until) WHERE locked;

-- ---------------------------------------------------------------------------
-- Write-once enforcement.
--
-- Re-writing byte-for-byte identical content to a locked key is allowed and is
-- a no-op: the approval path is idempotent, and a retried request must not fail
-- merely because it is a retry. Changing so much as one byte is refused.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION sf_enforce_object_lock() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.locked AND (OLD.retain_until IS NULL OR now() < OLD.retain_until) THEN
    IF NEW.digest IS DISTINCT FROM OLD.digest
       OR NEW.body IS DISTINCT FROM OLD.body
       OR NEW.bucket IS DISTINCT FROM OLD.bucket
       OR NEW.key IS DISTINCT FROM OLD.key THEN
      RAISE EXCEPTION
        'object %/% is under retention until % and cannot be modified',
        OLD.bucket, OLD.key, OLD.retain_until
        USING ERRCODE = '23514',
              HINT = 'Write-once storage. Store a new object instead of replacing this one.';
    END IF;

    -- Retention may be extended, never shortened. Shortening it is the first
    -- move of anyone trying to delete evidence legitimately.
    IF NEW.retain_until < OLD.retain_until THEN
      RAISE EXCEPTION
        'retention on %/% cannot be shortened (% -> %)',
        OLD.bucket, OLD.key, OLD.retain_until, NEW.retain_until
        USING ERRCODE = '23514';
    END IF;

    IF NOT NEW.locked THEN
      RAISE EXCEPTION 'the lock on %/% cannot be removed', OLD.bucket, OLD.key
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER objects_write_once
  BEFORE UPDATE ON objects
  FOR EACH ROW EXECUTE FUNCTION sf_enforce_object_lock();

CREATE OR REPLACE FUNCTION sf_forbid_locked_object_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.locked AND (OLD.retain_until IS NULL OR now() < OLD.retain_until) THEN
    RAISE EXCEPTION
      'object %/% is under retention until % and cannot be deleted',
      OLD.bucket, OLD.key, OLD.retain_until
      USING ERRCODE = '23514';
  END IF;
  RETURN OLD;
END $$;

CREATE TRIGGER objects_no_delete_while_locked
  BEFORE DELETE ON objects
  FOR EACH ROW EXECUTE FUNCTION sf_forbid_locked_object_delete();

-- ---------------------------------------------------------------------------
-- Tenant scoping.
--
-- Be precise about what this does and does not give you, because a policy that
-- looks stronger than it is, is worse than none.
--
-- The object store is not accessed through the tenant-scoped transaction path:
-- content and evidence are written before the sealing transaction opens, by
-- design, so those connections carry no app.tenant_id. Primary isolation is
-- therefore the key prefix, which every caller is forced through by
-- objstore.TenantKey — the same guarantee the filesystem adapter gives.
--
-- What the policy below adds is a second boundary for the case that matters
-- most: a query that IS running inside a tenant transaction cannot reach
-- another tenant's objects, whatever key it asks for. Outside such a
-- transaction the store sees everything, which is what lets the store work at
-- all, and is why tenant_id is recorded on every row: it makes cross-tenant
-- reads detectable in the audit trail and greppable in a review.
-- ---------------------------------------------------------------------------
ALTER TABLE objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE objects FORCE ROW LEVEL SECURITY;

CREATE POLICY objects_tenant_isolation ON objects
  USING (
    sf_current_tenant() IS NULL
    OR tenant_id IS NULL
    OR tenant_id = sf_current_tenant()
  )
  WITH CHECK (
    sf_current_tenant() IS NULL
    OR tenant_id IS NULL
    OR tenant_id = sf_current_tenant()
  );

GRANT SELECT, INSERT, UPDATE ON objects TO sf_app;
-- DELETE is granted so unlocked content can be garbage-collected. The trigger
-- above is what stops it reaching evidence.
GRANT DELETE ON objects TO sf_app;

COMMIT;
