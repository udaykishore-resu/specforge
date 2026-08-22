-- test/isolation/invariants.sql
--
-- Database-level security invariant suite. Run as a superuser against a freshly
-- migrated database; the tests SET ROLE sf_app so that RLS actually applies.
--
--   psql -f test/isolation/invariants.sql
--
-- Every assertion below is a control the application layer must never be the only
-- thing enforcing. A failure here is a release blocker.

\set ON_ERROR_STOP on
\set QUIET on
SET client_min_messages TO WARNING;

CREATE OR REPLACE FUNCTION sf_test_assert(cond boolean, label text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
  IF cond THEN
    RAISE NOTICE 'PASS  %', label;
  ELSE
    RAISE EXCEPTION 'FAIL  %', label;
  END IF;
END $$;

-- Runs `stmt` and asserts it raises. Returns the SQLSTATE for optional checking.
CREATE OR REPLACE FUNCTION sf_test_must_fail(stmt text, label text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
  BEGIN
    EXECUTE stmt;
  EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'PASS  % (blocked: %)', label, left(SQLERRM, 70);
    RETURN;
  END;
  RAISE EXCEPTION 'FAIL  % — statement unexpectedly succeeded', label;
END $$;

SET client_min_messages TO NOTICE;

-- ===========================================================================
-- Fixture: two tenants, each with a project and an artifact.
-- ===========================================================================
DO $$
DECLARE
  t_a uuid := '11111111-1111-4111-8111-111111111111';
  t_b uuid := '22222222-2222-4222-8222-222222222222';
  p_a uuid := 'aaaaaaaa-0000-4000-8000-000000000001';
  p_b uuid := 'bbbbbbbb-0000-4000-8000-000000000001';
  u   uuid := '99999999-9999-4999-8999-999999999999';
BEGIN
  -- TRUNCATE, not DELETE, and deliberately so.
  --
  -- This suite seals artifact versions and locks evidence objects on purpose,
  -- and sealed rows refuse DELETE — that refusal is one of the things being
  -- asserted below. A DELETE-based reset would therefore make the suite
  -- runnable exactly once per database, and the second run would fail on the
  -- first run's evidence rather than on a real defect.
  --
  -- TRUNCATE does not fire row-level DELETE triggers. That is not a hole in the
  -- invariant: TRUNCATE requires table ownership, which the application role
  -- (sf_app) does not have, and section 9 still proves that DELETE is refused
  -- even for the owner. Using it here keeps the reset honest and the suite
  -- re-runnable.
  TRUNCATE trace_links, artifact_versions, artifacts, outbox_events,
           audit_records, audit_sequences, audit_anchors, objects
        RESTART IDENTITY CASCADE;

  INSERT INTO tenants (id, slug, name, status, isolation_mode, created_by)
  VALUES (t_a, 'tenant-alpha', 'Alpha', 'ACTIVE', 'shared', u),
         (t_b, 'tenant-beta',  'Beta',  'ACTIVE', 'shared', u)
  ON CONFLICT (id) DO NOTHING;

  INSERT INTO projects (tenant_id, id, key, name, status, created_by)
  VALUES (t_a, p_a, 'ALPHA', 'Alpha Project', 'ACTIVE', u),
         (t_b, p_b, 'BETA',  'Beta Project',  'ACTIVE', u)
  ON CONFLICT DO NOTHING;

  INSERT INTO artifacts (tenant_id, project_id, artifact_id, artifact_type, title,
                         current_version, status, created_by)
  VALUES (t_a, p_a, 'PRD-001', 'PRD', 'Alpha PRD', 1, 'DRAFT', u),
         (t_b, p_b, 'PRD-001', 'PRD', 'Beta PRD',  1, 'DRAFT', u)
  ON CONFLICT DO NOTHING;

  INSERT INTO artifact_versions (tenant_id, project_id, artifact_id, version, artifact_type,
                                 status, content_schema, content, content_hash, created_by)
  VALUES (t_a, p_a, 'PRD-001', 1, 'PRD', 'USER_REVIEW', 'specforge.prd.v1',
          '{"title":"Alpha"}'::jsonb,
          'sha256:' || repeat('a', 64), u),
         (t_b, p_b, 'PRD-001', 1, 'PRD', 'USER_REVIEW', 'specforge.prd.v1',
          '{"title":"Beta"}'::jsonb,
          'sha256:' || repeat('b', 64), u)
  ON CONFLICT DO NOTHING;

  INSERT INTO audit_sequences (tenant_id) VALUES (t_a), (t_b) ON CONFLICT DO NOTHING;
  RAISE NOTICE 'fixture ready';
END $$;

-- ===========================================================================
-- 1. Row-Level Security: tenant isolation
-- ===========================================================================
SET ROLE sf_app;

-- 1a. No tenant context -> no rows at all (fail closed, not fail open).
BEGIN;
  SELECT sf_test_assert((SELECT count(*) FROM projects) = 0,
    'RLS: query without tenant context returns zero rows');
  SELECT sf_test_assert((SELECT count(*) FROM artifact_versions) = 0,
    'RLS: artifact_versions without tenant context returns zero rows');
COMMIT;

-- 1b. Tenant A sees only tenant A.
BEGIN;
  SET LOCAL app.tenant_id = '11111111-1111-4111-8111-111111111111';
  SELECT sf_test_assert((SELECT count(*) FROM projects) = 1,
    'RLS: tenant A sees exactly its own project');
  SELECT sf_test_assert((SELECT key FROM projects) = 'ALPHA',
    'RLS: tenant A sees the correct project');
  SELECT sf_test_assert(
    (SELECT count(*) FROM projects WHERE tenant_id = '22222222-2222-4222-8222-222222222222') = 0,
    'RLS: tenant A cannot read tenant B even when naming B explicitly');
  SELECT sf_test_assert(
    (SELECT count(*) FROM artifact_versions
      WHERE artifact_id = 'PRD-001' AND content->>'title' = 'Beta') = 0,
    'RLS: forged artifact ID does not leak tenant B content');
COMMIT;

-- 1c. Writing into another tenant is refused by the WITH CHECK clause.
BEGIN;
  SET LOCAL app.tenant_id = '11111111-1111-4111-8111-111111111111';
  SELECT sf_test_must_fail($q$
    INSERT INTO projects (tenant_id, id, key, name, status, created_by)
    VALUES ('22222222-2222-4222-8222-222222222222',
            'cccccccc-0000-4000-8000-000000000001','EVIL','Evil','ACTIVE',
            '99999999-9999-4999-8999-999999999999')
  $q$, 'RLS: tenant A cannot insert a row owned by tenant B');
ROLLBACK;

-- 1d. SET LOCAL does not leak past the transaction.
BEGIN;
  SET LOCAL app.tenant_id = '11111111-1111-4111-8111-111111111111';
COMMIT;
BEGIN;
  SELECT sf_test_assert((SELECT count(*) FROM projects) = 0,
    'RLS: tenant context does not leak to the next transaction on a pooled connection');
COMMIT;

-- ===========================================================================
-- 2. Sealed-artifact immutability
-- ===========================================================================
BEGIN;
  SET LOCAL app.tenant_id = '11111111-1111-4111-8111-111111111111';

  UPDATE artifact_versions
     SET status = 'APPROVED',
         approved_by = '99999999-9999-4999-8999-999999999999',
         approved_at = now(),
         approval_comment = 'Verified against SEC gate; no blocking findings.',
         approval_evidence = '{"evidence_id":"EVD-1","digest":"sha256:deadbeef"}'::jsonb,
         sealed_at = now()
   WHERE artifact_id = 'PRD-001' AND version = 1;
  SELECT sf_test_assert((SELECT status FROM artifact_versions WHERE artifact_id='PRD-001' AND version=1) = 'APPROVED',
    'Seal: legal USER_REVIEW -> APPROVED transition succeeds');

  SELECT sf_test_must_fail($q$
    UPDATE artifact_versions SET content = '{"title":"tampered"}'::jsonb
     WHERE artifact_id = 'PRD-001' AND version = 1
  $q$, 'Immutability: content of an APPROVED version cannot be modified');

  SELECT sf_test_must_fail($q$
    UPDATE artifact_versions SET content_hash = 'sha256:' || repeat('f',64)
     WHERE artifact_id = 'PRD-001' AND version = 1
  $q$, 'Immutability: content_hash of an APPROVED version cannot be rewritten');

  SELECT sf_test_must_fail($q$
    UPDATE artifact_versions SET approved_by = '00000000-0000-4000-8000-000000000000'
     WHERE artifact_id = 'PRD-001' AND version = 1
  $q$, 'Immutability: approver of an APPROVED version cannot be reassigned');

  SELECT sf_test_must_fail($q$
    UPDATE artifact_versions SET status = 'DRAFT'
     WHERE artifact_id = 'PRD-001' AND version = 1
  $q$, 'Immutability: APPROVED cannot be reverted to DRAFT');

  SELECT sf_test_must_fail($q$
    DELETE FROM artifact_versions WHERE artifact_id = 'PRD-001' AND version = 1
  $q$, 'Immutability: an APPROVED version cannot be deleted');

  -- The legal terminal transitions still work.
  UPDATE artifact_versions SET status = 'FROZEN'
   WHERE artifact_id = 'PRD-001' AND version = 1;
  SELECT sf_test_assert((SELECT status FROM artifact_versions WHERE artifact_id='PRD-001' AND version=1) = 'FROZEN',
    'Seal: APPROVED -> FROZEN is permitted');
ROLLBACK;

-- ===========================================================================
-- 3. Approval completeness constraint
-- ===========================================================================
BEGIN;
  SET LOCAL app.tenant_id = '11111111-1111-4111-8111-111111111111';
  SELECT sf_test_must_fail($q$
    UPDATE artifact_versions SET status = 'APPROVED'
     WHERE artifact_id = 'PRD-001' AND version = 1
  $q$, 'Evidence: APPROVED without approver/comment/evidence is rejected');
ROLLBACK;

-- ===========================================================================
-- 4. One APPROVED version per artifact
-- ===========================================================================
DO $$
BEGIN
  PERFORM set_config('app.tenant_id','11111111-1111-4111-8111-111111111111', true);
  BEGIN
    INSERT INTO artifact_versions (tenant_id, project_id, artifact_id, version, artifact_type,
        status, content_schema, content, content_hash, previous_version, created_by,
        approved_by, approved_at, approval_comment, approval_evidence, sealed_at)
    VALUES ('11111111-1111-4111-8111-111111111111','aaaaaaaa-0000-4000-8000-000000000001',
            'PRD-001', 2, 'PRD', 'APPROVED', 'specforge.prd.v1', '{"title":"v2"}'::jsonb,
            'sha256:' || repeat('c',64), 1, '99999999-9999-4999-8999-999999999999',
            '99999999-9999-4999-8999-999999999999', now(), 'approved v2',
            '{"evidence_id":"EVD-2"}'::jsonb, now());
    UPDATE artifact_versions
       SET status='APPROVED', approved_by='99999999-9999-4999-8999-999999999999',
           approved_at=now(), approval_comment='approved v1', sealed_at=now(),
           approval_evidence='{"evidence_id":"EVD-1"}'::jsonb
     WHERE artifact_id='PRD-001' AND version=1;
    RAISE EXCEPTION 'FAIL  Uniqueness: two APPROVED versions coexisted';
  EXCEPTION WHEN unique_violation THEN
    RAISE NOTICE 'PASS  Uniqueness: only one APPROVED version per artifact';
  END;
END $$;

-- ===========================================================================
-- 5. Version chain integrity
-- ===========================================================================
DO $$
BEGIN
  PERFORM set_config('app.tenant_id','11111111-1111-4111-8111-111111111111', true);
  BEGIN
    INSERT INTO artifact_versions (tenant_id, project_id, artifact_id, version, artifact_type,
        status, content_schema, content, content_hash, previous_version, created_by)
    VALUES ('11111111-1111-4111-8111-111111111111','aaaaaaaa-0000-4000-8000-000000000001',
            'PRD-001', 5, 'PRD', 'DRAFT', 'specforge.prd.v1', '{}'::jsonb,
            'sha256:' || repeat('d',64), 1, '99999999-9999-4999-8999-999999999999');
    RAISE EXCEPTION 'FAIL  Chain: gapped version accepted';
  EXCEPTION WHEN check_violation THEN
    RAISE NOTICE 'PASS  Chain: a gapped version (v5 after v1) is rejected';
  END;

  BEGIN
    INSERT INTO artifact_versions (tenant_id, project_id, artifact_id, version, artifact_type,
        status, content_schema, content, content_hash, previous_version, created_by)
    VALUES ('11111111-1111-4111-8111-111111111111','aaaaaaaa-0000-4000-8000-000000000001',
            'PRD-002', 1, 'PRD', 'DRAFT', 'specforge.prd.v1', '{}'::jsonb,
            'sha256:' || repeat('e',64), 1, '99999999-9999-4999-8999-999999999999');
    RAISE EXCEPTION 'FAIL  Chain: v1 with a previous_version accepted';
  EXCEPTION WHEN check_violation OR foreign_key_violation THEN
    RAISE NOTICE 'PASS  Chain: version 1 cannot declare a previous_version';
  END;
END $$;

-- ===========================================================================
-- 6. Trace links: LLM-proposed links need a governance disposition
-- ===========================================================================
DO $$
BEGIN
  PERFORM set_config('app.tenant_id','11111111-1111-4111-8111-111111111111', true);

  INSERT INTO artifacts (tenant_id, project_id, artifact_id, artifact_type, title,
                         current_version, status, created_by)
  VALUES ('11111111-1111-4111-8111-111111111111','aaaaaaaa-0000-4000-8000-000000000001',
          'SPEC-AUTH-001','SPECIFICATION','Auth spec',1,'DRAFT',
          '99999999-9999-4999-8999-999999999999')
  ON CONFLICT DO NOTHING;

  INSERT INTO artifact_versions (tenant_id, project_id, artifact_id, version, artifact_type,
      status, content_schema, content, content_hash, created_by)
  VALUES ('11111111-1111-4111-8111-111111111111','aaaaaaaa-0000-4000-8000-000000000001',
          'SPEC-AUTH-001',1,'SPECIFICATION','DRAFT','specforge.spec.v1','{}'::jsonb,
          'sha256:' || repeat('1',64),'99999999-9999-4999-8999-999999999999')
  ON CONFLICT DO NOTHING;

  BEGIN
    INSERT INTO trace_links (tenant_id, project_id, link_id, from_artifact_id, from_version,
        to_artifact_id, to_version, link_type, origin, confidence, status, created_by)
    VALUES ('11111111-1111-4111-8111-111111111111','aaaaaaaa-0000-4000-8000-000000000001',
            gen_random_uuid(),'SPEC-AUTH-001',1,'PRD-001',1,'DERIVED_FROM',
            'LLM_PROPOSED',0.87,'ACCEPTED','99999999-9999-4999-8999-999999999999');
    RAISE EXCEPTION 'FAIL  Governance: LLM link accepted without a disposition';
  EXCEPTION WHEN check_violation THEN
    RAISE NOTICE 'PASS  Governance: an LLM_PROPOSED link cannot be ACCEPTED without a disposition';
  END;

  -- The same link is fine in PROPOSED state.
  INSERT INTO trace_links (tenant_id, project_id, link_id, from_artifact_id, from_version,
      to_artifact_id, to_version, link_type, origin, confidence, status, created_by)
  VALUES ('11111111-1111-4111-8111-111111111111','aaaaaaaa-0000-4000-8000-000000000001',
          gen_random_uuid(),'SPEC-AUTH-001',1,'PRD-001',1,'DERIVED_FROM',
          'LLM_PROPOSED',0.87,'PROPOSED','99999999-9999-4999-8999-999999999999');
  RAISE NOTICE 'PASS  Governance: an LLM_PROPOSED link may exist as PROPOSED';

  -- A dangling endpoint is rejected.
  BEGIN
    INSERT INTO trace_links (tenant_id, project_id, link_id, from_artifact_id, from_version,
        to_artifact_id, to_version, link_type, origin, confidence, status, created_by)
    VALUES ('11111111-1111-4111-8111-111111111111','aaaaaaaa-0000-4000-8000-000000000001',
            gen_random_uuid(),'SPEC-AUTH-001',1,'PRD-999',1,'DERIVED_FROM',
            'HUMAN',1.0,'ACCEPTED','99999999-9999-4999-8999-999999999999');
    RAISE EXCEPTION 'FAIL  Graph: dangling trace link accepted';
  EXCEPTION WHEN foreign_key_violation THEN
    RAISE NOTICE 'PASS  Graph: a trace link to a non-existent artifact version is rejected';
  END;
END $$;

-- ===========================================================================
-- 7. Audit trail is append-only
-- ===========================================================================
DO $$
DECLARE
  t uuid := '11111111-1111-4111-8111-111111111111';
BEGIN
  PERFORM set_config('app.tenant_id', t::text, true);

  INSERT INTO audit_records (tenant_id, sequence, id, action, outcome, severity,
                             actor, target, prev_hash, record_hash)
  VALUES (t, 1, gen_random_uuid(), 'tenant.create', 'SUCCESS', 'NOTICE',
          '{"principal_id":"99999999-9999-4999-8999-999999999999"}'::jsonb,
          '{"type":"Tenant"}'::jsonb, repeat('0',64), repeat('1',64));
  RAISE NOTICE 'PASS  Audit: append succeeds';

  -- Layer 1: sf_app holds no UPDATE/DELETE grant at all.
  BEGIN
    UPDATE audit_records SET action = 'tenant.rewritten' WHERE tenant_id = t AND sequence = 1;
    RAISE EXCEPTION 'FAIL  Audit: record was updated by sf_app';
  EXCEPTION WHEN insufficient_privilege OR check_violation THEN
    RAISE NOTICE 'PASS  Audit: sf_app cannot update audit records';
  END;

  BEGIN
    DELETE FROM audit_records WHERE tenant_id = t AND sequence = 1;
    RAISE EXCEPTION 'FAIL  Audit: record was deleted by sf_app';
  EXCEPTION WHEN insufficient_privilege OR check_violation THEN
    RAISE NOTICE 'PASS  Audit: sf_app cannot delete audit records';
  END;
END $$;

-- Layer 2: the append-only trigger refuses even for a role that does hold the grant.
RESET ROLE;
DO $$
DECLARE
  t uuid := '11111111-1111-4111-8111-111111111111';
BEGIN
  PERFORM set_config('app.tenant_id', t::text, true);
  BEGIN
    UPDATE audit_records SET action = 'tenant.rewritten' WHERE tenant_id = t AND sequence = 1;
    RAISE EXCEPTION 'FAIL  Audit: the owner updated an audit record';
  EXCEPTION WHEN check_violation THEN
    RAISE NOTICE 'PASS  Audit: the append-only trigger refuses updates even for the table owner';
  END;

  BEGIN
    DELETE FROM audit_records WHERE tenant_id = t AND sequence = 1;
    RAISE EXCEPTION 'FAIL  Audit: the owner deleted an audit record';
  EXCEPTION WHEN check_violation THEN
    RAISE NOTICE 'PASS  Audit: the append-only trigger refuses deletes even for the table owner';
  END;
END $$;
SET ROLE sf_app;

-- ===========================================================================
-- 8. Service-account credentials cannot carry approval authority (SoD-6)
-- ===========================================================================
DO $$
BEGIN
  PERFORM set_config('app.tenant_id','11111111-1111-4111-8111-111111111111', true);
  BEGIN
    INSERT INTO api_keys (tenant_id, id, key_id, principal_id, name, secret_hash, permissions, created_by)
    VALUES ('11111111-1111-4111-8111-111111111111', gen_random_uuid(), 'sf_dev_test01',
            '99999999-9999-4999-8999-999999999999', 'ci-key', 'argon2id$...',
            ARRAY['artifact:read','artifact:approve'], '99999999-9999-4999-8999-999999999999');
    RAISE EXCEPTION 'FAIL  SoD: api key with approval permission accepted';
  EXCEPTION WHEN check_violation THEN
    RAISE NOTICE 'PASS  SoD-6: an API key cannot hold approval permissions';
  END;
END $$;

RESET ROLE;

-- ===========================================================================
-- 9. The delete trigger is the backstop behind the missing DELETE grant.
--    sf_app has no DELETE privilege on artifact_versions (test 2 proved that);
--    here we verify the trigger also refuses, as the owner.
-- ===========================================================================
-- The version this runs against must actually be sealed, or the DELETE matches
-- nothing and the block reports success without exercising the trigger. An
-- earlier revision of this test did exactly that: it emitted a NOTE and moved
-- on, so the one guarantee it existed to prove was never checked. A test that
-- cannot fail is worse than a missing test, because it reads like coverage.
DO $$
DECLARE
  sealed_count integer;
BEGIN
  PERFORM set_config('app.tenant_id','11111111-1111-4111-8111-111111111111', true);

  -- Seal tenant A's fixture version so the trigger has something to refuse.
  UPDATE artifact_versions
     SET status            = 'APPROVED',
         approved_by       = '44444444-4444-4444-8444-444444444444',
         approved_at       = now(),
         approval_comment  = 'sealed so the delete trigger can be exercised',
         approval_evidence = jsonb_build_object(
           'evidence_id', 'EVD-del-probe',
           'digest', 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
           'media_type', 'application/vnd.specforge.approval+json',
           'storage_ref', 'probe'),
         sealed_at         = now()
   WHERE tenant_id  = '11111111-1111-4111-8111-111111111111'
     AND artifact_id = 'PRD-001'
     AND version     = 1
     AND status NOT IN ('APPROVED','FROZEN','SUPERSEDED');

  SELECT count(*) INTO sealed_count
    FROM artifact_versions
   WHERE tenant_id   = '11111111-1111-4111-8111-111111111111'
     AND artifact_id = 'PRD-001'
     AND version     = 1
     AND status IN ('APPROVED','FROZEN','SUPERSEDED');

  IF sealed_count = 0 THEN
    RAISE EXCEPTION 'FAIL  the delete probe could not seal a version, so the trigger was never exercised';
  END IF;

  BEGIN
    DELETE FROM artifact_versions
     WHERE tenant_id   = '11111111-1111-4111-8111-111111111111'
       AND artifact_id = 'PRD-001'
       AND version     = 1;
    -- Reaching this line means a sealed version was deleted, which is the
    -- failure this entire file exists to catch. It must stop the run.
    RAISE EXCEPTION 'FAIL  Immutability: a sealed artifact version was DELETED by the table owner';
  EXCEPTION
    WHEN check_violation THEN
      RAISE NOTICE 'PASS  Immutability: the delete trigger refuses sealed versions even for the table owner';
  END;
END $$;


-- ---------------------------------------------------------------------------
-- 10. Object store: write-once retention
--
-- Approval evidence lives in the objects table when the db provider is in use.
-- The claim is that a locked object cannot be altered or removed by anyone with
-- a connection to this database, including the table owner running this script.
-- These assertions are the claim, tested.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  survived text;
BEGIN
  INSERT INTO objects (bucket, key, digest, size_bytes, body, locked, retain_until)
  VALUES ('sf-isolation-probe', 'evidence/probe',
          'sha256:' || encode(sha256('original'::bytea), 'hex'),
          8, 'original', true, now() + interval '7 days');

  -- 10a. Overwriting locked content.
  BEGIN
    UPDATE objects
       SET body   = 'tampered',
           digest = 'sha256:' || encode(sha256('tampered'::bytea), 'hex')
     WHERE bucket = 'sf-isolation-probe' AND key = 'evidence/probe';
    RAISE EXCEPTION 'FAIL  Object lock: LOCKED EVIDENCE WAS OVERWRITTEN by the table owner';
  EXCEPTION
    WHEN check_violation THEN
      RAISE NOTICE 'PASS  Object lock: a locked object cannot be overwritten';
  END;

  -- 10b. Deleting locked content.
  BEGIN
    DELETE FROM objects WHERE bucket = 'sf-isolation-probe' AND key = 'evidence/probe';
    RAISE EXCEPTION 'FAIL  Object lock: LOCKED EVIDENCE WAS DELETED by the table owner';
  EXCEPTION
    WHEN check_violation THEN
      RAISE NOTICE 'PASS  Object lock: a locked object cannot be deleted';
  END;

  -- 10c. Shortening retention. This is the first move of anyone who wants to
  -- delete evidence and be able to say the retention had expired.
  BEGIN
    UPDATE objects SET retain_until = now() - interval '1 day'
     WHERE bucket = 'sf-isolation-probe' AND key = 'evidence/probe';
    RAISE EXCEPTION 'FAIL  Object lock: retention was SHORTENED on a locked object';
  EXCEPTION
    WHEN check_violation THEN
      RAISE NOTICE 'PASS  Object lock: retention cannot be shortened';
  END;

  -- 10d. Releasing the lock.
  BEGIN
    UPDATE objects SET locked = false
     WHERE bucket = 'sf-isolation-probe' AND key = 'evidence/probe';
    RAISE EXCEPTION 'FAIL  Object lock: the lock was REMOVED from a locked object';
  EXCEPTION
    WHEN check_violation THEN
      RAISE NOTICE 'PASS  Object lock: the lock cannot be removed';
  END;

  -- 10e. A locked object with no retention date would be locked by accident
  -- rather than by policy.
  BEGIN
    INSERT INTO objects (bucket, key, digest, size_bytes, body, locked)
    VALUES ('sf-isolation-probe', 'evidence/no-retention',
            'sha256:' || encode(sha256('x'::bytea), 'hex'), 1, 'x', true);
    RAISE EXCEPTION 'FAIL  Object lock: a locked object was accepted with no retention date';
  EXCEPTION
    WHEN check_violation THEN
      RAISE NOTICE 'PASS  Object lock: a lock requires an explicit retention date';
  END;

  -- 10f. After all of that, the original bytes must be exactly as written.
  SELECT convert_from(body, 'UTF8') INTO survived
    FROM objects WHERE bucket = 'sf-isolation-probe' AND key = 'evidence/probe';
  IF survived IS DISTINCT FROM 'original' THEN
    RAISE EXCEPTION 'FAIL  Object lock: evidence content changed to %', survived;
  END IF;
  RAISE NOTICE 'PASS  Object lock: the evidence survived every attempt intact';
END $$;

DO $$ BEGIN RAISE NOTICE '--- all database invariants verified ---'; END $$;
