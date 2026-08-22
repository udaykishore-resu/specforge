-- 0004_roles_grants.sql
-- Application role and least-privilege grants.
--
-- sf_app is deliberately NOT the owner of any table and has no BYPASSRLS, so
-- FORCE ROW LEVEL SECURITY applies to it unconditionally. It has no UPDATE or DELETE
-- on audit_records: the append-only trigger is the backstop, this is the front door.

BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sf_app') THEN
    CREATE ROLE sf_app NOLOGIN;
  END IF;
END $$;

GRANT USAGE ON SCHEMA public TO sf_app;

GRANT SELECT, INSERT, UPDATE ON
  tenants, projects, principals, role_assignments, api_keys, idp_role_mappings,
  artifacts, artifact_versions, trace_links,
  audit_sequences, audit_anchors, outbox_events, idempotency_keys, processed_events
TO sf_app;

-- Audit records: append and read only. No UPDATE. No DELETE. Ever.
GRANT SELECT, INSERT ON audit_records TO sf_app;
GRANT SELECT, INSERT ON audit_records_default TO sf_app;

-- Housekeeping deletes that are safe (expiry sweepers on derived data only).
GRANT DELETE ON idempotency_keys, processed_events, role_assignments TO sf_app;

GRANT EXECUTE ON FUNCTION sf_current_tenant()    TO sf_app;
GRANT EXECUTE ON FUNCTION sf_current_principal() TO sf_app;

COMMIT;
