-- 0001_platform_foundation.sql
-- SpecForge Phase 1 — platform foundation.
--
-- Rollback plan: this migration is additive and creates only new objects in a clean
-- database. Recovery is restore-from-backup; no down migration is shipped (see
-- docs/architecture/09-database-schema.md §8).
--
-- Roles:
--   sf_migrator  owns the schema and runs migrations (created out-of-band by IaC)
--   sf_app       the application role; NOT the table owner, no BYPASSRLS
--
-- Every tenant-scoped table below has FORCE ROW LEVEL SECURITY so that even the owner
-- is subject to the isolation policy.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- Helper: current tenant from the transaction-local setting.
-- Returns NULL when unset, so an unscoped query matches no rows rather than all.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION sf_current_tenant() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid
$$;

CREATE OR REPLACE FUNCTION sf_current_principal() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.principal_id', true), '')::uuid
$$;

CREATE OR REPLACE FUNCTION sf_touch_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END $$;

-- ---------------------------------------------------------------------------
-- schema_migrations
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS schema_migrations (
  version      text PRIMARY KEY,
  checksum     text NOT NULL,
  applied_at   timestamptz NOT NULL DEFAULT now(),
  applied_by   text NOT NULL DEFAULT current_user,
  duration_ms  integer NOT NULL DEFAULT 0
);

-- ---------------------------------------------------------------------------
-- tenants  (platform-scoped: no RLS; guarded by permissions and explicit filters)
-- ---------------------------------------------------------------------------
CREATE TABLE tenants (
  id              uuid PRIMARY KEY,
  slug            text NOT NULL UNIQUE
                    CHECK (slug ~ '^[a-z][a-z0-9-]{2,39}$'),
  name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  status          text NOT NULL
                    CHECK (status IN ('PROVISIONING','ACTIVE','SUSPENDED','DEPROVISIONING','PURGED','FAILED')),
  isolation_mode  text NOT NULL
                    CHECK (isolation_mode IN ('shared','dedicated_schema','single_tenant')),
  region          text NOT NULL DEFAULT '',
  settings        jsonb NOT NULL DEFAULT '{}'::jsonb,
  status_reason   text NOT NULL DEFAULT '',
  created_by      uuid NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  version_no      bigint NOT NULL DEFAULT 1
);
CREATE TRIGGER tenants_touch BEFORE UPDATE ON tenants
  FOR EACH ROW EXECUTE FUNCTION sf_touch_updated_at();

-- ---------------------------------------------------------------------------
-- projects
-- ---------------------------------------------------------------------------
CREATE TABLE projects (
  tenant_id    uuid NOT NULL REFERENCES tenants(id),
  id           uuid NOT NULL,
  key          text NOT NULL CHECK (key ~ '^[A-Z][A-Z0-9]{1,9}$'),
  name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  description  text NOT NULL DEFAULT '',
  status       text NOT NULL CHECK (status IN ('ACTIVE','ARCHIVED','PURGED')),
  pdlc_phase   text NOT NULL DEFAULT 'DISCOVER'
                 CHECK (pdlc_phase IN ('DISCOVER','DEFINE','SPECIFY','MODEL','ARCHITECT','GENERATE',
                                       'VALIDATE','GOVERN','BUILD','TEST','SECURE','DEPLOY',
                                       'OBSERVE','REVIEW','EVOLVE','RETIRE')),
  settings     jsonb NOT NULL DEFAULT '{}'::jsonb,
  graph_version bigint NOT NULL DEFAULT 1,
  created_by   uuid NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  version_no   bigint NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, id)
);
CREATE UNIQUE INDEX projects_tenant_key ON projects (tenant_id, key);
CREATE TRIGGER projects_touch BEFORE UPDATE ON projects
  FOR EACH ROW EXECUTE FUNCTION sf_touch_updated_at();

ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON projects
  USING (tenant_id = sf_current_tenant())
  WITH CHECK (tenant_id = sf_current_tenant());

-- ---------------------------------------------------------------------------
-- principals / role assignments / api keys / idp mappings
-- ---------------------------------------------------------------------------
CREATE TABLE principals (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL REFERENCES tenants(id),
  kind          text NOT NULL CHECK (kind IN ('USER','SERVICE_ACCOUNT','SYSTEM')),
  issuer        text NOT NULL,
  subject       text NOT NULL,
  email         text NOT NULL DEFAULT '',
  display_name  text NOT NULL DEFAULT '',
  status        text NOT NULL CHECK (status IN ('ACTIVE','DISABLED')),
  attributes    jsonb NOT NULL DEFAULT '{}'::jsonb,
  last_login_at timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  version_no    bigint NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX principals_issuer_subject ON principals (issuer, subject);
CREATE INDEX principals_tenant ON principals (tenant_id, status);
CREATE TRIGGER principals_touch BEFORE UPDATE ON principals
  FOR EACH ROW EXECUTE FUNCTION sf_touch_updated_at();

ALTER TABLE principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE principals FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON principals
  USING (tenant_id = sf_current_tenant())
  WITH CHECK (tenant_id = sf_current_tenant());

CREATE TABLE role_assignments (
  tenant_id    uuid NOT NULL REFERENCES tenants(id),
  id           uuid NOT NULL,
  principal_id uuid NOT NULL,
  project_id   uuid,                       -- NULL => tenant-wide grant
  role         text NOT NULL CHECK (role IN (
                 'platform_admin','tenant_admin','product_owner','business_analyst','architect',
                 'developer','qa','devops','security','compliance','auditor','viewer')),
  granted_by   uuid NOT NULL,
  granted_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz,
  PRIMARY KEY (tenant_id, id)
);
-- NULLS NOT DISTINCT makes (principal, NULL project, role) a genuine uniqueness constraint.
CREATE UNIQUE INDEX role_assignments_unique
  ON role_assignments (tenant_id, principal_id, project_id, role) NULLS NOT DISTINCT;
CREATE INDEX role_assignments_principal ON role_assignments (tenant_id, principal_id);
CREATE INDEX role_assignments_expiring ON role_assignments (expires_at) WHERE expires_at IS NOT NULL;

ALTER TABLE role_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE role_assignments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON role_assignments
  USING (tenant_id = sf_current_tenant())
  WITH CHECK (tenant_id = sf_current_tenant());

CREATE TABLE api_keys (
  tenant_id    uuid NOT NULL REFERENCES tenants(id),
  id           uuid NOT NULL,
  key_id       text NOT NULL UNIQUE,
  principal_id uuid NOT NULL,
  name         text NOT NULL,
  secret_hash  text NOT NULL,
  permissions  text[] NOT NULL DEFAULT '{}',
  project_id   uuid,
  created_by   uuid NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz,
  revoked_at   timestamptz,
  last_used_at timestamptz,
  PRIMARY KEY (tenant_id, id),
  -- SoD-6: a service-account credential can never carry approval authority.
  CONSTRAINT api_keys_no_approval_permissions CHECK (
    NOT (permissions && ARRAY['artifact:approve','prd:approve','spec:approve',
                              'exception:grant','designauthority:decide','gate:override',
                              'deployment:approve','proposal:approve','finding:suppress'])
  )
);
CREATE INDEX api_keys_principal ON api_keys (tenant_id, principal_id);

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON api_keys
  USING (tenant_id = sf_current_tenant())
  WITH CHECK (tenant_id = sf_current_tenant());

CREATE TABLE idp_role_mappings (
  tenant_id       uuid NOT NULL REFERENCES tenants(id),
  id              uuid NOT NULL,
  idp_group       text NOT NULL,
  role            text NOT NULL,
  project_key     text,
  mapping_version integer NOT NULL DEFAULT 1,
  created_by      uuid NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);
CREATE UNIQUE INDEX idp_role_mappings_unique
  ON idp_role_mappings (tenant_id, idp_group, role, project_key) NULLS NOT DISTINCT;

ALTER TABLE idp_role_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE idp_role_mappings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON idp_role_mappings
  USING (tenant_id = sf_current_tenant())
  WITH CHECK (tenant_id = sf_current_tenant());

COMMIT;
