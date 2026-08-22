-- 0002_artifact_graph.sql
-- The canonical artifact model: artifacts, immutable versions, typed trace links.
-- See docs/architecture/02-canonical-artifact-model.md
--
-- The invariants encoded here are the ones the platform cannot afford to enforce only
-- in application code: sealed-version immutability, single approved version, approval
-- evidence completeness, gapless version chains, and "an LLM-proposed link cannot be
-- accepted without a governance disposition".

BEGIN;

CREATE TABLE artifacts (
  tenant_id       uuid NOT NULL REFERENCES tenants(id),
  project_id      uuid NOT NULL,
  artifact_id     text NOT NULL CHECK (artifact_id ~ '^[A-Z][A-Z0-9]*(-[A-Za-z0-9]+)+$'),
  artifact_type   text NOT NULL CHECK (artifact_type IN (
                    'REQUIREMENT','PRD','SPECIFICATION','BPMN_PROCESS','ARCHITECTURE',
                    'API_CONTRACT','DATA_MODEL','SEQUENCE','STATE_MACHINE','CODE_UNIT',
                    'TEST_CASE','PIPELINE_DEF','DEPLOYMENT','POLICY','EVIDENCE','PROMPT')),
  title           text NOT NULL DEFAULT '',
  current_version integer NOT NULL DEFAULT 0,
  status          text NOT NULL,
  labels          jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_by      uuid NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  version_no      bigint NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, project_id, artifact_id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id)
);
CREATE INDEX artifacts_type   ON artifacts (tenant_id, project_id, artifact_type, status);
CREATE INDEX artifacts_labels ON artifacts USING gin (labels);
CREATE TRIGGER artifacts_touch BEFORE UPDATE ON artifacts
  FOR EACH ROW EXECUTE FUNCTION sf_touch_updated_at();

ALTER TABLE artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifacts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON artifacts
  USING (tenant_id = sf_current_tenant())
  WITH CHECK (tenant_id = sf_current_tenant());

-- ---------------------------------------------------------------------------
-- artifact_versions
-- ---------------------------------------------------------------------------
CREATE TABLE artifact_versions (
  tenant_id                uuid NOT NULL,
  project_id               uuid NOT NULL,
  artifact_id              text NOT NULL,
  version                  integer NOT NULL CHECK (version >= 1),
  artifact_type            text NOT NULL,
  status                   text NOT NULL CHECK (status IN (
                             'DRAFT','AI_REVIEW','USER_REVIEW','CHANGES_REQUESTED',
                             'APPROVED','FROZEN','SUPERSEDED','ABANDONED')),
  content_schema           text NOT NULL,
  content                  jsonb,
  content_ref              text,
  content_hash             text NOT NULL CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
  parent_artifact_id       text,
  parent_artifact_version  integer,
  source_artifact_id       text,
  source_artifact_version  integer,
  previous_version         integer,
  change_summary           text NOT NULL DEFAULT '',
  generator                jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_by               uuid NOT NULL,
  created_at               timestamptz NOT NULL DEFAULT now(),
  updated_at               timestamptz NOT NULL DEFAULT now(),
  approved_by              uuid,
  approved_at              timestamptz,
  approval_comment         text NOT NULL DEFAULT '',
  approval_evidence        jsonb,
  sealed_at                timestamptz,
  version_no               bigint NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, project_id, artifact_id, version),
  FOREIGN KEY (tenant_id, project_id, artifact_id)
    REFERENCES artifacts(tenant_id, project_id, artifact_id),

  -- Content lives inline or by reference, never neither.
  CONSTRAINT content_present CHECK (content IS NOT NULL OR content_ref IS NOT NULL),
  -- Inline content is bounded; larger payloads must be externalized to object storage.
  CONSTRAINT content_inline_size CHECK (content IS NULL OR pg_column_size(content) < 262144),
  -- Approval completeness (brief §3): an APPROVED version without full evidence is impossible.
  CONSTRAINT approved_requires_evidence CHECK (
    status <> 'APPROVED' OR (
      approved_by IS NOT NULL AND approved_at IS NOT NULL
      AND approval_evidence IS NOT NULL AND length(approval_comment) > 0
      AND sealed_at IS NOT NULL)),
  -- Version chains are gapless and start at 1.
  CONSTRAINT chain_start CHECK ((version = 1) = (previous_version IS NULL)),
  CONSTRAINT chain_step  CHECK (previous_version IS NULL OR previous_version = version - 1),
  -- Structural/derivation references stay inside the same project.
  CONSTRAINT parent_pair CHECK ((parent_artifact_id IS NULL) = (parent_artifact_version IS NULL)),
  CONSTRAINT source_pair CHECK ((source_artifact_id IS NULL) = (source_artifact_version IS NULL))
);

CREATE INDEX artifact_versions_latest
  ON artifact_versions (tenant_id, project_id, artifact_id, version DESC);
CREATE INDEX artifact_versions_status
  ON artifact_versions (tenant_id, project_id, status, artifact_type);

-- At most one APPROVED version per artifact identity.
CREATE UNIQUE INDEX one_approved_per_artifact
  ON artifact_versions (tenant_id, project_id, artifact_id)
  WHERE status = 'APPROVED';

ALTER TABLE artifact_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifact_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON artifact_versions
  USING (tenant_id = sf_current_tenant())
  WITH CHECK (tenant_id = sf_current_tenant());

-- ---------------------------------------------------------------------------
-- Sealed-version immutability.
--
-- Once a version reaches a sealed status, the only permitted mutation is a status
-- move along the terminal transitions APPROVED->FROZEN, APPROVED->SUPERSEDED,
-- FROZEN->SUPERSEDED. Everything else raises, regardless of how the UPDATE was issued.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION sf_enforce_version_immutability() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  old_body jsonb;
  new_body jsonb;
BEGIN
  IF OLD.status IN ('APPROVED','FROZEN','SUPERSEDED','ABANDONED') THEN
    old_body := to_jsonb(OLD) - 'status' - 'version_no' - 'updated_at';
    new_body := to_jsonb(NEW) - 'status' - 'version_no' - 'updated_at';
    IF old_body IS DISTINCT FROM new_body THEN
      RAISE EXCEPTION
        'artifact version %/% is sealed (status %); content and metadata are immutable',
        OLD.artifact_id, OLD.version, OLD.status
        USING ERRCODE = '23514', HINT = 'Create a new version instead of modifying a sealed one.';
    END IF;
    IF NEW.status <> OLD.status
       AND NOT ((OLD.status = 'APPROVED' AND NEW.status IN ('FROZEN','SUPERSEDED'))
             OR (OLD.status = 'FROZEN'   AND NEW.status = 'SUPERSEDED')) THEN
      RAISE EXCEPTION
        'illegal status transition % -> % on sealed artifact version %/%',
        OLD.status, NEW.status, OLD.artifact_id, OLD.version
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER artifact_versions_immutable
  BEFORE UPDATE ON artifact_versions
  FOR EACH ROW EXECUTE FUNCTION sf_enforce_version_immutability();

CREATE OR REPLACE FUNCTION sf_forbid_sealed_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status IN ('APPROVED','FROZEN','SUPERSEDED') THEN
    RAISE EXCEPTION 'sealed artifact versions cannot be deleted (%/%)', OLD.artifact_id, OLD.version
      USING ERRCODE = '23514';
  END IF;
  RETURN OLD;
END $$;

CREATE TRIGGER artifact_versions_no_delete
  BEFORE DELETE ON artifact_versions
  FOR EACH ROW EXECUTE FUNCTION sf_forbid_sealed_delete();

CREATE TRIGGER artifact_versions_touch BEFORE UPDATE ON artifact_versions
  FOR EACH ROW EXECUTE FUNCTION sf_touch_updated_at();

-- ---------------------------------------------------------------------------
-- trace_links
-- ---------------------------------------------------------------------------
CREATE TABLE trace_links (
  tenant_id          uuid NOT NULL,
  project_id         uuid NOT NULL,
  link_id            uuid NOT NULL,
  from_artifact_id   text NOT NULL,
  from_version       integer NOT NULL,
  to_artifact_id     text NOT NULL,
  to_version         integer NOT NULL,
  link_type          text NOT NULL CHECK (link_type IN (
                       'DERIVED_FROM','SATISFIES','IMPLEMENTS','REPRESENTED_BY','VERIFIES',
                       'REALIZED_BY','DEPLOYS','CONTAINS','DEPENDS_ON','SUPERSEDES',
                       'GOVERNS','EVIDENCES','CONFLICTS_WITH')),
  origin             text NOT NULL CHECK (origin IN ('HUMAN','ANALYZER','LLM_PROPOSED')),
  confidence         numeric(4,3) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  status             text NOT NULL CHECK (status IN ('PROPOSED','ACCEPTED','REJECTED','STALE')),
  rationale          text NOT NULL DEFAULT '',
  evidence           jsonb,
  disposition_id     uuid,
  created_by         uuid NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  version_no         bigint NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, project_id, link_id),
  CONSTRAINT no_self_link CHECK (
    from_artifact_id <> to_artifact_id OR from_version <> to_version),
  -- "AI proposes, governance approves" expressed as a database constraint.
  CONSTRAINT llm_link_needs_disposition CHECK (
    status <> 'ACCEPTED' OR origin <> 'LLM_PROPOSED' OR disposition_id IS NOT NULL)
);

CREATE UNIQUE INDEX trace_links_unique ON trace_links
  (tenant_id, project_id, from_artifact_id, from_version, to_artifact_id, to_version, link_type);
CREATE INDEX trace_links_forward ON trace_links
  (tenant_id, project_id, from_artifact_id, link_type) WHERE status = 'ACCEPTED';
CREATE INDEX trace_links_backward ON trace_links
  (tenant_id, project_id, to_artifact_id, link_type) WHERE status = 'ACCEPTED';

CREATE TRIGGER trace_links_touch BEFORE UPDATE ON trace_links
  FOR EACH ROW EXECUTE FUNCTION sf_touch_updated_at();

ALTER TABLE trace_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE trace_links FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON trace_links
  USING (tenant_id = sf_current_tenant())
  WITH CHECK (tenant_id = sf_current_tenant());

-- Endpoints must exist in the same tenant+project. Enforced by trigger rather than FK
-- because a link may reference any version of an artifact and we want a precise message.
CREATE OR REPLACE FUNCTION sf_validate_trace_link() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM artifact_versions v
                 WHERE v.tenant_id = NEW.tenant_id AND v.project_id = NEW.project_id
                   AND v.artifact_id = NEW.from_artifact_id AND v.version = NEW.from_version) THEN
    RAISE EXCEPTION 'trace link source %/% does not exist in this project',
      NEW.from_artifact_id, NEW.from_version USING ERRCODE = '23503';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM artifact_versions v
                 WHERE v.tenant_id = NEW.tenant_id AND v.project_id = NEW.project_id
                   AND v.artifact_id = NEW.to_artifact_id AND v.version = NEW.to_version) THEN
    RAISE EXCEPTION 'trace link target %/% does not exist in this project',
      NEW.to_artifact_id, NEW.to_version USING ERRCODE = '23503';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER trace_links_validate
  BEFORE INSERT OR UPDATE ON trace_links
  FOR EACH ROW EXECUTE FUNCTION sf_validate_trace_link();

COMMIT;
