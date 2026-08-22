-- 0003_audit_outbox.sql
-- Tamper-evident audit chain, transactional outbox, idempotency, consumer de-duplication.
-- See docs/architecture/25-audit-scope.md and 04-event-model.md

BEGIN;

-- ---------------------------------------------------------------------------
-- audit_sequences: per-tenant gapless counter + running chain head.
-- Allocation happens under row lock inside the caller's transaction.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_sequences (
  tenant_id     uuid PRIMARY KEY REFERENCES tenants(id),
  next_sequence bigint NOT NULL DEFAULT 1,
  head_hash     text   NOT NULL DEFAULT repeat('0', 64),
  updated_at    timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- audit_records: append-only, hash-chained.
-- Partitioned by month so retention is a partition-detach, never a DELETE.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_records (
  tenant_id    uuid   NOT NULL,
  sequence     bigint NOT NULL,
  id           uuid   NOT NULL,
  project_id   uuid,
  action       text   NOT NULL,
  outcome      text   NOT NULL CHECK (outcome IN ('SUCCESS','DENIED','FAILURE')),
  severity     text   NOT NULL CHECK (severity IN ('INFO','NOTICE','WARNING','CRITICAL')),
  actor        jsonb  NOT NULL,
  target       jsonb  NOT NULL,
  attributes   jsonb  NOT NULL DEFAULT '{}'::jsonb,
  request_id   text   NOT NULL DEFAULT '',
  trace_id     text   NOT NULL DEFAULT '',
  occurred_at  timestamptz NOT NULL DEFAULT now(),
  prev_hash    text   NOT NULL CHECK (prev_hash  ~ '^[0-9a-f]{64}$'),
  record_hash  text   NOT NULL CHECK (record_hash ~ '^[0-9a-f]{64}$'),
  PRIMARY KEY (tenant_id, sequence, occurred_at)
) PARTITION BY RANGE (occurred_at);

-- Bootstrap partitions; the operator/scheduler creates future ones ahead of time.
CREATE TABLE audit_records_default PARTITION OF audit_records DEFAULT;

CREATE INDEX audit_records_tenant_time ON audit_records (tenant_id, occurred_at DESC);
CREATE INDEX audit_records_action      ON audit_records (tenant_id, action, occurred_at DESC);
CREATE INDEX audit_records_outcome     ON audit_records (tenant_id, outcome, occurred_at DESC);
CREATE INDEX audit_records_actor       ON audit_records USING gin (actor);

ALTER TABLE audit_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_records
  USING (tenant_id = sf_current_tenant())
  WITH CHECK (tenant_id = sf_current_tenant());

-- Append-only, enforced independently of GRANTs so a mis-granted role cannot tamper.
CREATE OR REPLACE FUNCTION sf_audit_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_records is append-only (attempted %)', TG_OP
    USING ERRCODE = '23514',
          HINT = 'Corrections are new audit records, never edits.';
END $$;

CREATE TRIGGER audit_records_no_update
  BEFORE UPDATE OR DELETE ON audit_records
  FOR EACH ROW EXECUTE FUNCTION sf_audit_append_only();

CREATE TRIGGER audit_records_default_no_update
  BEFORE UPDATE OR DELETE ON audit_records_default
  FOR EACH ROW EXECUTE FUNCTION sf_audit_append_only();

-- ---------------------------------------------------------------------------
-- audit_anchors: periodic chain heads written to WORM object storage.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_anchors (
  tenant_id   uuid   NOT NULL REFERENCES tenants(id),
  anchored_at timestamptz NOT NULL DEFAULT now(),
  sequence    bigint NOT NULL,
  head_hash   text   NOT NULL,
  storage_ref text   NOT NULL,
  PRIMARY KEY (tenant_id, anchored_at)
);

ALTER TABLE audit_anchors ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_anchors FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_anchors
  USING (tenant_id = sf_current_tenant())
  WITH CHECK (tenant_id = sf_current_tenant());

-- ---------------------------------------------------------------------------
-- outbox_events: written in the same transaction as the state change.
-- ---------------------------------------------------------------------------
CREATE TABLE outbox_events (
  id                uuid PRIMARY KEY,
  tenant_id         uuid NOT NULL,
  project_id        uuid,
  event_type        text NOT NULL,
  schema            text NOT NULL,
  schema_version    integer NOT NULL DEFAULT 1,
  aggregate_type    text NOT NULL,
  aggregate_id      text NOT NULL,
  aggregate_version integer,
  partition_key     text NOT NULL,
  payload           jsonb NOT NULL,
  payload_hash      text NOT NULL,
  correlation       jsonb NOT NULL DEFAULT '{}'::jsonb,
  actor             jsonb NOT NULL DEFAULT '{}'::jsonb,
  occurred_at       timestamptz NOT NULL DEFAULT now(),
  created_at        timestamptz NOT NULL DEFAULT now(),
  published_at      timestamptz,
  attempts          integer NOT NULL DEFAULT 0,
  last_error        text NOT NULL DEFAULT ''
);
CREATE INDEX outbox_unpublished ON outbox_events (created_at) WHERE published_at IS NULL;
CREATE INDEX outbox_tenant_type ON outbox_events (tenant_id, event_type, occurred_at DESC);

ALTER TABLE outbox_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox_events FORCE ROW LEVEL SECURITY;
-- The relay runs as a platform process without tenant context, so it needs a bypass
-- policy scoped to exactly that: reading and marking published, nothing else.
CREATE POLICY tenant_isolation ON outbox_events
  USING (tenant_id = sf_current_tenant() OR current_setting('app.relay', true) = 'on')
  WITH CHECK (tenant_id = sf_current_tenant());

-- ---------------------------------------------------------------------------
-- idempotency_keys
-- ---------------------------------------------------------------------------
CREATE TABLE idempotency_keys (
  tenant_id     uuid NOT NULL,
  key           text NOT NULL,
  request_hash  text NOT NULL,
  status        text NOT NULL CHECK (status IN ('IN_PROGRESS','COMPLETED')),
  http_status   integer,
  response_body bytea,
  principal_id  uuid NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  completed_at  timestamptz,
  expires_at    timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, key)
);
CREATE INDEX idempotency_expiry ON idempotency_keys (expires_at);

ALTER TABLE idempotency_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON idempotency_keys
  USING (tenant_id = sf_current_tenant())
  WITH CHECK (tenant_id = sf_current_tenant());

-- ---------------------------------------------------------------------------
-- processed_events: consumer-side de-duplication for at-least-once delivery.
-- ---------------------------------------------------------------------------
CREATE TABLE processed_events (
  consumer_group text NOT NULL,
  event_id       uuid NOT NULL,
  tenant_id      uuid NOT NULL,
  processed_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (consumer_group, event_id)
);
CREATE INDEX processed_events_gc ON processed_events (processed_at);

COMMIT;
