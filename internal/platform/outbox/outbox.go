// Package outbox implements the transactional outbox pattern.
//
// Domain events are written to outbox_events inside the same transaction as the
// state change that produced them. A relay publishes them afterwards. This
// removes the dual-write failure mode entirely: there is no code path where a
// state change commits without its event, or an event is published for a change
// that rolled back.
//
// Delivery is at-least-once; consumers de-duplicate on event_id.
package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/specforge/specforge/internal/platform/db"
	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/hash"
	"github.com/specforge/specforge/internal/platform/id"
	"github.com/specforge/specforge/internal/platform/jcs"
	"github.com/specforge/specforge/internal/platform/obs"
	"github.com/specforge/specforge/internal/platform/types"
)

// Envelope is the wire format of every domain event.
type Envelope struct {
	EventID       string           `json:"event_id"`
	EventType     string           `json:"event_type"`
	Schema        string           `json:"schema"`
	SchemaVersion int              `json:"schema_version"`
	OccurredAt    time.Time        `json:"occurred_at"`
	RecordedAt    time.Time        `json:"recorded_at,omitempty"`
	TenantID      types.TenantID   `json:"tenant_id"`
	ProjectID     *types.ProjectID `json:"project_id,omitempty"`
	Aggregate     Aggregate        `json:"aggregate"`
	Actor         Actor            `json:"actor"`
	Correlation   Correlation      `json:"correlation"`
	Payload       json.RawMessage  `json:"payload"`
	PayloadHash   string           `json:"payload_hash"`
}

// Aggregate identifies what changed.
type Aggregate struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Version int    `json:"version,omitempty"`
}

// Actor identifies who or what caused the change.
type Actor struct {
	Kind        string `json:"kind"` // USER | SERVICE_ACCOUNT | SYSTEM
	PrincipalID string `json:"principal_id,omitempty"`
	Display     string `json:"display,omitempty"`
	OnBehalfOf  string `json:"on_behalf_of,omitempty"`
}

// Correlation carries the identifiers that let any signal be joined to any other.
type Correlation struct {
	TraceID        string `json:"trace_id,omitempty"`
	SpanID         string `json:"span_id,omitempty"`
	RequestID      string `json:"request_id,omitempty"`
	CausationID    string `json:"causation_id,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

// PartitionKey determines ordering. Events for one aggregate are strictly
// ordered; there is no global ordering guarantee and no consumer needs one.
func (e Envelope) PartitionKey() string {
	return string(e.TenantID) + ":" + e.Aggregate.ID
}

// New builds an envelope, computing the payload hash so a consumer can detect
// tampering in the log independently of broker guarantees.
func New(
	eventType string,
	tenantID types.TenantID,
	projectID *types.ProjectID,
	agg Aggregate,
	actor Actor,
	corr Correlation,
	payload any,
) (Envelope, error) {
	canonical, err := jcs.Canonicalize(payload)
	if err != nil {
		return Envelope{}, fmt.Errorf("outbox: canonicalizing payload for %s: %w", eventType, err)
	}
	return Envelope{
		EventID:       id.NewUUIDv7(),
		EventType:     eventType,
		Schema:        "specforge.event." + eventType,
		SchemaVersion: 1,
		OccurredAt:    types.Now(),
		TenantID:      tenantID,
		ProjectID:     projectID,
		Aggregate:     agg,
		Actor:         actor,
		Correlation:   corr,
		Payload:       canonical,
		PayloadHash:   "sha256:" + hash.Sum(canonical),
	}, nil
}

// Writer appends events inside a caller's transaction.
type Writer interface {
	Append(ctx context.Context, tx db.Tx, events ...Envelope) error
}

// Publisher delivers events to the message log.
type Publisher interface {
	Publish(ctx context.Context, envelopes []Envelope) error
	Close() error
}

// Store is the outbox table.
type Store struct{}

// NewStore builds the outbox writer.
func NewStore() *Store { return &Store{} }

const insertSQL = `
INSERT INTO outbox_events (
  id, tenant_id, project_id, event_type, schema, schema_version,
  aggregate_type, aggregate_id, aggregate_version, partition_key,
  payload, payload_hash, correlation, actor, occurred_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13::jsonb,$14::jsonb,$15)`

// Append writes events in the caller's transaction. If the transaction rolls
// back, so do the events — which is the entire point.
func (s *Store) Append(ctx context.Context, tx db.Tx, events ...Envelope) error {
	const op = "outbox.Append"
	for _, e := range events {
		corr, err := json.Marshal(e.Correlation)
		if err != nil {
			return errors.Wrap(err, op, errors.KindInternal, "outbox.encode_failed",
				"Could not encode event correlation data.")
		}
		actor, err := json.Marshal(e.Actor)
		if err != nil {
			return errors.Wrap(err, op, errors.KindInternal, "outbox.encode_failed",
				"Could not encode event actor data.")
		}
		var projectID any
		if e.ProjectID != nil {
			projectID = e.ProjectID.String()
		}
		var aggVersion any
		if e.Aggregate.Version > 0 {
			aggVersion = int64(e.Aggregate.Version)
		}

		_, err = tx.ExecContext(ctx, insertSQL,
			e.EventID, e.TenantID.String(), projectID, e.EventType, e.Schema,
			int64(e.SchemaVersion), e.Aggregate.Type, e.Aggregate.ID, aggVersion,
			e.PartitionKey(), string(e.Payload), e.PayloadHash,
			string(corr), string(actor), e.OccurredAt)
		if err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "outbox.append_failed",
				"Could not record the domain event.")
		}
		obs.Counter("sf_outbox_appended_total", "Events appended to the outbox",
			obs.Labels{"event_type": e.EventType})
	}
	return nil
}

// ---------------------------------------------------------------------------
// Relay
// ---------------------------------------------------------------------------

// RelayConfig tunes the publishing loop.
type RelayConfig struct {
	BatchSize   int
	Interval    time.Duration
	MaxAttempts int
}

// Relay polls the outbox and publishes.
//
// FOR UPDATE SKIP LOCKED lets several relay replicas run concurrently without
// contending or double-publishing within a batch. A crash between publishing and
// marking a row published produces a duplicate, which consumer idempotency absorbs.
type Relay struct {
	db     *db.DB
	pub    Publisher
	cfg    RelayConfig
	logger *slog.Logger
}

// NewRelay builds a relay.
func NewRelay(database *db.DB, pub Publisher, cfg RelayConfig, logger *slog.Logger) *Relay {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 200
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 500 * time.Millisecond
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 8
	}
	return &Relay{db: database, pub: pub, cfg: cfg, logger: logger}
}

const selectPendingSQL = `
SELECT id, tenant_id, project_id, event_type, schema, schema_version,
       aggregate_type, aggregate_id, coalesce(aggregate_version, 0),
       payload, payload_hash, correlation, actor, occurred_at, attempts
  FROM outbox_events
 WHERE published_at IS NULL
   AND attempts < $1
 ORDER BY created_at
 FOR UPDATE SKIP LOCKED
 LIMIT $2`

// Run publishes pending events until the context is cancelled.
func (r *Relay) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			n, err := r.PublishBatch(ctx)
			if err != nil && !errors.Is(err, context.Canceled) {
				r.logger.ErrorContext(ctx, "outbox relay batch failed", "error", err)
				obs.Counter("sf_outbox_relay_errors_total", "Relay batch failures", nil)
			}
			if n == r.cfg.BatchSize {
				// A full batch means there is more waiting; do not sleep.
				ticker.Reset(time.Millisecond)
			} else {
				ticker.Reset(r.cfg.Interval)
			}
		}
	}
}

// PublishBatch publishes one batch and returns how many events were handled.
func (r *Relay) PublishBatch(ctx context.Context) (int, error) {
	relayCtx := db.WithRelaySession(ctx)

	var published int
	err := r.db.Tx(relayCtx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.QueryContext(ctx, selectPendingSQL,
			int64(r.cfg.MaxAttempts), int64(r.cfg.BatchSize))
		if err != nil {
			return fmt.Errorf("outbox: selecting pending events: %w", err)
		}

		var (
			envelopes []Envelope
			ids       []string
		)
		for rows.Next() {
			var (
				e         Envelope
				projectID *string
				corrRaw   []byte
				actorRaw  []byte
				attempts  int64
				aggVer    int64
				tenantID  string
			)
			if err := rows.Scan(&e.EventID, &tenantID, &projectID, &e.EventType, &e.Schema,
				&e.SchemaVersion, &e.Aggregate.Type, &e.Aggregate.ID, &aggVer,
				&e.Payload, &e.PayloadHash, &corrRaw, &actorRaw, &e.OccurredAt, &attempts); err != nil {
				_ = rows.Close()
				return fmt.Errorf("outbox: scanning event: %w", err)
			}
			e.TenantID = types.TenantID(tenantID)
			if projectID != nil {
				pid := types.ProjectID(*projectID)
				e.ProjectID = &pid
			}
			e.Aggregate.Version = int(aggVer)
			_ = json.Unmarshal(corrRaw, &e.Correlation)
			_ = json.Unmarshal(actorRaw, &e.Actor)
			e.RecordedAt = types.Now()

			envelopes = append(envelopes, e)
			ids = append(ids, e.EventID)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return fmt.Errorf("outbox: iterating events: %w", err)
		}
		_ = rows.Close()

		if len(envelopes) == 0 {
			return nil
		}

		if err := r.pub.Publish(ctx, envelopes); err != nil {
			// Record the attempt so a permanently failing event eventually stops
			// blocking the batch and surfaces for triage.
			for _, eid := range ids {
				_, _ = tx.ExecContext(ctx,
					`UPDATE outbox_events SET attempts = attempts + 1, last_error = $2 WHERE id = $1`,
					eid, truncate(err.Error(), 500))
			}
			return fmt.Errorf("outbox: publishing batch: %w", err)
		}

		for _, eid := range ids {
			if _, err := tx.ExecContext(ctx,
				`UPDATE outbox_events SET published_at = now() WHERE id = $1`, eid); err != nil {
				return fmt.Errorf("outbox: marking published: %w", err)
			}
		}
		published = len(envelopes)
		for _, e := range envelopes {
			obs.Counter("sf_outbox_published_total", "Events published from the outbox",
				obs.Labels{"event_type": e.EventType})
			obs.Observe("sf_outbox_age_seconds", "Delay between event occurrence and publication",
				nil, time.Since(e.OccurredAt).Seconds())
		}
		return nil
	})

	return published, err
}

// PendingCount reports how many events await publication, for alerting.
func (r *Relay) PendingCount(ctx context.Context) (int64, error) {
	var n int64
	err := r.db.SQL().QueryRowContext(ctx,
		`SELECT count(*) FROM outbox_events WHERE published_at IS NULL`).Scan(&n)
	return n, err
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
