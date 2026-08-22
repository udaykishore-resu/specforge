// Package eventbus publishes domain events and dispatches them to consumers.
//
// Two publishers ship:
//
//   - InProcess: consumers run in the same process. Used for local development
//     and tests. It is a real implementation with real de-duplication and DLQ
//     behaviour, not a stub.
//   - FileLog: an append-only, per-topic log on disk with the same envelope
//     format as the Kafka topics. It gives durable, replayable events without a
//     broker, which makes the whole platform demonstrable offline.
//
// A Kafka-compatible publisher plugs into the same interface for production.
package eventbus

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/specforge/specforge/internal/platform/obs"
	"github.com/specforge/specforge/internal/platform/outbox"
)

// Handler processes one event. Handlers must be idempotent: delivery is
// at-least-once and a handler may see the same event_id more than once.
type Handler func(ctx context.Context, e outbox.Envelope) error

// Subscription binds a handler to event types.
type Subscription struct {
	// ConsumerGroup names the logical consumer for de-duplication and lag metrics.
	ConsumerGroup string
	// EventTypes to receive. A trailing "*" matches a prefix, e.g. "artifact.*".
	EventTypes []string
	Handler    Handler
	// MaxAttempts before the event goes to the dead-letter queue.
	MaxAttempts int
}

func (s Subscription) matches(eventType string) bool {
	for _, pattern := range s.EventTypes {
		if pattern == "*" {
			return true
		}
		if strings.HasSuffix(pattern, "*") {
			if strings.HasPrefix(eventType, strings.TrimSuffix(pattern, "*")) {
				return true
			}
			continue
		}
		if pattern == eventType {
			return true
		}
	}
	return false
}

// DeadLetter records an event that exhausted its retries.
type DeadLetter struct {
	Envelope      outbox.Envelope `json:"envelope"`
	ConsumerGroup string          `json:"consumer_group"`
	Attempts      int             `json:"attempts"`
	LastError     string          `json:"last_error"`
	FailedAt      time.Time       `json:"failed_at"`
}

// InProcess dispatches events to in-process handlers.
type InProcess struct {
	mu      sync.RWMutex
	subs    []Subscription
	seen    map[string]time.Time // consumerGroup|eventID -> when processed
	dlq     []DeadLetter
	logger  *slog.Logger
	seenTTL time.Duration
}

// NewInProcess builds an in-process bus.
func NewInProcess(logger *slog.Logger) *InProcess {
	return &InProcess{
		seen:    map[string]time.Time{},
		logger:  logger,
		seenTTL: time.Hour,
	}
}

// Subscribe registers a handler.
func (b *InProcess) Subscribe(s Subscription) {
	if s.MaxAttempts <= 0 {
		s.MaxAttempts = 3
	}
	b.mu.Lock()
	b.subs = append(b.subs, s)
	b.mu.Unlock()
}

// Publish dispatches events to matching handlers.
func (b *InProcess) Publish(ctx context.Context, envelopes []outbox.Envelope) error {
	b.mu.RLock()
	subs := make([]Subscription, len(b.subs))
	copy(subs, b.subs)
	b.mu.RUnlock()

	for _, e := range envelopes {
		for _, s := range subs {
			if !s.matches(e.EventType) {
				continue
			}
			b.deliver(ctx, s, e)
		}
	}
	return nil
}

func (b *InProcess) deliver(ctx context.Context, s Subscription, e outbox.Envelope) {
	key := s.ConsumerGroup + "|" + e.EventID

	b.mu.Lock()
	if _, dup := b.seen[key]; dup {
		b.mu.Unlock()
		obs.Counter("sf_events_deduplicated_total", "Duplicate events skipped by a consumer",
			obs.Labels{"group": s.ConsumerGroup})
		return
	}
	b.mu.Unlock()

	var lastErr error
	for attempt := 1; attempt <= s.MaxAttempts; attempt++ {
		start := time.Now()
		err := s.Handler(ctx, e)
		obs.Observe("sf_event_handler_duration_seconds", "Event handler duration",
			obs.Labels{"group": s.ConsumerGroup, "event_type": e.EventType},
			time.Since(start).Seconds())

		if err == nil {
			b.mu.Lock()
			b.seen[key] = time.Now()
			b.gcSeenLocked()
			b.mu.Unlock()
			obs.Counter("sf_events_handled_total", "Events handled",
				obs.Labels{"group": s.ConsumerGroup, "event_type": e.EventType, "outcome": "success"})
			return
		}
		lastErr = err

		if attempt < s.MaxAttempts {
			// Exponential backoff with a cap; jitter is unnecessary in-process
			// because there is no thundering herd across replicas.
			delay := time.Duration(1<<uint(attempt-1)) * 50 * time.Millisecond
			if delay > 2*time.Second {
				delay = 2 * time.Second
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
	}

	b.mu.Lock()
	b.dlq = append(b.dlq, DeadLetter{
		Envelope: e, ConsumerGroup: s.ConsumerGroup,
		Attempts: s.MaxAttempts, LastError: lastErr.Error(), FailedAt: time.Now(),
	})
	b.mu.Unlock()

	obs.Counter("sf_events_handled_total", "Events handled",
		obs.Labels{"group": s.ConsumerGroup, "event_type": e.EventType, "outcome": "dead_letter"})
	b.logger.Error("event moved to dead-letter queue",
		"group", s.ConsumerGroup, "event_type", e.EventType,
		"event_id", e.EventID, "error", lastErr)
}

// gcSeenLocked drops de-duplication entries past their TTL. Callers hold b.mu.
func (b *InProcess) gcSeenLocked() {
	if len(b.seen) < 10000 {
		return
	}
	cutoff := time.Now().Add(-b.seenTTL)
	for k, t := range b.seen {
		if t.Before(cutoff) {
			delete(b.seen, k)
		}
	}
}

// DeadLetters returns a snapshot of the dead-letter queue.
func (b *InProcess) DeadLetters() []DeadLetter {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]DeadLetter, len(b.dlq))
	copy(out, b.dlq)
	return out
}

// Close releases resources.
func (b *InProcess) Close() error { return nil }

// ---------------------------------------------------------------------------
// FileLog
// ---------------------------------------------------------------------------

// FileLog appends events to per-topic NDJSON files. Durable and replayable with
// no broker, and the envelope format matches the Kafka topics exactly, so a
// local recording can be replayed into a real cluster.
type FileLog struct {
	dir         string
	topicPrefix string
	mu          sync.Mutex
	files       map[string]*os.File
	fanout      Publisher
}

// Publisher is the interface both publishers satisfy (and outbox.Publisher too).
type Publisher interface {
	Publish(ctx context.Context, envelopes []outbox.Envelope) error
	Close() error
}

// NewFileLog creates a durable file-backed publisher. If fanout is non-nil,
// events are also delivered to it after being persisted, so in-process consumers
// still run while the log stays authoritative.
func NewFileLog(dir, topicPrefix string, fanout Publisher) (*FileLog, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("eventbus: creating log directory: %w", err)
	}
	return &FileLog{
		dir: dir, topicPrefix: topicPrefix,
		files: map[string]*os.File{}, fanout: fanout,
	}, nil
}

// topicFor maps an event type onto its topic, mirroring the production layout
// described in docs/architecture/04-event-model.md §4.
func (f *FileLog) topicFor(eventType string) string {
	family := eventType
	if i := strings.Index(eventType, "."); i > 0 {
		family = eventType[:i]
	}
	switch family {
	case "artifact", "trace_link":
		return f.topicPrefix + "artifact.v1"
	case "prd":
		return f.topicPrefix + "prd.v1"
	case "gate", "governance", "disposition", "exception", "policy":
		return f.topicPrefix + "governance.v1"
	case "pipeline", "deployment":
		return f.topicPrefix + "delivery.v1"
	case "pod", "workload", "slo", "incident", "runtime", "cost":
		return f.topicPrefix + "runtime.v1"
	case "inference", "guardrail", "prompt", "model", "ai":
		return f.topicPrefix + "ai.v1"
	case "tenant", "project", "principal", "role":
		return f.topicPrefix + "tenancy.v1"
	case "audit":
		return f.topicPrefix + "audit.v1"
	default:
		return f.topicPrefix + "domain.v1"
	}
}

func (f *FileLog) Publish(ctx context.Context, envelopes []outbox.Envelope) error {
	f.mu.Lock()
	for _, e := range envelopes {
		topic := f.topicFor(e.EventType)
		fh, ok := f.files[topic]
		if !ok {
			path := filepath.Join(f.dir, topic+".ndjson")
			var err error
			fh, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
			if err != nil {
				f.mu.Unlock()
				return fmt.Errorf("eventbus: opening topic log %s: %w", topic, err)
			}
			f.files[topic] = fh
		}
		line, err := json.Marshal(e)
		if err != nil {
			f.mu.Unlock()
			return fmt.Errorf("eventbus: encoding event %s: %w", e.EventID, err)
		}
		if _, err := fh.Write(append(line, '\n')); err != nil {
			f.mu.Unlock()
			return fmt.Errorf("eventbus: appending to topic %s: %w", topic, err)
		}
		obs.Counter("sf_events_published_total", "Events published",
			obs.Labels{"topic": topic, "event_type": e.EventType})
	}
	// Durability before dispatch: a consumer must never observe an event that is
	// not in the log, or replay would lose it.
	for _, fh := range f.files {
		_ = fh.Sync()
	}
	f.mu.Unlock()

	if f.fanout != nil {
		return f.fanout.Publish(ctx, envelopes)
	}
	return nil
}

// Close flushes and closes every open topic file.
func (f *FileLog) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var firstErr error
	for _, fh := range f.files {
		if err := fh.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	f.files = map[string]*os.File{}
	if f.fanout != nil {
		if err := f.fanout.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Replay reads a topic log and delivers every event to fn, for projection
// rebuilds and for replaying a dead-letter batch.
func (f *FileLog) Replay(ctx context.Context, topic string, since time.Time, fn Handler) error {
	path := filepath.Join(f.dir, topic+".ndjson")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("eventbus: reading topic log: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e outbox.Envelope
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return fmt.Errorf("eventbus: decoding logged event: %w", err)
		}
		if !since.IsZero() && e.OccurredAt.Before(since) {
			continue
		}
		if err := fn(ctx, e); err != nil {
			return fmt.Errorf("eventbus: replaying %s: %w", e.EventID, err)
		}
	}
	return nil
}
