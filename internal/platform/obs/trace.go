package obs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// SpanContext is a W3C trace context.
type SpanContext struct {
	TraceID string // 32 lowercase hex characters
	SpanID  string // 16 lowercase hex characters
	Sampled bool
	Remote  bool
	// TraceState carries vendor-specific data across systems, untouched.
	TraceState string
}

func (sc SpanContext) Valid() bool {
	return len(sc.TraceID) == 32 && len(sc.SpanID) == 16 &&
		sc.TraceID != strings.Repeat("0", 32) && sc.SpanID != strings.Repeat("0", 16)
}

// TraceParent renders the W3C traceparent header value.
func (sc SpanContext) TraceParent() string {
	flags := "00"
	if sc.Sampled {
		flags = "01"
	}
	return "00-" + sc.TraceID + "-" + sc.SpanID + "-" + flags
}

// ParseTraceParent parses a W3C traceparent header.
//
// A malformed or all-zero header is rejected rather than repaired, so a caller
// cannot pin every request onto one trace by sending a fixed value.
func ParseTraceParent(v string) (SpanContext, bool) {
	parts := strings.Split(strings.TrimSpace(v), "-")
	if len(parts) != 4 || parts[0] != "00" {
		return SpanContext{}, false
	}
	sc := SpanContext{
		TraceID: strings.ToLower(parts[1]),
		SpanID:  strings.ToLower(parts[2]),
		Sampled: len(parts[3]) == 2 && parts[3][1]&0x01 == 1,
		Remote:  true,
	}
	if !isHex(sc.TraceID, 32) || !isHex(sc.SpanID, 16) || !sc.Valid() {
		return SpanContext{}, false
	}
	return sc, true
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// SpanKind mirrors the OpenTelemetry span kinds.
type SpanKind int

const (
	SpanInternal SpanKind = 1
	SpanServer   SpanKind = 2
	SpanClient   SpanKind = 3
	SpanProducer SpanKind = 4
	SpanConsumer SpanKind = 5
)

// StatusCode mirrors the OpenTelemetry status codes.
type StatusCode int

const (
	StatusUnset StatusCode = 0
	StatusOK    StatusCode = 1
	StatusError StatusCode = 2
)

// Span is a unit of work.
type Span struct {
	Name       string
	Context    SpanContext
	ParentID   string
	Kind       SpanKind
	Start      time.Time
	EndTime    time.Time
	Status     StatusCode
	StatusMsg  string
	Attributes map[string]any

	mu     sync.Mutex
	events []spanEvent
	tracer *Tracer
	ended  bool
}

type spanEvent struct {
	Name string
	Time time.Time
	Attr map[string]any
}

type spanKey struct{}

// Tracer creates spans and hands finished ones to an exporter.
type Tracer struct {
	ServiceName string
	SampleRatio float64
	exporter    Exporter
	mu          sync.Mutex
}

// Exporter receives completed spans. Implementations must be non-blocking or
// internally buffered: telemetry must never be able to stall a request.
type Exporter interface {
	ExportSpans(ctx context.Context, spans []*Span) error
	Shutdown(ctx context.Context) error
}

// NewTracer builds a tracer.
func NewTracer(serviceName string, sampleRatio float64, exp Exporter) *Tracer {
	if sampleRatio < 0 {
		sampleRatio = 0
	}
	if sampleRatio > 1 {
		sampleRatio = 1
	}
	return &Tracer{ServiceName: serviceName, SampleRatio: sampleRatio, exporter: exp}
}

// Start begins a span, continuing the trace in ctx when one is present.
func (t *Tracer) Start(ctx context.Context, name string, kind SpanKind) (context.Context, *Span) {
	parent, hasParent := SpanFrom(ctx)

	sc := SpanContext{SpanID: newSpanID()}
	var parentID string
	if hasParent && parent.Context.Valid() {
		sc.TraceID = parent.Context.TraceID
		sc.Sampled = parent.Context.Sampled
		sc.TraceState = parent.Context.TraceState
		parentID = parent.Context.SpanID
	} else if remote, ok := RemoteContextFrom(ctx); ok && remote.Valid() {
		sc.TraceID = remote.TraceID
		sc.Sampled = remote.Sampled
		sc.TraceState = remote.TraceState
		parentID = remote.SpanID
	} else {
		sc.TraceID = newTraceID()
		sc.Sampled = t.shouldSample(sc.TraceID)
	}

	s := &Span{
		Name:       name,
		Context:    sc,
		ParentID:   parentID,
		Kind:       kind,
		Start:      time.Now(),
		Attributes: map[string]any{},
		tracer:     t,
	}
	return context.WithValue(ctx, spanKey{}, s), s
}

// shouldSample uses the trace ID rather than a random draw, so every span of a
// trace makes the same decision even across processes.
func (t *Tracer) shouldSample(traceID string) bool {
	if t.SampleRatio >= 1 {
		return true
	}
	if t.SampleRatio <= 0 {
		return false
	}
	if len(traceID) < 16 {
		return false
	}
	b, err := hex.DecodeString(traceID[16:32])
	if err != nil || len(b) < 8 {
		return false
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return float64(v>>11)/float64(1<<53) < t.SampleRatio
}

// SetAttr records an attribute. Values must already be redacted: spans are
// exported to systems with weaker access control than the database.
func (s *Span) SetAttr(k string, v any) *Span {
	if s == nil {
		return s
	}
	s.mu.Lock()
	s.Attributes[k] = v
	s.mu.Unlock()
	return s
}

// AddEvent records a point-in-time event on the span.
func (s *Span) AddEvent(name string, attrs map[string]any) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.events = append(s.events, spanEvent{Name: name, Time: time.Now(), Attr: attrs})
	s.mu.Unlock()
}

// RecordError marks the span failed and records the error message.
func (s *Span) RecordError(err error) {
	if s == nil || err == nil {
		return
	}
	s.mu.Lock()
	s.Status = StatusError
	s.StatusMsg = err.Error()
	s.mu.Unlock()
	s.AddEvent("exception", map[string]any{"exception.message": err.Error()})
}

// SetStatus sets the span status explicitly.
func (s *Span) SetStatus(code StatusCode, msg string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.Status = code
	s.StatusMsg = msg
	s.mu.Unlock()
}

// End finishes the span and queues it for export. Calling End twice is a no-op
// so that `defer span.End()` alongside an explicit End is harmless.
func (s *Span) End() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return
	}
	s.ended = true
	s.EndTime = time.Now()
	s.mu.Unlock()

	if s.tracer == nil || s.tracer.exporter == nil || !s.Context.Sampled {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.tracer.exporter.ExportSpans(ctx, []*Span{s})
}

// Duration returns the span duration, or the elapsed time if still open.
func (s *Span) Duration() time.Duration {
	if s.EndTime.IsZero() {
		return time.Since(s.Start)
	}
	return s.EndTime.Sub(s.Start)
}

// Events returns a copy of the recorded events.
func (s *Span) Events() []spanEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]spanEvent, len(s.events))
	copy(out, s.events)
	return out
}

// SpanFrom returns the active span in ctx.
func SpanFrom(ctx context.Context) (*Span, bool) {
	s, ok := ctx.Value(spanKey{}).(*Span)
	return s, ok
}

// TraceIDFrom returns the current trace ID, or "".
func TraceIDFrom(ctx context.Context) string {
	if s, ok := SpanFrom(ctx); ok {
		return s.Context.TraceID
	}
	if sc, ok := RemoteContextFrom(ctx); ok {
		return sc.TraceID
	}
	return ""
}

// SpanIDFrom returns the current span ID, or "".
func SpanIDFrom(ctx context.Context) string {
	if s, ok := SpanFrom(ctx); ok {
		return s.Context.SpanID
	}
	return ""
}

type remoteKey struct{}

// WithRemoteContext stores an inbound trace context extracted at the edge.
func WithRemoteContext(ctx context.Context, sc SpanContext) context.Context {
	return context.WithValue(ctx, remoteKey{}, sc)
}

// RemoteContextFrom reads an inbound trace context.
func RemoteContextFrom(ctx context.Context) (SpanContext, bool) {
	sc, ok := ctx.Value(remoteKey{}).(SpanContext)
	return sc, ok
}

func newTraceID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("obs: crypto/rand unavailable: %v", err))
	}
	return hex.EncodeToString(b[:])
}

func newSpanID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("obs: crypto/rand unavailable: %v", err))
	}
	return hex.EncodeToString(b[:])
}
