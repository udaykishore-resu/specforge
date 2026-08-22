package obs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// NopExporter discards spans. Used in tests and when tracing is disabled.
type NopExporter struct{}

func (NopExporter) ExportSpans(context.Context, []*Span) error { return nil }
func (NopExporter) Shutdown(context.Context) error             { return nil }

// RecordingExporter keeps spans in memory. Test-only: it grows without bound.
type RecordingExporter struct {
	mu    sync.Mutex
	spans []*Span
}

func (r *RecordingExporter) ExportSpans(_ context.Context, spans []*Span) error {
	r.mu.Lock()
	r.spans = append(r.spans, spans...)
	r.mu.Unlock()
	return nil
}

func (r *RecordingExporter) Shutdown(context.Context) error { return nil }

// Spans returns a snapshot of recorded spans.
func (r *RecordingExporter) Spans() []*Span {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*Span, len(r.spans))
	copy(out, r.spans)
	return out
}

// Reset clears recorded spans.
func (r *RecordingExporter) Reset() {
	r.mu.Lock()
	r.spans = nil
	r.mu.Unlock()
}

// BatchExporter buffers spans and flushes them on an interval or when the batch
// fills. Export never blocks the caller: if the queue is full the span is
// dropped and counted, because losing telemetry is strictly better than adding
// latency to a user request.
type BatchExporter struct {
	inner    Exporter
	queue    chan *Span
	maxBatch int
	interval time.Duration
	done     chan struct{}
	wg       sync.WaitGroup
	closeOne sync.Once
}

// NewBatchExporter wraps an exporter with buffering.
func NewBatchExporter(inner Exporter, queueSize, maxBatch int, interval time.Duration) *BatchExporter {
	if queueSize <= 0 {
		queueSize = 2048
	}
	if maxBatch <= 0 {
		maxBatch = 256
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	b := &BatchExporter{
		inner:    inner,
		queue:    make(chan *Span, queueSize),
		maxBatch: maxBatch,
		interval: interval,
		done:     make(chan struct{}),
	}
	b.wg.Add(1)
	go b.run()
	return b
}

func (b *BatchExporter) ExportSpans(_ context.Context, spans []*Span) error {
	for _, s := range spans {
		select {
		case b.queue <- s:
		default:
			Counter("sf_telemetry_spans_dropped_total",
				"Spans dropped because the export queue was full", nil)
		}
	}
	return nil
}

func (b *BatchExporter) run() {
	defer b.wg.Done()
	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()

	batch := make([]*Span, 0, b.maxBatch)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := b.inner.ExportSpans(ctx, batch); err != nil {
			Counter("sf_telemetry_export_failures_total", "Failed span export batches", nil)
		}
		cancel()
		batch = batch[:0]
	}

	for {
		select {
		case s := <-b.queue:
			batch = append(batch, s)
			if len(batch) >= b.maxBatch {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-b.done:
			// Drain whatever is queued before exiting.
			for {
				select {
				case s := <-b.queue:
					batch = append(batch, s)
					if len(batch) >= b.maxBatch {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

// Shutdown flushes buffered spans and stops the worker.
func (b *BatchExporter) Shutdown(ctx context.Context) error {
	b.closeOne.Do(func() { close(b.done) })
	stopped := make(chan struct{})
	go func() { b.wg.Wait(); close(stopped) }()
	select {
	case <-stopped:
		return b.inner.Shutdown(ctx)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// OTLPExporter posts spans to an OpenTelemetry collector using OTLP/HTTP with
// the JSON encoding (the protobuf JSON mapping the specification defines).
type OTLPExporter struct {
	endpoint    string
	serviceName string
	client      *http.Client
	headers     map[string]string
}

// NewOTLPExporter builds an exporter. endpoint is the collector base URL, for
// example http://otel-collector:4318.
func NewOTLPExporter(endpoint, serviceName string, headers map[string]string) *OTLPExporter {
	return &OTLPExporter{
		endpoint:    endpoint,
		serviceName: serviceName,
		headers:     headers,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				IdleConnTimeout:     60 * time.Second,
				TLSHandshakeTimeout: 5 * time.Second,
			},
		},
	}
}

func (e *OTLPExporter) ExportSpans(ctx context.Context, spans []*Span) error {
	if len(spans) == 0 || e.endpoint == "" {
		return nil
	}
	payload := e.encode(spans)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("obs: encoding OTLP payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		e.endpoint+"/v1/traces", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("obs: building OTLP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range e.headers {
		req.Header.Set(k, v)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("obs: posting spans: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("obs: collector returned %s", resp.Status)
	}
	return nil
}

func (e *OTLPExporter) Shutdown(context.Context) error {
	e.client.CloseIdleConnections()
	return nil
}

// encode renders spans in the OTLP JSON structure.
func (e *OTLPExporter) encode(spans []*Span) map[string]any {
	out := make([]map[string]any, 0, len(spans))
	for _, s := range spans {
		attrs := make([]map[string]any, 0, len(s.Attributes))
		for k, v := range s.Attributes {
			attrs = append(attrs, otlpAttr(k, v))
		}

		events := make([]map[string]any, 0)
		for _, ev := range s.Events() {
			eattrs := make([]map[string]any, 0, len(ev.Attr))
			for k, v := range ev.Attr {
				eattrs = append(eattrs, otlpAttr(k, v))
			}
			events = append(events, map[string]any{
				"name":         ev.Name,
				"timeUnixNano": nanos(ev.Time),
				"attributes":   eattrs,
			})
		}

		span := map[string]any{
			"traceId":           s.Context.TraceID,
			"spanId":            s.Context.SpanID,
			"name":              s.Name,
			"kind":              int(s.Kind),
			"startTimeUnixNano": nanos(s.Start),
			"endTimeUnixNano":   nanos(s.EndTime),
			"attributes":        attrs,
			"events":            events,
			"status":            map[string]any{"code": int(s.Status), "message": s.StatusMsg},
		}
		if s.ParentID != "" {
			span["parentSpanId"] = s.ParentID
		}
		out = append(out, span)
	}

	return map[string]any{
		"resourceSpans": []map[string]any{{
			"resource": map[string]any{
				"attributes": []map[string]any{
					otlpAttr("service.name", e.serviceName),
					otlpAttr("telemetry.sdk.name", "specforge"),
					otlpAttr("telemetry.sdk.language", "go"),
				},
			},
			"scopeSpans": []map[string]any{{
				"scope": map[string]any{"name": "github.com/specforge/specforge"},
				"spans": out,
			}},
		}},
	}
}

func otlpAttr(k string, v any) map[string]any {
	var val map[string]any
	switch t := v.(type) {
	case string:
		val = map[string]any{"stringValue": t}
	case bool:
		val = map[string]any{"boolValue": t}
	case int:
		val = map[string]any{"intValue": strconv.Itoa(t)}
	case int64:
		val = map[string]any{"intValue": strconv.FormatInt(t, 10)}
	case float64:
		val = map[string]any{"doubleValue": t}
	case time.Duration:
		val = map[string]any{"intValue": strconv.FormatInt(t.Milliseconds(), 10)}
	default:
		val = map[string]any{"stringValue": fmt.Sprint(t)}
	}
	return map[string]any{"key": k, "value": val}
}

func nanos(t time.Time) string {
	if t.IsZero() {
		return "0"
	}
	return strconv.FormatInt(t.UnixNano(), 10)
}
