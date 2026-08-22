// Package log configures structured logging and enforces redaction.
//
// The redaction handler is the important part. Logging is the easiest way to
// leak tenant content, credentials and PII into a system that has weaker access
// controls than the database it came from, so redaction happens in the handler
// rather than relying on every call site to remember.
package log

import (
	"context"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
)

// Context keys for correlation fields injected into every record.
type ctxKey int

const (
	ctxFields ctxKey = iota
)

// Fields carries correlation attributes through a request or job.
type Fields struct {
	TraceID     string
	SpanID      string
	RequestID   string
	TenantID    string
	ProjectID   string
	PrincipalID string
	Extra       []slog.Attr
}

// WithFields attaches correlation fields to the context.
func WithFields(ctx context.Context, f Fields) context.Context {
	if existing, ok := ctx.Value(ctxFields).(Fields); ok {
		if f.TraceID == "" {
			f.TraceID = existing.TraceID
		}
		if f.SpanID == "" {
			f.SpanID = existing.SpanID
		}
		if f.RequestID == "" {
			f.RequestID = existing.RequestID
		}
		if f.TenantID == "" {
			f.TenantID = existing.TenantID
		}
		if f.ProjectID == "" {
			f.ProjectID = existing.ProjectID
		}
		if f.PrincipalID == "" {
			f.PrincipalID = existing.PrincipalID
		}
		f.Extra = append(existing.Extra, f.Extra...)
	}
	return context.WithValue(ctx, ctxFields, f)
}

// FieldsFrom reads correlation fields from the context.
func FieldsFrom(ctx context.Context) (Fields, bool) {
	f, ok := ctx.Value(ctxFields).(Fields)
	return f, ok
}

// Options configures the logger.
type Options struct {
	Level       string // debug | info | warn | error
	Format      string // json | text
	ServiceName string
	Version     string
	Env         string
	Output      io.Writer
	// AddSource includes the caller position. Off in production: it is expensive
	// and the operation/code fields are more useful anyway.
	AddSource bool
}

// New builds a logger with correlation and redaction handlers installed.
func New(opts Options) *slog.Logger {
	out := opts.Output
	if out == nil {
		out = os.Stdout
	}

	var level slog.Level
	switch strings.ToLower(opts.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	ho := &slog.HandlerOptions{Level: level, AddSource: opts.AddSource}

	var base slog.Handler
	if strings.EqualFold(opts.Format, "text") {
		base = slog.NewTextHandler(out, ho)
	} else {
		base = slog.NewJSONHandler(out, ho)
	}

	h := &redactHandler{inner: &correlationHandler{inner: base}}

	logger := slog.New(h)
	attrs := []any{}
	if opts.ServiceName != "" {
		attrs = append(attrs, slog.String("service", opts.ServiceName))
	}
	if opts.Version != "" {
		attrs = append(attrs, slog.String("version", opts.Version))
	}
	if opts.Env != "" {
		attrs = append(attrs, slog.String("env", opts.Env))
	}
	if len(attrs) > 0 {
		logger = logger.With(attrs...)
	}
	return logger
}

// correlationHandler copies context fields onto every record so that a log line
// can always be joined to a trace, a tenant and a request.
type correlationHandler struct{ inner slog.Handler }

func (h *correlationHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *correlationHandler) Handle(ctx context.Context, r slog.Record) error {
	if f, ok := FieldsFrom(ctx); ok {
		add := func(k, v string) {
			if v != "" {
				r.AddAttrs(slog.String(k, v))
			}
		}
		add("trace_id", f.TraceID)
		add("span_id", f.SpanID)
		add("request_id", f.RequestID)
		add("tenant_id", f.TenantID)
		add("project_id", f.ProjectID)
		add("principal_id", f.PrincipalID)
		for _, a := range f.Extra {
			r.AddAttrs(a)
		}
	}
	return h.inner.Handle(ctx, r)
}

func (h *correlationHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &correlationHandler{inner: h.inner.WithAttrs(as)}
}
func (h *correlationHandler) WithGroup(name string) slog.Handler {
	return &correlationHandler{inner: h.inner.WithGroup(name)}
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

// sensitiveKeys are attribute names whose values are always replaced.
var sensitiveKeys = map[string]bool{
	"password": true, "passwd": true, "secret": true, "token": true,
	"access_token": true, "refresh_token": true, "id_token": true,
	"api_key": true, "apikey": true, "authorization": true, "cookie": true,
	"set-cookie": true, "client_secret": true, "private_key": true,
	"secret_hash": true, "dsn": true, "connection_string": true,
	"prompt": true, "completion": true, "content": true, "body": true,
	"email": true, "phone": true, "ssn": true, "national_id": true,
}

// secretPatterns catch credentials that arrive inside free-text messages.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/-]{16,}`),
	regexp.MustCompile(`sf_[a-z]+_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}`),                    // SpecForge API keys
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), // JWTs
	regexp.MustCompile(`(?i)(password|secret|token)\s*[=:]\s*\S+`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
}

const redacted = "***redacted***"

type redactHandler struct{ inner slog.Handler }

func (h *redactHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *redactHandler) Handle(ctx context.Context, r slog.Record) error {
	clean := slog.NewRecord(r.Time, r.Level, redactString(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		clean.AddAttrs(redactAttr(a))
		return true
	})
	return h.inner.Handle(ctx, clean)
}

func (h *redactHandler) WithAttrs(as []slog.Attr) slog.Handler {
	out := make([]slog.Attr, len(as))
	for i, a := range as {
		out[i] = redactAttr(a)
	}
	return &redactHandler{inner: h.inner.WithAttrs(out)}
}

func (h *redactHandler) WithGroup(name string) slog.Handler {
	return &redactHandler{inner: h.inner.WithGroup(name)}
}

func redactAttr(a slog.Attr) slog.Attr {
	if sensitiveKeys[strings.ToLower(a.Key)] {
		return slog.String(a.Key, redacted)
	}
	switch a.Value.Kind() {
	case slog.KindString:
		return slog.String(a.Key, redactString(a.Value.String()))
	case slog.KindGroup:
		attrs := a.Value.Group()
		out := make([]any, 0, len(attrs))
		for _, g := range attrs {
			out = append(out, redactAttr(g))
		}
		return slog.Group(a.Key, out...)
	default:
		return a
	}
}

func redactString(s string) string {
	if s == "" {
		return s
	}
	for _, re := range secretPatterns {
		s = re.ReplaceAllString(s, redacted)
	}
	return s
}

// RedactString exposes the free-text redactor for use outside logging, for
// example when normalising an upstream error before returning it.
func RedactString(s string) string { return redactString(s) }

// FromContext returns a logger carrying the context's correlation fields.
// The returned logger still requires a context on each call for handler-level
// correlation, so prefer logger.InfoContext(ctx, ...) at call sites.
func FromContext(ctx context.Context, base *slog.Logger) *slog.Logger {
	if base == nil {
		base = slog.Default()
	}
	return base
}
