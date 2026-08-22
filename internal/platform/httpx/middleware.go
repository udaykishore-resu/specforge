package httpx

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/id"
	"github.com/specforge/specforge/internal/platform/log"
	"github.com/specforge/specforge/internal/platform/obs"
)

// Middleware wraps a handler.
type Middleware func(http.Handler) http.Handler

// Chain composes middleware so that the first listed runs outermost.
//
// The order in Server.routes is fixed and tested, because getting it wrong is a
// security bug rather than a style question: recovery must be outermost so a
// panic still produces a response, and authorization must run after tenant
// resolution so it has a tenant to compare against.
func Chain(mw ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for i := len(mw) - 1; i >= 0; i-- {
			next = mw[i](next)
		}
		return next
	}
}

type ctxKey int

const (
	ctxRequestID ctxKey = iota
	ctxRoutePattern
)

// RequestIDFrom returns the request correlation id.
func RequestIDFrom(ctx context.Context) string {
	v, _ := ctx.Value(ctxRequestID).(string)
	return v
}

// RoutePatternFrom returns the templated route, for low-cardinality metrics.
func RoutePatternFrom(ctx context.Context) string {
	v, _ := ctx.Value(ctxRoutePattern).(string)
	return v
}

// WithRoutePattern records the templated route on the context.
func WithRoutePattern(ctx context.Context, pattern string) context.Context {
	return context.WithValue(ctx, ctxRoutePattern, pattern)
}

// responseWriter captures the status and size for logging and metrics.
type responseWriter struct {
	http.ResponseWriter
	status  int
	written int64
	hijack  bool
}

func (w *responseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.written += int64(n)
	return n, err
}

// Flush supports streaming responses (SSE).
func (w *responseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		if w.status == 0 {
			w.status = http.StatusOK
		}
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Recoverer converts a panic into a 500 problem response and keeps the process
// alive. It is the outermost middleware so nothing above it can panic unhandled.
func Recoverer(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					if rec == http.ErrAbortHandler {
						panic(rec)
					}
					logger.ErrorContext(r.Context(), "panic recovered",
						"panic", fmt.Sprint(rec),
						"stack", string(debug.Stack()),
						"method", r.Method, "path", r.URL.Path)
					obs.Counter("sf_http_panics_total", "Recovered handler panics", nil)

					err := errors.Internal("httpx.Recoverer", "internal.error",
						"An internal error occurred.")
					WriteProblem(w, r, err, nil)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// RequestID assigns or propagates a correlation id.
func RequestID() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rid := r.Header.Get("X-Request-Id")
			// An inbound id is only trusted for correlation, never for anything
			// with authority, and is length-bounded so it cannot bloat logs.
			if rid == "" || len(rid) > 128 || !isPrintableASCII(rid) {
				rid = id.NewRequestID()
			}
			ctx := context.WithValue(r.Context(), ctxRequestID, rid)
			ctx = log.WithFields(ctx, log.Fields{RequestID: rid})
			w.Header().Set("X-Request-Id", rid)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Tracing starts a server span and propagates W3C trace context.
func Tracing(tracer *obs.Tracer) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if tp := r.Header.Get("traceparent"); tp != "" {
				if sc, ok := obs.ParseTraceParent(tp); ok {
					sc.TraceState = r.Header.Get("tracestate")
					ctx = obs.WithRemoteContext(ctx, sc)
				}
			}

			ctx, span := tracer.Start(ctx, "http.server.request", obs.SpanServer)
			defer span.End()

			span.SetAttr("http.request.method", r.Method)
			span.SetAttr("url.path", r.URL.Path)
			span.SetAttr("http.route", RoutePatternFrom(ctx))
			span.SetAttr("request.id", RequestIDFrom(ctx))

			ctx = log.WithFields(ctx, log.Fields{
				TraceID: span.Context.TraceID,
				SpanID:  span.Context.SpanID,
			})
			w.Header().Set("traceparent", span.Context.TraceParent())

			rw := &responseWriter{ResponseWriter: w}
			next.ServeHTTP(rw, r.WithContext(ctx))

			span.SetAttr("http.response.status_code", rw.status)
			if rw.status >= 500 {
				span.SetStatus(obs.StatusError, http.StatusText(rw.status))
			}
		})
	}
}

// Logging records one structured line per request.
func Logging(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w}

			next.ServeHTTP(rw, r)

			status := rw.status
			if status == 0 {
				status = http.StatusOK
			}
			route := RoutePatternFrom(r.Context())
			if route == "" {
				route = "unmatched"
			}
			duration := time.Since(start)

			level := slog.LevelInfo
			switch {
			case status >= 500:
				level = slog.LevelError
			case status >= 400:
				level = slog.LevelWarn
			case r.Method == http.MethodGet:
				level = slog.LevelDebug
			}

			logger.Log(r.Context(), level, "http request",
				"method", r.Method, "route", route, "path", r.URL.Path,
				"status", status, "duration_ms", duration.Milliseconds(),
				"bytes", rw.written, "remote", clientIP(r))

			obs.Counter("sf_http_requests_total", "HTTP requests",
				obs.Labels{"route": route, "method": r.Method, "status": strconv.Itoa(status)})
			obs.Observe("sf_http_request_duration_seconds", "HTTP request duration",
				obs.Labels{"route": route, "method": r.Method}, duration.Seconds())
		})
	}
}

// SecurityHeaders applies the standard response hardening headers.
func SecurityHeaders(isProduction bool) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()")
			// The API returns JSON only; a restrictive CSP means a reflected
			// payload cannot execute even if one were ever echoed.
			h.Set("Content-Security-Policy",
				"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
			if isProduction {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CORSOptions configures cross-origin access.
type CORSOptions struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
	ExposeHeaders  []string
	MaxAge         time.Duration
}

// CORS applies an explicit origin allowlist.
//
// There is no wildcard support. Credentials are allowed only for exactly
// matched origins, because "*" plus credentials is either rejected by browsers
// or a serious hole wherever it is honoured.
func CORS(opts CORSOptions) Middleware {
	allowed := make(map[string]bool, len(opts.AllowedOrigins))
	for _, o := range opts.AllowedOrigins {
		allowed[strings.TrimRight(o, "/")] = true
	}
	methods := strings.Join(defaultIfEmpty(opts.AllowedMethods,
		[]string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}), ", ")
	headers := strings.Join(defaultIfEmpty(opts.AllowedHeaders,
		[]string{"Authorization", "Content-Type", "X-Request-Id", "Idempotency-Key", "If-Match", "traceparent"}), ", ")
	expose := strings.Join(defaultIfEmpty(opts.ExposeHeaders,
		[]string{"X-Request-Id", "traceparent", "RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset"}), ", ")
	maxAge := opts.MaxAge
	if maxAge <= 0 {
		maxAge = 10 * time.Minute
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := strings.TrimRight(r.Header.Get("Origin"), "/")
			if origin != "" && allowed[origin] {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Access-Control-Allow-Credentials", "true")
				h.Set("Vary", "Origin")
				h.Set("Access-Control-Expose-Headers", expose)

				if r.Method == http.MethodOptions {
					h.Set("Access-Control-Allow-Methods", methods)
					h.Set("Access-Control-Allow-Headers", headers)
					h.Set("Access-Control-Max-Age", strconv.Itoa(int(maxAge.Seconds())))
					w.WriteHeader(http.StatusNoContent)
					return
				}
			} else if r.Method == http.MethodOptions && origin != "" {
				// An unlisted origin gets a plain rejection rather than a
				// permissive default.
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Timeout bounds handler execution.
func Timeout(d time.Duration) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isStreaming(r) {
				// Streaming routes manage their own lifetime; a fixed deadline
				// would cut SSE connections mid-flight.
				next.ServeHTTP(w, r)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// BodyLimit caps the request body size.
func BodyLimit(max int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, max)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// NoStore prevents caching of authenticated responses.
func NoStore() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store, private")
			next.ServeHTTP(w, r)
		})
	}
}

func isStreaming(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/event-stream") ||
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func defaultIfEmpty(v, def []string) []string {
	if len(v) == 0 {
		return def
	}
	return v
}

func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// clientIP resolves the caller's address.
//
// X-Forwarded-For is only consulted when the immediate peer is a trusted proxy,
// because a client can set that header to anything it likes.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return host
}

// TrustedProxyIP returns the effective client IP, honouring X-Forwarded-For only
// when the direct peer is in the trusted set.
func TrustedProxyIP(r *http.Request, trusted []*net.IPNet) string {
	peer := clientIP(r)
	ip := net.ParseIP(peer)
	if ip == nil {
		return peer
	}
	for _, n := range trusted {
		if n.Contains(ip) {
			xff := r.Header.Get("X-Forwarded-For")
			if xff == "" {
				return peer
			}
			// The left-most entry is the original client per the convention.
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if net.ParseIP(first) != nil {
				return first
			}
			return peer
		}
	}
	return peer
}
