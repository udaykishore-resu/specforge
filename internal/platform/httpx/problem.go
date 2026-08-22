// Package httpx holds the HTTP transport plumbing: RFC 9457 problem responses,
// the middleware chain, and helpers for decoding and rendering.
//
// Two invariants the package exists to guarantee:
//
//   - Every error response is a problem+json document with a stable machine
//     code and a trace id, so a client can branch on the code and an operator
//     can find the request.
//   - No handler can be registered without declaring the permission it requires
//     (see Route). The route lint reads these declarations, which is why an
//     unprotected endpoint cannot ship by omission.
package httpx

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/obs"
)

// ProblemBaseURL prefixes the `type` URI of problem documents.
const ProblemBaseURL = "https://specforge.io/problems/"

// Problem is an RFC 9457 problem detail document.
type Problem struct {
	Type     string         `json:"type"`
	Title    string         `json:"title"`
	Status   int            `json:"status"`
	Detail   string         `json:"detail,omitempty"`
	Instance string         `json:"instance,omitempty"`
	Code     string         `json:"code"`
	TraceID  string         `json:"trace_id,omitempty"`
	Errors   []FieldError   `json:"errors,omitempty"`
	Extra    map[string]any `json:"-"`
}

// FieldError describes a validation failure on a specific field.
type FieldError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

// MarshalJSON flattens Extra into the document, as RFC 9457 permits.
func (p Problem) MarshalJSON() ([]byte, error) {
	type alias Problem
	base, err := json.Marshal(alias(p))
	if err != nil {
		return nil, err
	}
	if len(p.Extra) == 0 {
		return base, nil
	}
	var merged map[string]any
	if err := json.Unmarshal(base, &merged); err != nil {
		return nil, err
	}
	for k, v := range p.Extra {
		if _, taken := merged[k]; !taken {
			merged[k] = v
		}
	}
	return json.Marshal(merged)
}

// WriteProblem renders an error as problem+json.
//
// The message written to the client comes from the platform error's Message
// field, which is defined to be free of tenant data. Errors that are not
// platform errors are reduced to a generic message so an unexpected failure
// cannot leak an internal detail through the response body.
func WriteProblem(w http.ResponseWriter, r *http.Request, err error, logger *slog.Logger) {
	status := errors.HTTPStatus(err)
	code := errors.CodeOf(err)
	traceID := obs.TraceIDFrom(r.Context())

	p := Problem{
		Type:     ProblemBaseURL + strings.ReplaceAll(strings.ReplaceAll(code, ".", "-"), "_", "-"),
		Title:    http.StatusText(status),
		Status:   status,
		Detail:   errors.MessageOf(err),
		Instance: r.URL.Path,
		Code:     code,
		TraceID:  traceID,
		Extra:    errors.DetailsOf(err),
	}

	if status == http.StatusUnauthorized {
		if code == "auth.step_up_required" {
			w.Header().Set("WWW-Authenticate",
				`Bearer error="insufficient_user_authentication", acr_values="mfa"`)
		} else {
			w.Header().Set("WWW-Authenticate", `Bearer realm="specforge"`)
		}
	}

	if logger != nil {
		level := slog.LevelWarn
		if status >= 500 {
			level = slog.LevelError
		}
		logger.Log(r.Context(), level, "request failed",
			"code", code, "status", status, "method", r.Method,
			"path", r.URL.Path, "error", err.Error())
	}

	obs.Counter("sf_http_errors_total", "HTTP error responses",
		obs.Labels{"code": code, "status": fmt.Sprint(status)})

	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if encErr := json.NewEncoder(w).Encode(p); encErr != nil && logger != nil {
		logger.ErrorContext(r.Context(), "writing problem response failed", "error", encErr)
	}
}

// WriteJSON renders a successful JSON response.
func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v == nil {
		return nil
	}
	return json.NewEncoder(w).Encode(v)
}

// WriteNoContent renders a 204.
func WriteNoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// DecodeJSON reads and validates a JSON request body.
//
// Unknown fields are rejected rather than ignored: a client sending
// "aproval_comment" should be told, not silently have their comment dropped.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	const op = "httpx.DecodeJSON"

	ct := r.Header.Get("Content-Type")
	if ct != "" {
		media := strings.TrimSpace(strings.Split(ct, ";")[0])
		if media != "application/json" {
			return errors.Invalid(op, "request.unsupported_media_type",
				"The request body must be application/json.")
		}
	}
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		var syntaxErr *json.SyntaxError
		var typeErr *json.UnmarshalTypeError
		var maxErr *http.MaxBytesError

		switch {
		case errors.As(err, &syntaxErr):
			return errors.Invalid(op, "request.malformed_json",
				"The request body contains malformed JSON at byte %d.", syntaxErr.Offset)
		case errors.As(err, &typeErr):
			return errors.Invalid(op, "request.invalid_field_type",
				"Field %q has the wrong type.", typeErr.Field)
		case errors.As(err, &maxErr):
			return errors.Invalid(op, "request.body_too_large",
				"The request body exceeds %d bytes.", maxBytes)
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			field := strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`)
			return errors.Invalid(op, "request.unknown_field",
				"Field %q is not recognised.", field)
		case err.Error() == "EOF":
			return errors.Invalid(op, "request.empty_body", "A request body is required.")
		default:
			return errors.Invalid(op, "request.malformed_json", "The request body could not be parsed.")
		}
	}

	// Reject a second JSON document in the same body.
	if err := dec.Decode(&struct{}{}); err == nil {
		return errors.Invalid(op, "request.multiple_documents",
			"The request body must contain a single JSON document.")
	}
	return nil
}

// Validator is implemented by request DTOs that validate themselves.
type Validator interface {
	Validate() error
}

// DecodeAndValidate decodes a body and runs its validation.
func DecodeAndValidate(w http.ResponseWriter, r *http.Request, dst Validator, maxBytes int64) error {
	if err := DecodeJSON(w, r, dst, maxBytes); err != nil {
		return err
	}
	return dst.Validate()
}
