// Package errors defines SpecForge's structured error model.
//
// Three rules hold everywhere in the codebase:
//
//  1. Wrap with %w at every boundary; never log-and-return.
//  2. Never put tenant data, secrets or internal details in Message — it is
//     returned to clients verbatim.
//  3. Map to HTTP in exactly one place (HTTPStatus), so status codes cannot
//     drift between handlers.
package errors

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Kind classifies an error for transport mapping and for deciding whether a
// caller may retry.
type Kind string

const (
	KindInvalid       Kind = "INVALID_ARGUMENT"
	KindUnauthorized  Kind = "UNAUTHENTICATED"
	KindForbidden     Kind = "PERMISSION_DENIED"
	KindNotFound      Kind = "NOT_FOUND"
	KindConflict      Kind = "CONFLICT"
	KindPrecondition  Kind = "FAILED_PRECONDITION"
	KindExhausted     Kind = "RESOURCE_EXHAUSTED"
	KindInternal      Kind = "INTERNAL"
	KindUnavailable   Kind = "UNAVAILABLE"
	KindTimeout       Kind = "DEADLINE_EXCEEDED"
	KindTampered      Kind = "INTEGRITY_VIOLATION"
	KindUnprocessable Kind = "UNPROCESSABLE"
)

// Error is a structured platform error.
type Error struct {
	Kind    Kind
	Code    string         // stable machine code, e.g. "artifact.sealed_immutable"
	Message string         // client-safe, free of tenant data
	Details map[string]any // structured, already redacted
	Op      string         // operation, for the call chain
	Err     error          // wrapped cause
}

func (e *Error) Error() string {
	var sb strings.Builder
	if e.Op != "" {
		sb.WriteString(e.Op)
		sb.WriteString(": ")
	}
	if e.Code != "" {
		sb.WriteString("[")
		sb.WriteString(e.Code)
		sb.WriteString("] ")
	}
	sb.WriteString(e.Message)
	if e.Err != nil {
		sb.WriteString(": ")
		sb.WriteString(e.Err.Error())
	}
	return sb.String()
}

func (e *Error) Unwrap() error { return e.Err }

// WithDetail attaches a structured detail and returns the error for chaining.
// Callers must not pass secrets or unredacted tenant content.
func (e *Error) WithDetail(k string, v any) *Error {
	if e.Details == nil {
		e.Details = map[string]any{}
	}
	e.Details[k] = v
	return e
}

// E constructs an Error. args, if present, are treated as fmt arguments for msg.
func E(op string, kind Kind, code, msg string, args ...any) *Error {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	return &Error{Kind: kind, Code: code, Message: msg, Op: op}
}

// Wrap wraps a cause with an Error.
func Wrap(err error, op string, kind Kind, code, msg string, args ...any) *Error {
	e := E(op, kind, code, msg, args...)
	e.Err = err
	return e
}

// KindOf reports the Kind of an error, defaulting to KindInternal.
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	if err == nil {
		return ""
	}
	return KindInternal
}

// CodeOf reports the stable machine code of an error, or "internal.error".
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) && e.Code != "" {
		return e.Code
	}
	return "internal.error"
}

// MessageOf returns a client-safe message. Errors that are not platform errors
// are deliberately reduced to a generic string so internal detail never leaks.
func MessageOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Message
	}
	return "An internal error occurred."
}

// DetailsOf returns the structured details of a platform error, if any.
func DetailsOf(err error) map[string]any {
	var e *Error
	if errors.As(err, &e) {
		return e.Details
	}
	return nil
}

// HTTPStatus maps an error to an HTTP status code. This is the only place in
// the codebase that performs this mapping.
func HTTPStatus(err error) int {
	switch KindOf(err) {
	case KindInvalid:
		return http.StatusBadRequest
	case KindUnauthorized:
		return http.StatusUnauthorized
	case KindForbidden:
		return http.StatusForbidden
	case KindNotFound:
		return http.StatusNotFound
	case KindConflict:
		return http.StatusConflict
	case KindPrecondition:
		return http.StatusPreconditionFailed
	case KindUnprocessable:
		return http.StatusUnprocessableEntity
	case KindExhausted:
		return http.StatusTooManyRequests
	case KindUnavailable:
		return http.StatusServiceUnavailable
	case KindTimeout:
		return http.StatusGatewayTimeout
	case KindTampered:
		// An integrity violation is a server-side failure of a security control,
		// not a client mistake, and it must never look like a routine 4xx.
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

// Retryable reports whether a caller may safely retry the same request.
func Retryable(err error) bool {
	switch KindOf(err) {
	case KindUnavailable, KindTimeout, KindExhausted:
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Constructors for the errors used across modules
// ---------------------------------------------------------------------------

func Invalid(op, code, msg string, args ...any) *Error {
	return E(op, KindInvalid, code, msg, args...)
}
func NotFound(op, code, msg string, args ...any) *Error {
	return E(op, KindNotFound, code, msg, args...)
}
func Forbidden(op, code, msg string, args ...any) *Error {
	return E(op, KindForbidden, code, msg, args...)
}
func Unauthorized(op, code, msg string, args ...any) *Error {
	return E(op, KindUnauthorized, code, msg, args...)
}
func Conflict(op, code, msg string, args ...any) *Error {
	return E(op, KindConflict, code, msg, args...)
}
func Precondition(op, code, msg string, args ...any) *Error {
	return E(op, KindPrecondition, code, msg, args...)
}
func Unprocessable(op, code, msg string, args ...any) *Error {
	return E(op, KindUnprocessable, code, msg, args...)
}
func Exhausted(op, code, msg string, args ...any) *Error {
	return E(op, KindExhausted, code, msg, args...)
}
func Internal(op, code, msg string, args ...any) *Error {
	return E(op, KindInternal, code, msg, args...)
}
func Unavailable(op, code, msg string, args ...any) *Error {
	return E(op, KindUnavailable, code, msg, args...)
}

// Tampered reports a detected integrity violation. Raising this must always be
// accompanied by an audit record and an incident; it is never a routine failure.
func Tampered(op, code, msg string, args ...any) *Error {
	return E(op, KindTampered, code, msg, args...)
}

// Re-exported standard helpers so callers need only this package.
var (
	Is     = errors.Is
	As     = errors.As
	Unwrap = errors.Unwrap
	Join   = errors.Join
	New    = errors.New
)
