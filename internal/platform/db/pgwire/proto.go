package pgwire

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Backend message type bytes.
const (
	msgAuthentication      = 'R'
	msgBackendKeyData      = 'K'
	msgBindComplete        = '2'
	msgCloseComplete       = '3'
	msgCommandComplete     = 'C'
	msgDataRow             = 'D'
	msgEmptyQueryResponse  = 'I'
	msgErrorResponse       = 'E'
	msgNoData              = 'n'
	msgNoticeResponse      = 'N'
	msgNotification        = 'A'
	msgParameterDescr      = 't'
	msgParameterStatus     = 'S'
	msgParseComplete       = '1'
	msgPortalSuspended     = 's'
	msgReadyForQuery       = 'Z'
	msgRowDescription      = 'T'
	msgCopyInResponse      = 'G'
	msgCopyOutResponse     = 'H'
	msgCopyBothResponse    = 'W'
	msgNegotiateProtocol   = 'v'
	msgFunctionCallResp    = 'V'
	msgAuthenticationOK    = 0
	msgAuthCleartext       = 3
	msgAuthMD5             = 5
	msgAuthSASL            = 10
	msgAuthSASLContinue    = 11
	msgAuthSASLFinal       = 12
	protocolVersionNumber  = 196608 // 3.0
	cancelRequestCode      = 80877102
	sslRequestCode         = 80877103
	maxIncomingMessageSize = 64 << 20 // 64 MiB guard against a hostile/desynced peer
)

// writeBuf builds frontend messages.
type writeBuf struct {
	buf []byte
	// index of the length placeholder for the message currently being built
	lenPos int
}

func newWriteBuf() *writeBuf { return &writeBuf{buf: make([]byte, 0, 256)} }

// startMsg begins a message with the given type byte. Pass 0 for the untyped
// startup/cancel/SSL messages.
func (w *writeBuf) startMsg(typ byte) {
	w.buf = w.buf[:0]
	if typ != 0 {
		w.buf = append(w.buf, typ)
	}
	w.lenPos = len(w.buf)
	w.buf = append(w.buf, 0, 0, 0, 0)
}

func (w *writeBuf) finish() []byte {
	binary.BigEndian.PutUint32(w.buf[w.lenPos:], uint32(len(w.buf)-w.lenPos))
	return w.buf
}

func (w *writeBuf) int32(v int32)   { w.buf = binary.BigEndian.AppendUint32(w.buf, uint32(v)) }
func (w *writeBuf) int16(v int16)   { w.buf = binary.BigEndian.AppendUint16(w.buf, uint16(v)) }
func (w *writeBuf) byte(b byte)     { w.buf = append(w.buf, b) }
func (w *writeBuf) bytes(b []byte)  { w.buf = append(w.buf, b...) }
func (w *writeBuf) string(s string) { w.buf = append(w.buf, s...); w.buf = append(w.buf, 0) }

// readBuf reads backend messages.
type readBuf struct {
	r   *bufio.Reader
	typ byte
	msg []byte
	pos int
}

func newReadBuf(r *bufio.Reader) *readBuf { return &readBuf{r: r} }

// next reads one backend message into the buffer.
func (b *readBuf) next() error {
	var hdr [5]byte
	if _, err := io.ReadFull(b.r, hdr[:]); err != nil {
		return err
	}
	b.typ = hdr[0]
	n := int(binary.BigEndian.Uint32(hdr[1:])) - 4
	if n < 0 || n > maxIncomingMessageSize {
		return fmt.Errorf("pgwire: invalid message length %d for type %q", n, b.typ)
	}
	if cap(b.msg) < n {
		b.msg = make([]byte, n)
	}
	b.msg = b.msg[:n]
	if n > 0 {
		if _, err := io.ReadFull(b.r, b.msg); err != nil {
			return err
		}
	}
	b.pos = 0
	return nil
}

func (b *readBuf) remaining() int { return len(b.msg) - b.pos }

func (b *readBuf) int32() int32 {
	v := int32(binary.BigEndian.Uint32(b.msg[b.pos:]))
	b.pos += 4
	return v
}

func (b *readBuf) int16() int16 {
	v := int16(binary.BigEndian.Uint16(b.msg[b.pos:]))
	b.pos += 2
	return v
}

func (b *readBuf) byteVal() byte {
	v := b.msg[b.pos]
	b.pos++
	return v
}

func (b *readBuf) string() string {
	i := b.pos
	for i < len(b.msg) && b.msg[i] != 0 {
		i++
	}
	s := string(b.msg[b.pos:i])
	b.pos = i + 1
	return s
}

func (b *readBuf) rest() []byte {
	v := b.msg[b.pos:]
	b.pos = len(b.msg)
	return v
}

// Error is a PostgreSQL ErrorResponse rendered as a Go error. Callers can use
// SQLState to branch on constraint violations without string matching.
type Error struct {
	Severity   string
	Code       string
	Message    string
	Detail     string
	Hint       string
	Position   string
	Where      string
	Schema     string
	Table      string
	Column     string
	Constraint string
	File       string
	Line       string
	Routine    string
}

func (e *Error) Error() string {
	var sb strings.Builder
	sb.WriteString("pg: ")
	if e.Severity != "" {
		sb.WriteString(e.Severity)
		sb.WriteString(": ")
	}
	sb.WriteString(e.Message)
	if e.Code != "" {
		sb.WriteString(" (SQLSTATE ")
		sb.WriteString(e.Code)
		sb.WriteString(")")
	}
	if e.Constraint != "" {
		sb.WriteString(" [constraint ")
		sb.WriteString(e.Constraint)
		sb.WriteString("]")
	}
	if e.Detail != "" {
		sb.WriteString(": ")
		sb.WriteString(e.Detail)
	}
	return sb.String()
}

// SQLState returns the five-character SQLSTATE code, or "" if unknown.
func (e *Error) SQLState() string { return e.Code }

// AsError extracts a *Error from an error chain.
func AsError(err error) (*Error, bool) {
	var pe *Error
	if errors.As(err, &pe) {
		return pe, true
	}
	return nil, false
}

func parseError(b *readBuf) *Error {
	e := &Error{}
	for {
		f := b.byteVal()
		if f == 0 {
			break
		}
		v := b.string()
		switch f {
		case 'S':
			e.Severity = v
		case 'C':
			e.Code = v
		case 'M':
			e.Message = v
		case 'D':
			e.Detail = v
		case 'H':
			e.Hint = v
		case 'P':
			e.Position = v
		case 'W':
			e.Where = v
		case 's':
			e.Schema = v
		case 't':
			e.Table = v
		case 'c':
			e.Column = v
		case 'n':
			e.Constraint = v
		case 'F':
			e.File = v
		case 'L':
			e.Line = v
		case 'R':
			e.Routine = v
		}
	}
	return e
}

// fieldDescription describes one result column.
type fieldDescription struct {
	name     string
	tableOID int32
	colAttr  int16
	typeOID  int32
	typeLen  int16
	typeMod  int32
	format   int16
}

func parseRowDescription(b *readBuf) []fieldDescription {
	n := int(b.int16())
	fields := make([]fieldDescription, n)
	for i := 0; i < n; i++ {
		fields[i] = fieldDescription{
			name:     b.string(),
			tableOID: b.int32(),
			colAttr:  b.int16(),
			typeOID:  b.int32(),
			typeLen:  b.int16(),
			typeMod:  b.int32(),
			format:   b.int16(),
		}
	}
	return fields
}
