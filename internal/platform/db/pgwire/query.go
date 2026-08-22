package pgwire

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
)

// ExecContext runs a parameterised statement through the extended query protocol.
func (c *Conn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if len(args) == 0 {
		return c.simpleExec(ctx, query)
	}
	rows, err := c.extendedQuery(ctx, query, args)
	if err != nil {
		return nil, err
	}
	// Drain so the connection is left at ReadyForQuery.
	if err := rows.drain(); err != nil {
		return nil, err
	}
	return result{rows: rows.affected}, nil
}

// QueryContext runs a parameterised query through the extended query protocol.
func (c *Conn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return c.extendedQuery(ctx, query, args)
}

func (c *Conn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	return &stmt{c: c, query: query, nparams: countPlaceholders(query)}, nil
}

type stmt struct {
	c       *Conn
	query   string
	nparams int
}

var (
	_ driver.Stmt             = (*stmt)(nil)
	_ driver.StmtExecContext  = (*stmt)(nil)
	_ driver.StmtQueryContext = (*stmt)(nil)
)

func (s *stmt) Close() error  { return nil }
func (s *stmt) NumInput() int { return s.nparams }

func (s *stmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.ExecContext(context.Background(), valuesToNamed(args))
}
func (s *stmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.QueryContext(context.Background(), valuesToNamed(args))
}
func (s *stmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	return s.c.ExecContext(ctx, s.query, args)
}
func (s *stmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	return s.c.QueryContext(ctx, s.query, args)
}

func valuesToNamed(args []driver.Value) []driver.NamedValue {
	out := make([]driver.NamedValue, len(args))
	for i, v := range args {
		out[i] = driver.NamedValue{Ordinal: i + 1, Value: v}
	}
	return out
}

// countPlaceholders counts distinct $N placeholders, ignoring those inside
// string literals, dollar-quoted bodies, and comments.
func countPlaceholders(q string) int {
	max := 0
	for i := 0; i < len(q); i++ {
		switch q[i] {
		case '\'':
			for i++; i < len(q); i++ {
				if q[i] == '\'' {
					if i+1 < len(q) && q[i+1] == '\'' {
						i++
						continue
					}
					break
				}
			}
		case '-':
			if i+1 < len(q) && q[i+1] == '-' {
				for i < len(q) && q[i] != '\n' {
					i++
				}
			}
		case '$':
			j := i + 1
			n := 0
			for j < len(q) && q[j] >= '0' && q[j] <= '9' {
				n = n*10 + int(q[j]-'0')
				j++
			}
			if j > i+1 {
				if n > max {
					max = n
				}
				i = j - 1
			}
		}
	}
	return max
}

// extendedQuery performs Parse/Bind/Describe/Execute/Sync on the unnamed
// statement and portal.
func (c *Conn) extendedQuery(ctx context.Context, query string, args []driver.NamedValue) (*rows, error) {
	if c.bad {
		return nil, driver.ErrBadConn
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Parse (unnamed statement, let the server infer parameter types).
	c.w.startMsg('P')
	c.w.string("")
	c.w.string(query)
	c.w.int16(0)
	pkt := append([]byte(nil), c.w.finish()...)

	// Bind (unnamed portal from unnamed statement).
	c.w.startMsg('B')
	c.w.string("")
	c.w.string("")
	c.w.int16(0) // all parameters in text format
	c.w.int16(int16(len(args)))
	for _, a := range args {
		raw, isNull, err := encodeParam(a.Value)
		if err != nil {
			return nil, fmt.Errorf("pgwire: parameter $%d: %w", a.Ordinal, err)
		}
		if isNull {
			c.w.int32(-1)
			continue
		}
		c.w.int32(int32(len(raw)))
		c.w.bytes(raw)
	}
	c.w.int16(0) // all results in text format
	pkt = append(pkt, c.w.finish()...)

	// Describe the portal to learn the result shape.
	c.w.startMsg('D')
	c.w.byte('P')
	c.w.string("")
	pkt = append(pkt, c.w.finish()...)

	// Execute with no row limit.
	c.w.startMsg('E')
	c.w.string("")
	c.w.int32(0)
	pkt = append(pkt, c.w.finish()...)

	c.w.startMsg('S')
	pkt = append(pkt, c.w.finish()...)

	unwatch := c.watchCancel(ctx)
	if err := c.flush(pkt); err != nil {
		unwatch()
		return nil, c.markBad(err)
	}

	r := &rows{c: c, ctx: ctx, unwatch: unwatch}

	// Read until we know the shape: RowDescription, NoData, or an error.
	for {
		if err := c.r.next(); err != nil {
			r.finish()
			return nil, c.markBad(readErr(ctx, err))
		}
		switch c.r.typ {
		case msgParseComplete, msgBindComplete:
			// expected
		case msgRowDescription:
			r.fields = parseRowDescription(c.r)
			return r, nil
		case msgNoData:
			return r, nil
		case msgErrorResponse:
			e := parseError(c.r)
			r.err = e
			r.drainAfterError()
			return nil, e
		case msgNoticeResponse, msgParameterStatus, msgNotification:
			_ = c.r.rest()
		case msgCommandComplete:
			r.affected += parseCommandTag(c.r.string())
			r.done = true
		case msgReadyForQuery:
			c.txStatus = c.r.byteVal()
			r.done = true
			r.finish()
			return r, nil
		default:
			_ = c.r.rest()
		}
	}
}

// rows streams DataRow messages until CommandComplete/ReadyForQuery.
type rows struct {
	c        *Conn
	ctx      context.Context
	fields   []fieldDescription
	affected int64
	done     bool
	closed   bool
	err      error
	unwatch  func()
}

var _ driver.Rows = (*rows)(nil)

func (r *rows) Columns() []string {
	out := make([]string, len(r.fields))
	for i, f := range r.fields {
		out[i] = f.name
	}
	return out
}

func (r *rows) Next(dest []driver.Value) error {
	if r.err != nil {
		return r.err
	}
	if r.done {
		return io.EOF
	}
	for {
		if err := r.c.r.next(); err != nil {
			r.err = r.c.markBad(readErr(r.ctx, err))
			r.finish()
			return r.err
		}
		switch r.c.r.typ {
		case msgDataRow:
			n := int(r.c.r.int16())
			if n > len(dest) {
				n = len(dest)
			}
			for i := 0; i < n; i++ {
				l := r.c.r.int32()
				if l < 0 {
					dest[i] = nil
					continue
				}
				raw := r.c.r.msg[r.c.r.pos : r.c.r.pos+int(l)]
				r.c.r.pos += int(l)
				v, err := decodeValue(r.fields[i].typeOID, raw)
				if err != nil {
					r.err = err
					return err
				}
				dest[i] = v
			}
			return nil
		case msgCommandComplete:
			r.affected += parseCommandTag(r.c.r.string())
		case msgEmptyQueryResponse, msgPortalSuspended:
			// no rows
		case msgErrorResponse:
			r.err = parseError(r.c.r)
			r.drainAfterError()
			return r.err
		case msgReadyForQuery:
			r.c.txStatus = r.c.r.byteVal()
			r.done = true
			r.finish()
			return io.EOF
		case msgNoticeResponse, msgParameterStatus, msgNotification:
			_ = r.c.r.rest()
		default:
			_ = r.c.r.rest()
		}
	}
}

func (r *rows) Close() error {
	if r.closed {
		return nil
	}
	if !r.done && r.err == nil {
		// Consume the remainder so the connection is reusable.
		_ = r.drain()
	}
	r.finish()
	return nil
}

func (r *rows) finish() {
	if r.closed {
		return
	}
	r.closed = true
	if r.unwatch != nil {
		r.unwatch()
	}
}

func (r *rows) drain() error {
	buf := make([]driver.Value, len(r.fields))
	for {
		err := r.Next(buf)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// drainAfterError consumes messages up to and including ReadyForQuery so the
// connection can be returned to the pool after a server-side error.
func (r *rows) drainAfterError() {
	for {
		if err := r.c.r.next(); err != nil {
			r.c.bad = true
			r.finish()
			return
		}
		if r.c.r.typ == msgReadyForQuery {
			r.c.txStatus = r.c.r.byteVal()
			r.done = true
			r.finish()
			return
		}
		_ = r.c.r.rest()
	}
}
