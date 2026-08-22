package pgwire

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DriverName is the name this driver registers under.
const DriverName = "pgwire"

func init() { sql.Register(DriverName, &Driver{}) }

// Driver implements driver.Driver and driver.DriverContext.
type Driver struct{}

var (
	_ driver.Driver          = (*Driver)(nil)
	_ driver.DriverContext   = (*Driver)(nil)
	_ driver.Connector       = (*Connector)(nil)
	_ driver.Conn            = (*Conn)(nil)
	_ driver.ConnBeginTx     = (*Conn)(nil)
	_ driver.ExecerContext   = (*Conn)(nil)
	_ driver.QueryerContext  = (*Conn)(nil)
	_ driver.Pinger          = (*Conn)(nil)
	_ driver.SessionResetter = (*Conn)(nil)
	_ driver.Validator       = (*Conn)(nil)
)

func (d *Driver) Open(dsn string) (driver.Conn, error) {
	c, err := d.OpenConnector(dsn)
	if err != nil {
		return nil, err
	}
	return c.Connect(context.Background())
}

func (d *Driver) OpenConnector(dsn string) (driver.Connector, error) {
	cfg, err := ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	return &Connector{cfg: cfg, driver: d}, nil
}

// Connector produces connections from a parsed config.
type Connector struct {
	cfg    *Config
	driver *Driver
}

func (c *Connector) Driver() driver.Driver { return c.driver }

func (c *Connector) Connect(ctx context.Context) (driver.Conn, error) {
	return connect(ctx, c.cfg)
}

// NewConnector builds a database/sql connector from a DSN, for callers that
// want to avoid the global driver registry.
func NewConnector(dsn string) (driver.Connector, error) {
	cfg, err := ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	return &Connector{cfg: cfg, driver: &Driver{}}, nil
}

// Conn is a single PostgreSQL session.
type Conn struct {
	cfg    *Config
	conn   net.Conn
	r      *readBuf
	w      *writeBuf
	bw     *bufio.Writer
	params map[string]string

	pid       int32
	secretKey int32

	txStatus byte // 'I' idle, 'T' in transaction, 'E' failed transaction
	bad      bool
	closed   bool

	mu sync.Mutex
}

func connect(ctx context.Context, cfg *Config) (*Conn, error) {
	d := net.Dialer{Timeout: cfg.ConnectTimeout}
	nc, err := d.DialContext(ctx, "tcp", cfg.address())
	if err != nil {
		return nil, fmt.Errorf("pgwire: dialing %s: %w", cfg.address(), err)
	}
	if tc, ok := nc.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}

	if cfg.SSLMode != SSLDisable {
		nc, err = startTLS(nc, cfg)
		if err != nil {
			return nil, err
		}
	}

	c := &Conn{
		cfg:    cfg,
		conn:   nc,
		bw:     bufio.NewWriterSize(nc, 32*1024),
		r:      newReadBuf(bufio.NewReaderSize(nc, 32*1024)),
		w:      newWriteBuf(),
		params: map[string]string{},
	}

	if dl, ok := ctx.Deadline(); ok {
		_ = nc.SetDeadline(dl)
		defer func() { _ = nc.SetDeadline(time.Time{}) }()
	}

	if err := c.startup(); err != nil {
		_ = nc.Close()
		return nil, err
	}
	return c, nil
}

func startTLS(nc net.Conn, cfg *Config) (net.Conn, error) {
	// SSLRequest is an untyped 8-byte message.
	var req [8]byte
	binary.BigEndian.PutUint32(req[0:], 8)
	binary.BigEndian.PutUint32(req[4:], sslRequestCode)
	if _, err := nc.Write(req[:]); err != nil {
		_ = nc.Close()
		return nil, fmt.Errorf("pgwire: sending SSLRequest: %w", err)
	}
	var resp [1]byte
	if _, err := io.ReadFull(nc, resp[:]); err != nil {
		_ = nc.Close()
		return nil, fmt.Errorf("pgwire: reading SSLRequest response: %w", err)
	}
	if resp[0] != 'S' {
		_ = nc.Close()
		return nil, fmt.Errorf("pgwire: server refused TLS but sslmode=%s requires it", cfg.SSLMode)
	}

	tlsCfg := &tls.Config{
		ServerName: cfg.Host,
		MinVersion: tls.VersionTLS12,
	}
	switch cfg.SSLMode {
	case SSLRequire:
		// Encrypted but unauthenticated. Acceptable only inside a trusted network
		// segment; verify-full is the production setting.
		tlsCfg.InsecureSkipVerify = true
	case SSLVerifyCA:
		tlsCfg.InsecureSkipVerify = true
		pool, err := rootPool(cfg.SSLRootCert)
		if err != nil {
			_ = nc.Close()
			return nil, err
		}
		tlsCfg.RootCAs = pool
		tlsCfg.VerifyPeerCertificate = verifyChainOnly(pool)
	case SSLVerifyFull:
		if cfg.SSLRootCert != "" {
			pool, err := rootPool(cfg.SSLRootCert)
			if err != nil {
				_ = nc.Close()
				return nil, err
			}
			tlsCfg.RootCAs = pool
		}
	}

	tc := tls.Client(nc, tlsCfg)
	if err := tc.Handshake(); err != nil {
		_ = nc.Close()
		return nil, fmt.Errorf("pgwire: TLS handshake: %w", err)
	}
	return tc, nil
}

func rootPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return x509.SystemCertPool()
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("pgwire: reading sslrootcert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("pgwire: sslrootcert %q contains no usable certificates", path)
	}
	return pool, nil
}

func verifyChainOnly(pool *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("pgwire: server presented no certificate")
		}
		certs := make([]*x509.Certificate, 0, len(rawCerts))
		for _, raw := range rawCerts {
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return fmt.Errorf("pgwire: parsing server certificate: %w", err)
			}
			certs = append(certs, cert)
		}
		inter := x509.NewCertPool()
		for _, c := range certs[1:] {
			inter.AddCert(c)
		}
		_, err := certs[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter})
		return err
	}
}

// ---------------------------------------------------------------------------
// Startup and authentication
// ---------------------------------------------------------------------------

func (c *Conn) startup() error {
	c.w.startMsg(0)
	c.w.int32(protocolVersionNumber)
	c.w.string("user")
	c.w.string(c.cfg.User)
	c.w.string("database")
	c.w.string(c.cfg.Database)
	c.w.string("application_name")
	c.w.string(c.cfg.ApplicationName)
	// Predictable server behaviour regardless of the server's locale settings.
	c.w.string("client_encoding")
	c.w.string("UTF8")
	c.w.string("DateStyle")
	c.w.string("ISO, MDY")
	for k, v := range c.cfg.StatementParams {
		c.w.string(k)
		c.w.string(v)
	}
	c.w.byte(0)
	if err := c.flush(c.w.finish()); err != nil {
		return err
	}

	for {
		if err := c.r.next(); err != nil {
			return fmt.Errorf("pgwire: reading startup response: %w", err)
		}
		switch c.r.typ {
		case msgAuthentication:
			if done, err := c.handleAuth(); err != nil {
				return err
			} else if done {
				continue
			}
		case msgParameterStatus:
			k := c.r.string()
			v := c.r.string()
			c.params[k] = v
		case msgBackendKeyData:
			c.pid = c.r.int32()
			c.secretKey = c.r.int32()
		case msgReadyForQuery:
			c.txStatus = c.r.byteVal()
			return nil
		case msgErrorResponse:
			return parseError(c.r)
		case msgNoticeResponse:
			_ = parseError(c.r)
		case msgNegotiateProtocol:
			return errors.New("pgwire: server requested an unsupported protocol version")
		default:
			return fmt.Errorf("pgwire: unexpected message %q during startup", c.r.typ)
		}
	}
}

func (c *Conn) handleAuth() (bool, error) {
	switch code := c.r.int32(); code {
	case msgAuthenticationOK:
		return true, nil
	case msgAuthCleartext:
		c.w.startMsg('p')
		c.w.string(c.cfg.Password)
		return true, c.flush(c.w.finish())
	case msgAuthMD5:
		salt := c.r.rest()
		c.w.startMsg('p')
		c.w.string(md5Auth(c.cfg.User, c.cfg.Password, salt))
		return true, c.flush(c.w.finish())
	case msgAuthSASL:
		return true, c.authSCRAM()
	case msgAuthSASLContinue, msgAuthSASLFinal:
		return false, errors.New("pgwire: unexpected SASL continuation outside the SASL exchange")
	default:
		return false, fmt.Errorf("pgwire: unsupported authentication method %d", code)
	}
}

func (c *Conn) authSCRAM() error {
	var supported bool
	for c.r.remaining() > 0 {
		m := c.r.string()
		if m == "" {
			break
		}
		if m == "SCRAM-SHA-256" {
			supported = true
		}
	}
	if !supported {
		return errors.New("pgwire: server offered no supported SASL mechanism (need SCRAM-SHA-256)")
	}

	sc, err := newSCRAMClient(c.cfg.User, c.cfg.Password)
	if err != nil {
		return err
	}
	first := sc.firstMessage()

	c.w.startMsg('p')
	c.w.string("SCRAM-SHA-256")
	c.w.int32(int32(len(first)))
	c.w.bytes([]byte(first))
	if err := c.flush(c.w.finish()); err != nil {
		return err
	}

	// AuthenticationSASLContinue
	if err := c.r.next(); err != nil {
		return err
	}
	if c.r.typ == msgErrorResponse {
		return parseError(c.r)
	}
	if c.r.typ != msgAuthentication || c.r.int32() != msgAuthSASLContinue {
		return errors.New("pgwire: expected AuthenticationSASLContinue")
	}
	final, err := sc.finalMessage(string(c.r.rest()))
	if err != nil {
		return err
	}

	c.w.startMsg('p')
	c.w.bytes([]byte(final))
	if err := c.flush(c.w.finish()); err != nil {
		return err
	}

	// AuthenticationSASLFinal
	if err := c.r.next(); err != nil {
		return err
	}
	if c.r.typ == msgErrorResponse {
		return parseError(c.r)
	}
	if c.r.typ != msgAuthentication || c.r.int32() != msgAuthSASLFinal {
		return errors.New("pgwire: expected AuthenticationSASLFinal")
	}
	if err := sc.verifyServer(string(c.r.rest())); err != nil {
		return err
	}

	// AuthenticationOk
	if err := c.r.next(); err != nil {
		return err
	}
	if c.r.typ == msgErrorResponse {
		return parseError(c.r)
	}
	if c.r.typ != msgAuthentication || c.r.int32() != msgAuthenticationOK {
		return errors.New("pgwire: expected AuthenticationOk after SASL")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

func (c *Conn) flush(b []byte) error {
	if _, err := c.bw.Write(b); err != nil {
		c.bad = true
		return err
	}
	if err := c.bw.Flush(); err != nil {
		c.bad = true
		return err
	}
	return nil
}

func (c *Conn) markBad(err error) error {
	if err == nil {
		return nil
	}
	// Protocol-level errors reported by the server leave the connection usable;
	// transport errors do not.
	var pe *Error
	if errors.As(err, &pe) {
		return err
	}
	c.bad = true
	return err
}

// IsValid reports whether database/sql may reuse this connection.
func (c *Conn) IsValid() bool { return !c.bad && !c.closed }

func (c *Conn) ResetSession(ctx context.Context) error {
	if c.bad || c.closed {
		return driver.ErrBadConn
	}
	// Transaction-scoped settings (SET LOCAL) cannot leak, and the pool never
	// hands out a connection mid-transaction. A connection left in a transaction
	// means a bug upstream, so discard it rather than paper over it.
	if c.txStatus != 'I' {
		c.bad = true
		return driver.ErrBadConn
	}
	return nil
}

func (c *Conn) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	c.w.startMsg('X')
	_ = c.flush(c.w.finish())
	return c.conn.Close()
}

func (c *Conn) Prepare(query string) (driver.Stmt, error) {
	return nil, errors.New("pgwire: use PrepareContext / QueryContext")
}

func (c *Conn) Ping(ctx context.Context) error {
	_, err := c.ExecContext(ctx, ";", nil)
	if err != nil && errors.Is(err, driver.ErrSkip) {
		return nil
	}
	return err
}

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

// watchCancel arranges for an in-flight query to be cancelled when ctx is done.
// PostgreSQL requires the cancel request to arrive on a separate connection.
func (c *Conn) watchCancel(ctx context.Context) func() {
	if ctx.Done() == nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			c.sendCancelRequest()
			// Give the server a moment to act; then unblock the reader so the
			// caller sees the context error rather than hanging.
			_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		case <-done:
		}
	}()
	return func() {
		close(done)
		_ = c.conn.SetReadDeadline(time.Time{})
	}
}

func (c *Conn) sendCancelRequest() {
	if c.pid == 0 {
		return
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	nc, err := d.Dial("tcp", c.cfg.address())
	if err != nil {
		return
	}
	defer func() { _ = nc.Close() }()

	if c.cfg.SSLMode != SSLDisable {
		nc, err = startTLS(nc, c.cfg)
		if err != nil {
			return
		}
	}
	var buf [16]byte
	binary.BigEndian.PutUint32(buf[0:], 16)
	binary.BigEndian.PutUint32(buf[4:], cancelRequestCode)
	binary.BigEndian.PutUint32(buf[8:], uint32(c.pid))
	binary.BigEndian.PutUint32(buf[12:], uint32(c.secretKey))
	_ = nc.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, _ = nc.Write(buf[:])
}

// ---------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------

func (c *Conn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *Conn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if c.bad {
		return nil, driver.ErrBadConn
	}
	stmt := "BEGIN"
	switch sql.IsolationLevel(opts.Isolation) {
	case sql.LevelDefault:
	case sql.LevelReadCommitted:
		stmt += " ISOLATION LEVEL READ COMMITTED"
	case sql.LevelRepeatableRead:
		stmt += " ISOLATION LEVEL REPEATABLE READ"
	case sql.LevelSerializable:
		stmt += " ISOLATION LEVEL SERIALIZABLE"
	default:
		return nil, fmt.Errorf("pgwire: unsupported isolation level %s",
			sql.IsolationLevel(opts.Isolation))
	}
	if opts.ReadOnly {
		stmt += " READ ONLY"
	}
	if _, err := c.simpleExec(ctx, stmt); err != nil {
		return nil, err
	}
	return &tx{c: c}, nil
}

type tx struct{ c *Conn }

func (t *tx) Commit() error {
	_, err := t.c.simpleExec(context.Background(), "COMMIT")
	return err
}

func (t *tx) Rollback() error {
	_, err := t.c.simpleExec(context.Background(), "ROLLBACK")
	return err
}

// ---------------------------------------------------------------------------
// Simple query protocol — used for control statements and migration scripts
// ---------------------------------------------------------------------------

func (c *Conn) simpleExec(ctx context.Context, query string) (driver.Result, error) {
	if c.bad {
		return nil, driver.ErrBadConn
	}
	unwatch := c.watchCancel(ctx)
	defer unwatch()

	c.w.startMsg('Q')
	c.w.string(query)
	if err := c.flush(c.w.finish()); err != nil {
		return nil, c.markBad(err)
	}

	var (
		affected int64
		firstErr error
	)
	for {
		if err := c.r.next(); err != nil {
			return nil, c.markBad(readErr(ctx, err))
		}
		switch c.r.typ {
		case msgCommandComplete:
			affected += parseCommandTag(c.r.string())
		case msgRowDescription, msgDataRow, msgEmptyQueryResponse, msgNoData:
			// Results of a control statement are not consumed.
			_ = c.r.rest()
		case msgErrorResponse:
			if e := parseError(c.r); firstErr == nil {
				firstErr = e
			}
		case msgNoticeResponse, msgParameterStatus, msgNotification:
			_ = c.r.rest()
		case msgReadyForQuery:
			c.txStatus = c.r.byteVal()
			if firstErr != nil {
				return nil, firstErr
			}
			return result{rows: affected}, nil
		case msgCopyInResponse, msgCopyOutResponse, msgCopyBothResponse:
			return nil, errors.New("pgwire: COPY is not supported")
		default:
			_ = c.r.rest()
		}
	}
}

// ExecScript runs a multi-statement SQL script through the simple query
// protocol. Migration files are the only intended caller; it does not accept
// parameters, so there is no injection surface beyond the file itself.
func (c *Conn) ExecScript(ctx context.Context, script string) error {
	_, err := c.simpleExec(ctx, script)
	return err
}

func readErr(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return driver.ErrBadConn
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return context.DeadlineExceeded
	}
	return err
}

func parseCommandTag(tag string) int64 {
	fields := strings.Fields(tag)
	if len(fields) == 0 {
		return 0
	}
	switch fields[0] {
	case "INSERT":
		if len(fields) == 3 {
			n, _ := strconv.ParseInt(fields[2], 10, 64)
			return n
		}
	case "UPDATE", "DELETE", "SELECT", "MOVE", "FETCH", "COPY", "MERGE":
		if len(fields) >= 2 {
			n, _ := strconv.ParseInt(fields[len(fields)-1], 10, 64)
			return n
		}
	}
	return 0
}

type result struct{ rows int64 }

func (r result) LastInsertId() (int64, error) {
	return 0, errors.New("pgwire: LastInsertId is not supported; use RETURNING")
}
func (r result) RowsAffected() (int64, error) { return r.rows, nil }
