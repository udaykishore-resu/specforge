package cache

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/specforge/specforge/internal/platform/obs"
)

// Redis is a minimal RESP client covering the commands the platform uses:
// GET, SET with expiry, DEL, SCAN, INCR, EXPIRE and PING.
//
// It exists so the platform runs against a real Redis without a third-party
// dependency. The protocol surface is deliberately small and the connection
// pool is simple; swapping in a full-featured client means replacing this file
// only, because everything above depends on the Cache interface.
type Redis struct {
	addr     string
	password string
	db       int
	useTLS   bool

	mu    sync.Mutex
	conns []*redisConn
	max   int
	// dialTimeout and ioTimeout bound every operation, so a wedged cache
	// degrades latency rather than hanging a request.
	dialTimeout time.Duration
	ioTimeout   time.Duration
	closed      bool
}

var _ Cache = (*Redis)(nil)

type redisConn struct {
	c  net.Conn
	br *bufio.Reader
	bw *bufio.Writer
}

// RedisOptions configures the client.
type RedisOptions struct {
	Addr        string
	Password    string
	DB          int
	TLS         bool
	MaxConns    int
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

// NewRedis creates a client and verifies connectivity.
func NewRedis(ctx context.Context, opts RedisOptions) (*Redis, error) {
	if opts.Addr == "" {
		return nil, errors.New("cache: redis address is required")
	}
	if opts.MaxConns <= 0 {
		opts.MaxConns = 10
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 5 * time.Second
	}
	if opts.IOTimeout <= 0 {
		opts.IOTimeout = 3 * time.Second
	}
	r := &Redis{
		addr: opts.Addr, password: opts.Password, db: opts.DB, useTLS: opts.TLS,
		max: opts.MaxConns, dialTimeout: opts.DialTimeout, ioTimeout: opts.IOTimeout,
	}
	if err := r.Health(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Redis) dial() (*redisConn, error) {
	var (
		c   net.Conn
		err error
	)
	d := net.Dialer{Timeout: r.dialTimeout}
	if r.useTLS {
		c, err = tls.DialWithDialer(&d, "tcp", r.addr, &tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		c, err = d.Dial("tcp", r.addr)
	}
	if err != nil {
		return nil, fmt.Errorf("cache: dialing redis: %w", err)
	}

	rc := &redisConn{c: c, br: bufio.NewReader(c), bw: bufio.NewWriter(c)}
	if r.password != "" {
		if _, err := r.do(rc, "AUTH", r.password); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("cache: redis auth: %w", err)
		}
	}
	if r.db != 0 {
		if _, err := r.do(rc, "SELECT", strconv.Itoa(r.db)); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("cache: redis select: %w", err)
		}
	}
	return rc, nil
}

func (r *Redis) get() (*redisConn, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, errors.New("cache: client is closed")
	}
	if n := len(r.conns); n > 0 {
		c := r.conns[n-1]
		r.conns = r.conns[:n-1]
		r.mu.Unlock()
		return c, nil
	}
	r.mu.Unlock()
	return r.dial()
}

func (r *Redis) put(c *redisConn, broken bool) {
	if broken {
		_ = c.c.Close()
		return
	}
	r.mu.Lock()
	if r.closed || len(r.conns) >= r.max {
		r.mu.Unlock()
		_ = c.c.Close()
		return
	}
	r.conns = append(r.conns, c)
	r.mu.Unlock()
}

// do writes a command in the RESP array form and reads one reply.
func (r *Redis) do(rc *redisConn, args ...string) (any, error) {
	_ = rc.c.SetDeadline(time.Now().Add(r.ioTimeout))

	fmt.Fprintf(rc.bw, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(rc.bw, "$%d\r\n%s\r\n", len(a), a)
	}
	if err := rc.bw.Flush(); err != nil {
		return nil, fmt.Errorf("cache: writing command: %w", err)
	}
	return readReply(rc.br)
}

func (r *Redis) command(_ context.Context, args ...string) (any, error) {
	rc, err := r.get()
	if err != nil {
		return nil, err
	}
	reply, err := r.do(rc, args...)
	// A protocol-level error reply leaves the connection usable; a transport
	// error does not.
	var re redisError
	broken := err != nil && !errors.As(err, &re)
	r.put(rc, broken)
	return reply, err
}

type redisError struct{ msg string }

func (e redisError) Error() string { return "redis: " + e.msg }

func readReply(br *bufio.Reader) (any, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("cache: reading reply: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil, errors.New("cache: empty reply")
	}

	switch line[0] {
	case '+':
		return line[1:], nil
	case '-':
		return nil, redisError{msg: line[1:]}
	case ':':
		n, err := strconv.ParseInt(line[1:], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("cache: parsing integer reply: %w", err)
		}
		return n, nil
	case '$':
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, fmt.Errorf("cache: parsing bulk length: %w", err)
		}
		if n < 0 {
			return nil, nil // nil bulk string
		}
		buf := make([]byte, n+2)
		if _, err := readFull(br, buf); err != nil {
			return nil, fmt.Errorf("cache: reading bulk string: %w", err)
		}
		return buf[:n], nil
	case '*':
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, fmt.Errorf("cache: parsing array length: %w", err)
		}
		if n < 0 {
			return nil, nil
		}
		out := make([]any, n)
		for i := 0; i < n; i++ {
			v, err := readReply(br)
			if err != nil {
				return nil, err
			}
			out[i] = v
		}
		return out, nil
	default:
		return nil, fmt.Errorf("cache: unexpected reply prefix %q", line[0])
	}
}

func readFull(br *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := br.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (r *Redis) Get(ctx context.Context, key string) ([]byte, bool, error) {
	reply, err := r.command(ctx, "GET", key)
	if err != nil {
		obs.Counter("sf_cache_operations_total", "Cache operations",
			obs.Labels{"op": "get", "result": "error"})
		return nil, false, err
	}
	if reply == nil {
		obs.Counter("sf_cache_operations_total", "Cache operations",
			obs.Labels{"op": "get", "result": "miss"})
		return nil, false, nil
	}
	b, ok := reply.([]byte)
	if !ok {
		return nil, false, fmt.Errorf("cache: unexpected GET reply type %T", reply)
	}
	obs.Counter("sf_cache_operations_total", "Cache operations",
		obs.Labels{"op": "get", "result": "hit"})
	return b, true, nil
}

func (r *Redis) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	args := []string{"SET", key, string(value)}
	if ttl > 0 {
		args = append(args, "PX", strconv.FormatInt(ttl.Milliseconds(), 10))
	}
	_, err := r.command(ctx, args...)
	return err
}

func (r *Redis) Delete(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	_, err := r.command(ctx, append([]string{"DEL"}, keys...)...)
	return err
}

// DeletePrefix scans and deletes matching keys.
//
// SCAN rather than KEYS: KEYS blocks the server for the whole keyspace, which on
// a shared cache is an outage waiting for the first large tenant.
func (r *Redis) DeletePrefix(ctx context.Context, prefix string) error {
	cursor := "0"
	for {
		reply, err := r.command(ctx, "SCAN", cursor, "MATCH", prefix+"*", "COUNT", "500")
		if err != nil {
			return err
		}
		arr, ok := reply.([]any)
		if !ok || len(arr) != 2 {
			return fmt.Errorf("cache: unexpected SCAN reply")
		}
		next, _ := arr[0].([]byte)
		keysAny, _ := arr[1].([]any)

		if len(keysAny) > 0 {
			keys := make([]string, 0, len(keysAny))
			for _, k := range keysAny {
				if b, ok := k.([]byte); ok {
					keys = append(keys, string(b))
				}
			}
			if err := r.Delete(ctx, keys...); err != nil {
				return err
			}
		}
		cursor = string(next)
		if cursor == "0" || cursor == "" {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
}

func (r *Redis) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	reply, err := r.command(ctx, "INCR", key)
	if err != nil {
		return 0, err
	}
	n, ok := reply.(int64)
	if !ok {
		return 0, fmt.Errorf("cache: unexpected INCR reply type %T", reply)
	}
	if n == 1 && ttl > 0 {
		// Only the first increment sets the window, so a burst cannot keep
		// extending the expiry and starve the reset.
		if _, err := r.command(ctx, "PEXPIRE", key, strconv.FormatInt(ttl.Milliseconds(), 10)); err != nil {
			return n, err
		}
	}
	return n, nil
}

func (r *Redis) Health(ctx context.Context) error {
	reply, err := r.command(ctx, "PING")
	if err != nil {
		return err
	}
	if s, ok := reply.(string); ok && s == "PONG" {
		return nil
	}
	return fmt.Errorf("cache: unexpected PING reply %v", reply)
}

func (r *Redis) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	for _, c := range r.conns {
		_ = c.c.Close()
	}
	r.conns = nil
	return nil
}
