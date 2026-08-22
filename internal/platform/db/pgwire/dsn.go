package pgwire

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SSLMode mirrors libpq's sslmode parameter. "prefer" is deliberately not
// supported: silently downgrading to plaintext is the kind of default that
// turns into a finding.
type SSLMode string

const (
	SSLDisable    SSLMode = "disable"
	SSLRequire    SSLMode = "require"     // encrypt, do not verify (dev only)
	SSLVerifyCA   SSLMode = "verify-ca"   // encrypt + verify chain
	SSLVerifyFull SSLMode = "verify-full" // encrypt + verify chain + hostname
)

// Config is a parsed connection string.
type Config struct {
	Host            string
	Port            int
	User            string
	Password        string
	Database        string
	SSLMode         SSLMode
	SSLRootCert     string
	ApplicationName string
	ConnectTimeout  time.Duration
	StatementParams map[string]string // extra startup parameters, e.g. search_path
}

// ParseDSN accepts either a URL form
//
//	postgres://user:pass@host:5432/db?sslmode=verify-full&application_name=specforge
//
// or a keyword/value form
//
//	host=localhost port=5432 user=sf password=... dbname=sf sslmode=require
func ParseDSN(dsn string) (*Config, error) {
	cfg := &Config{
		Host:            "localhost",
		Port:            5432,
		SSLMode:         SSLVerifyFull,
		ApplicationName: "specforge",
		ConnectTimeout:  10 * time.Second,
		StatementParams: map[string]string{},
	}

	kv := map[string]string{}
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return nil, fmt.Errorf("pgwire: parsing DSN: %w", err)
		}
		if u.User != nil {
			kv["user"] = u.User.Username()
			if p, ok := u.User.Password(); ok {
				kv["password"] = p
			}
		}
		if h := u.Hostname(); h != "" {
			kv["host"] = h
		}
		if p := u.Port(); p != "" {
			kv["port"] = p
		}
		if db := strings.TrimPrefix(u.Path, "/"); db != "" {
			kv["dbname"] = db
		}
		for k, vs := range u.Query() {
			if len(vs) > 0 {
				kv[k] = vs[0]
			}
		}
	} else {
		for _, field := range splitKeywordDSN(dsn) {
			k, v, ok := strings.Cut(field, "=")
			if !ok {
				return nil, fmt.Errorf("pgwire: malformed DSN field %q", field)
			}
			kv[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), "'")
		}
	}

	for k, v := range kv {
		switch k {
		case "host":
			cfg.Host = v
		case "port":
			p, err := strconv.Atoi(v)
			if err != nil || p <= 0 || p > 65535 {
				return nil, fmt.Errorf("pgwire: invalid port %q", v)
			}
			cfg.Port = p
		case "user":
			cfg.User = v
		case "password":
			cfg.Password = v
		case "dbname", "database":
			cfg.Database = v
		case "sslmode":
			switch SSLMode(v) {
			case SSLDisable, SSLRequire, SSLVerifyCA, SSLVerifyFull:
				cfg.SSLMode = SSLMode(v)
			case "prefer", "allow":
				return nil, fmt.Errorf("pgwire: sslmode=%q is not supported because it silently "+
					"permits plaintext; use disable, require, verify-ca or verify-full", v)
			default:
				return nil, fmt.Errorf("pgwire: unknown sslmode %q", v)
			}
		case "sslrootcert":
			cfg.SSLRootCert = v
		case "application_name":
			cfg.ApplicationName = v
		case "connect_timeout":
			secs, err := strconv.Atoi(v)
			if err != nil || secs < 0 {
				return nil, fmt.Errorf("pgwire: invalid connect_timeout %q", v)
			}
			cfg.ConnectTimeout = time.Duration(secs) * time.Second
		case "search_path", "timezone", "statement_timeout", "options":
			cfg.StatementParams[k] = v
		}
	}

	if cfg.User == "" {
		return nil, fmt.Errorf("pgwire: DSN is missing a user")
	}
	if cfg.Database == "" {
		cfg.Database = cfg.User
	}
	if cfg.SSLMode == SSLVerifyFull && (cfg.Host == "localhost" || cfg.Host == "127.0.0.1") {
		// Not an error: local development uses a Unix-adjacent loopback where a
		// certificate chain is meaningless. Callers set sslmode explicitly.
		_ = cfg
	}
	return cfg, nil
}

// splitKeywordDSN splits on whitespace while honouring single-quoted values.
func splitKeywordDSN(s string) []string {
	var (
		out   []string
		cur   strings.Builder
		quote bool
	)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			quote = !quote
			cur.WriteByte(c)
		case (c == ' ' || c == '\t') && !quote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func (c *Config) address() string {
	return net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
}
