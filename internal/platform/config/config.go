// Package config loads and validates process configuration.
//
// Precedence: defaults -> file -> environment (SF_ prefix) -> flags.
// The process exits non-zero on any invalid or missing required value, because
// a service that starts with a half-valid security configuration is worse than
// one that does not start.
//
// Secrets never appear in configuration files. Fields that hold credentials
// carry a `secret://name#key` reference which the secrets package resolves at
// startup and on rotation.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/specforge/specforge/internal/platform/buildinfo"
	"github.com/specforge/specforge/internal/platform/objstore"
)

// Env is the deployment environment.
type Env string

const (
	EnvDevelopment Env = "development"
	EnvTest        Env = "test"
	EnvStaging     Env = "staging"
	EnvProduction  Env = "production"
)

func (e Env) IsProduction() bool  { return e == EnvProduction }
func (e Env) IsDevelopment() bool { return e == EnvDevelopment || e == EnvTest }

// Config is the full process configuration.
type Config struct {
	Env         Env
	ServiceName string
	Version     string

	HTTP       HTTPConfig
	DB         DBConfig
	Cache      CacheConfig
	ObjStore   ObjStoreConfig
	Events     EventsConfig
	Auth       AuthConfig
	Obs        ObsConfig
	AI         AIConfig
	Governance GovernanceConfig
	Limits     LimitsConfig
}

type HTTPConfig struct {
	Addr            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	HandlerTimeout  time.Duration
	MaxBodyBytes    int64
	AllowedOrigins  []string
	TrustedProxies  []string
	// PublicBaseURL is used to build absolute URLs (OIDC redirect, problem types).
	PublicBaseURL string
}

type DBConfig struct {
	Driver           string // "pgwire" (default) or "pgx" when built with the pgx tag
	DSN              string
	MaxOpenConns     int
	MaxIdleConns     int
	ConnMaxLifetime  time.Duration
	ConnMaxIdleTime  time.Duration
	StatementTimeout time.Duration
	MigrationsDir    string
}

type CacheConfig struct {
	Provider string // "memory" | "redis"
	Addr     string
	Password string
	DB       int
	TLS      bool
	TTL      time.Duration
}

type ObjStoreConfig struct {
	// Provider selects the adapter. See objstore.Providers for what this build
	// contains; Validate refuses anything else at startup.
	Provider string // "db" | "fs"
	Root     string // filesystem root when Provider == "fs"
	// Endpoint and Region are carried for a future S3 adapter and are ignored by
	// the adapters that exist. They are kept so that moving to one is a
	// configuration change rather than a schema change.
	Endpoint       string
	Region         string
	ContentBucket  string
	EvidenceBucket string
	AccessKey      string
	SecretKey      string
	// ObjectLock enables write-once semantics on the evidence bucket. It is
	// mandatory in production: approval evidence that can be deleted is not evidence.
	ObjectLock bool
}

type EventsConfig struct {
	Provider      string // "memory" | "log" | "kafka"
	Brokers       []string
	TopicPrefix   string
	LogDir        string
	RelayBatch    int
	RelayInterval time.Duration
}

type AuthConfig struct {
	Issuer       string
	Audience     string
	JWKSURL      string
	JWKSTTL      time.Duration
	TenantClaim  string
	RolesClaim   string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	CookieName   string
	CookieDomain string
	SessionTTL   time.Duration
	StepUpMaxAge time.Duration
	ClockSkew    time.Duration
	// DevIdP starts the built-in OIDC provider. Refused in production.
	DevIdP     bool
	DevIdPAddr string
}

type ObsConfig struct {
	OTLPEndpoint  string
	SampleRatio   float64
	MetricsAddr   string
	LogLevel      string
	LogFormat     string // "json" | "text"
	ServiceName   string
	ExportTimeout time.Duration
}

type AIConfig struct {
	GatewayURL      string
	DefaultProvider string
	RequestTimeout  time.Duration
	StreamTimeout   time.Duration
}

type GovernanceConfig struct {
	FourEyes            bool
	StepUpMaxAge        time.Duration
	MaxExceptionDays    int
	MinDispositionChars int
	EvidenceRetention   time.Duration
}

type LimitsConfig struct {
	RPSPerPrincipal int
	RPSPerTenant    int
	BurstMultiplier int
	MaxGraphDepth   int
	MaxPageSize     int
	DefaultPageSize int
}

// Default returns the baseline configuration.
func Default() Config {
	return Config{
		Env:         EnvDevelopment,
		ServiceName: "specforge-api",
		Version:     buildinfo.Get().Version,
		HTTP: HTTPConfig{
			Addr:            ":8080",
			ReadTimeout:     10 * time.Second,
			WriteTimeout:    30 * time.Second,
			IdleTimeout:     120 * time.Second,
			ShutdownTimeout: 25 * time.Second,
			HandlerTimeout:  15 * time.Second,
			MaxBodyBytes:    1 << 20,
			AllowedOrigins:  []string{"http://localhost:3000"},
			PublicBaseURL:   "http://localhost:8080",
		},
		DB: DBConfig{
			Driver:           "pgwire",
			DSN:              "host=127.0.0.1 port=5432 user=specforge dbname=specforge sslmode=disable",
			MaxOpenConns:     25,
			MaxIdleConns:     5,
			ConnMaxLifetime:  30 * time.Minute,
			ConnMaxIdleTime:  5 * time.Minute,
			StatementTimeout: 15 * time.Second,
			MigrationsDir:    "migrations",
		},
		Cache:    CacheConfig{Provider: "memory", TTL: 60 * time.Second},
		ObjStore: ObjStoreConfig{Provider: "fs", Root: "./.data/objstore", ContentBucket: "sf-content", EvidenceBucket: "sf-evidence", ObjectLock: true},
		Events: EventsConfig{
			Provider: "memory", TopicPrefix: "sf.", LogDir: "./.data/events",
			RelayBatch: 200, RelayInterval: 500 * time.Millisecond,
		},
		Auth: AuthConfig{
			JWKSTTL:      5 * time.Minute,
			TenantClaim:  "https://specforge.io/tenant",
			RolesClaim:   "https://specforge.io/roles",
			CookieName:   "sf_session",
			SessionTTL:   8 * time.Hour,
			StepUpMaxAge: 15 * time.Minute,
			ClockSkew:    60 * time.Second,
			DevIdP:       true,
			DevIdPAddr:   ":8081",
		},
		Obs: ObsConfig{
			SampleRatio: 0.1, MetricsAddr: ":9090", LogLevel: "info", LogFormat: "json",
			ExportTimeout: 10 * time.Second,
		},
		AI: AIConfig{
			GatewayURL: "http://127.0.0.1:8090", DefaultProvider: "simulator",
			RequestTimeout: 60 * time.Second, StreamTimeout: 300 * time.Second,
		},
		Governance: GovernanceConfig{
			FourEyes: true, StepUpMaxAge: 15 * time.Minute, MaxExceptionDays: 90,
			MinDispositionChars: 30, EvidenceRetention: 7 * 365 * 24 * time.Hour,
		},
		Limits: LimitsConfig{
			RPSPerPrincipal: 50, RPSPerTenant: 200, BurstMultiplier: 4,
			MaxGraphDepth: 12, MaxPageSize: 200, DefaultPageSize: 50,
		},
	}
}

// Load builds the configuration from defaults plus environment overrides and
// validates the result.
func Load() (Config, error) {
	c := Default()
	c.applyEnv()
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// MustLoad loads the configuration or terminates the process.
func MustLoad() Config {
	c, err := Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		os.Exit(2)
	}
	return c
}

func (c *Config) applyEnv() {
	str := func(key string, dst *string) {
		if v, ok := os.LookupEnv("SF_" + key); ok {
			*dst = v
		}
	}
	num := func(key string, dst *int) {
		if v, ok := os.LookupEnv("SF_" + key); ok {
			if n, err := strconv.Atoi(v); err == nil {
				*dst = n
			}
		}
	}
	dur := func(key string, dst *time.Duration) {
		if v, ok := os.LookupEnv("SF_" + key); ok {
			if d, err := time.ParseDuration(v); err == nil {
				*dst = d
			}
		}
	}
	boolean := func(key string, dst *bool) {
		if v, ok := os.LookupEnv("SF_" + key); ok {
			*dst = v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
		}
	}
	list := func(key string, dst *[]string) {
		if v, ok := os.LookupEnv("SF_" + key); ok && v != "" {
			parts := strings.Split(v, ",")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			*dst = parts
		}
	}

	if v, ok := os.LookupEnv("SF_ENV"); ok {
		c.Env = Env(v)
	}
	str("SERVICE_NAME", &c.ServiceName)
	str("VERSION", &c.Version)

	str("HTTP_ADDR", &c.HTTP.Addr)
	dur("HTTP_READ_TIMEOUT", &c.HTTP.ReadTimeout)
	dur("HTTP_WRITE_TIMEOUT", &c.HTTP.WriteTimeout)
	dur("HTTP_SHUTDOWN_TIMEOUT", &c.HTTP.ShutdownTimeout)
	dur("HTTP_HANDLER_TIMEOUT", &c.HTTP.HandlerTimeout)
	list("HTTP_ALLOWED_ORIGINS", &c.HTTP.AllowedOrigins)
	str("HTTP_PUBLIC_BASE_URL", &c.HTTP.PublicBaseURL)

	str("DB_DRIVER", &c.DB.Driver)
	str("DB_DSN", &c.DB.DSN)
	num("DB_MAX_OPEN_CONNS", &c.DB.MaxOpenConns)
	num("DB_MAX_IDLE_CONNS", &c.DB.MaxIdleConns)
	dur("DB_STATEMENT_TIMEOUT", &c.DB.StatementTimeout)
	str("DB_MIGRATIONS_DIR", &c.DB.MigrationsDir)

	str("CACHE_PROVIDER", &c.Cache.Provider)
	str("CACHE_ADDR", &c.Cache.Addr)
	str("CACHE_PASSWORD", &c.Cache.Password)
	boolean("CACHE_TLS", &c.Cache.TLS)

	str("OBJSTORE_PROVIDER", &c.ObjStore.Provider)
	str("OBJSTORE_ROOT", &c.ObjStore.Root)
	str("OBJSTORE_ENDPOINT", &c.ObjStore.Endpoint)
	str("OBJSTORE_REGION", &c.ObjStore.Region)
	str("OBJSTORE_CONTENT_BUCKET", &c.ObjStore.ContentBucket)
	str("OBJSTORE_EVIDENCE_BUCKET", &c.ObjStore.EvidenceBucket)
	str("OBJSTORE_ACCESS_KEY", &c.ObjStore.AccessKey)
	str("OBJSTORE_SECRET_KEY", &c.ObjStore.SecretKey)
	boolean("OBJSTORE_OBJECT_LOCK", &c.ObjStore.ObjectLock)

	str("EVENTS_PROVIDER", &c.Events.Provider)
	list("EVENTS_BROKERS", &c.Events.Brokers)
	str("EVENTS_TOPIC_PREFIX", &c.Events.TopicPrefix)
	str("EVENTS_LOG_DIR", &c.Events.LogDir)
	num("EVENTS_RELAY_BATCH", &c.Events.RelayBatch)
	dur("EVENTS_RELAY_INTERVAL", &c.Events.RelayInterval)

	str("AUTH_ISSUER", &c.Auth.Issuer)
	str("AUTH_AUDIENCE", &c.Auth.Audience)
	str("AUTH_JWKS_URL", &c.Auth.JWKSURL)
	str("AUTH_TENANT_CLAIM", &c.Auth.TenantClaim)
	str("AUTH_ROLES_CLAIM", &c.Auth.RolesClaim)
	str("AUTH_CLIENT_ID", &c.Auth.ClientID)
	str("AUTH_CLIENT_SECRET", &c.Auth.ClientSecret)
	str("AUTH_REDIRECT_URL", &c.Auth.RedirectURL)
	dur("AUTH_SESSION_TTL", &c.Auth.SessionTTL)
	dur("AUTH_STEP_UP_MAX_AGE", &c.Auth.StepUpMaxAge)
	boolean("AUTH_DEV_IDP", &c.Auth.DevIdP)
	str("AUTH_DEV_IDP_ADDR", &c.Auth.DevIdPAddr)

	str("OTEL_ENDPOINT", &c.Obs.OTLPEndpoint)
	str("LOG_LEVEL", &c.Obs.LogLevel)
	str("LOG_FORMAT", &c.Obs.LogFormat)
	str("METRICS_ADDR", &c.Obs.MetricsAddr)
	if v, ok := os.LookupEnv("SF_OTEL_SAMPLE_RATIO"); ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			c.Obs.SampleRatio = f
		}
	}

	str("AI_GATEWAY_URL", &c.AI.GatewayURL)
	str("AI_DEFAULT_PROVIDER", &c.AI.DefaultProvider)

	boolean("GOV_FOUR_EYES", &c.Governance.FourEyes)
	num("GOV_MAX_EXCEPTION_DAYS", &c.Governance.MaxExceptionDays)

	num("LIMIT_RPS_PER_PRINCIPAL", &c.Limits.RPSPerPrincipal)
	num("LIMIT_RPS_PER_TENANT", &c.Limits.RPSPerTenant)
	num("LIMIT_MAX_GRAPH_DEPTH", &c.Limits.MaxGraphDepth)
}

// Validate checks the configuration, applying stricter rules in production.
func (c *Config) Validate() error {
	var problems []string
	add := func(f string, a ...any) { problems = append(problems, fmt.Sprintf(f, a...)) }

	switch c.Env {
	case EnvDevelopment, EnvTest, EnvStaging, EnvProduction:
	default:
		add("unknown env %q", c.Env)
	}

	if c.HTTP.Addr == "" {
		add("http.addr is required")
	}
	if c.HTTP.MaxBodyBytes <= 0 {
		add("http.max_body_bytes must be positive")
	}
	if c.DB.DSN == "" {
		add("db.dsn is required")
	}
	if c.DB.MaxOpenConns < 1 {
		add("db.max_open_conns must be at least 1")
	}
	// Catch an unavailable object store adapter here, where the message reaches
	// somebody, rather than at the first write — or, worse, in a crash loop
	// whose only symptom is a container restarting every sixty seconds.
	if !objstore.Supported(c.ObjStore.Provider) {
		add("objstore.provider=%q is not available in this build; supported providers are %s",
			c.ObjStore.Provider, strings.Join(objstore.ProviderNames(), ", "))
	}
	if c.Limits.MaxGraphDepth < 1 || c.Limits.MaxGraphDepth > 64 {
		add("limits.max_graph_depth must be between 1 and 64")
	}
	if c.Obs.SampleRatio < 0 || c.Obs.SampleRatio > 1 {
		add("obs.sample_ratio must be between 0 and 1")
	}
	if c.Governance.MaxExceptionDays < 1 || c.Governance.MaxExceptionDays > 365 {
		add("governance.max_exception_days must be between 1 and 365")
	}

	if c.Env.IsProduction() {
		// Production hardening. Each of these has been a real incident somewhere.
		if c.Auth.DevIdP {
			add("auth.dev_idp must be disabled in production")
		}
		if c.Auth.Issuer == "" {
			add("auth.issuer is required in production")
		}
		if c.Auth.Audience == "" {
			add("auth.audience is required in production")
		}
		if strings.Contains(c.DB.DSN, "sslmode=disable") {
			add("db.dsn must not disable TLS in production")
		}
		if !c.ObjStore.ObjectLock {
			add("objstore.object_lock must be enabled in production so approval evidence is immutable")
		}
		if c.ObjStore.Provider == "fs" {
			// The filesystem adapter enforces write-once in application code and
			// on one node's disk. Neither survives the failure modes production
			// has to survive.
			add("objstore.provider=fs is not supported in production; use db")
		}
		if c.Events.Provider == "memory" {
			add("events.provider=memory is not supported in production")
		}
		if c.Cache.Provider == "memory" {
			add("cache.provider=memory is not supported in production")
		}
		for _, o := range c.HTTP.AllowedOrigins {
			if o == "*" {
				add("http.allowed_origins must not contain a wildcard in production")
			}
			if strings.HasPrefix(o, "http://") {
				add("http.allowed_origins must use https in production (%s)", o)
			}
		}
		if !strings.HasPrefix(c.HTTP.PublicBaseURL, "https://") {
			add("http.public_base_url must use https in production")
		}
		if !c.Governance.FourEyes {
			add("governance.four_eyes cannot be disabled in production")
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

// Redacted returns a copy safe to log: every credential-bearing field is masked.
func (c Config) Redacted() Config {
	mask := func(s string) string {
		if s == "" {
			return ""
		}
		return "***redacted***"
	}
	c.DB.DSN = redactDSN(c.DB.DSN)
	c.Cache.Password = mask(c.Cache.Password)
	c.ObjStore.AccessKey = mask(c.ObjStore.AccessKey)
	c.ObjStore.SecretKey = mask(c.ObjStore.SecretKey)
	c.Auth.ClientSecret = mask(c.Auth.ClientSecret)
	return c
}

// redactDSN strips the password from a connection string in both DSN forms.
func redactDSN(dsn string) string {
	if i := strings.Index(dsn, "password="); i >= 0 {
		end := strings.IndexAny(dsn[i+9:], " \t")
		if end < 0 {
			return dsn[:i] + "password=***"
		}
		return dsn[:i] + "password=***" + dsn[i+9+end:]
	}
	// URL form: scheme://user:pass@host
	if at := strings.Index(dsn, "@"); at > 0 {
		if scheme := strings.Index(dsn, "://"); scheme >= 0 && scheme < at {
			userinfo := dsn[scheme+3 : at]
			if colon := strings.Index(userinfo, ":"); colon >= 0 {
				return dsn[:scheme+3] + userinfo[:colon] + ":***" + dsn[at:]
			}
		}
	}
	return dsn
}
