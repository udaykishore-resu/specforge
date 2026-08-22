// Package ratelimit implements per-principal and per-tenant request limiting.
//
// The limiter is a sliding window over a cache counter. It is deliberately
// simple and fails open on cache errors: a cache outage should degrade limiting,
// not take down the API. Quotas that must fail closed (AI token budgets) live in
// the gateway and are backed by the database instead.
package ratelimit

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/specforge/specforge/internal/platform/cache"
	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/obs"
	"github.com/specforge/specforge/internal/platform/types"
)

// Limit describes an allowance.
type Limit struct {
	Requests int
	Window   time.Duration
	Burst    int
}

// Decision is the outcome of a limit check.
type Decision struct {
	Allowed    bool
	Limit      int
	Remaining  int
	ResetAfter time.Duration
}

// Limiter enforces limits against a cache backend.
type Limiter struct {
	cache cache.Cache
	// failOpen keeps traffic flowing when the cache is unavailable.
	failOpen bool
}

// New builds a limiter.
func New(c cache.Cache) *Limiter { return &Limiter{cache: c, failOpen: true} }

// Allow checks and consumes one unit against a dimension.
func (l *Limiter) Allow(ctx context.Context, tenantID types.TenantID, dimension, subject string, lim Limit) (Decision, error) {
	if lim.Requests <= 0 || lim.Window <= 0 {
		return Decision{Allowed: true}, nil
	}
	effective := lim.Requests
	if lim.Burst > effective {
		effective = lim.Burst
	}

	// The window is bucketed by wall clock so every replica agrees on the
	// boundary without coordination.
	bucket := time.Now().UnixNano() / int64(lim.Window)
	key := cache.Key(tenantID, "rl", dimension, subject, strconv.FormatInt(bucket, 10))

	n, err := l.cache.Incr(ctx, key, lim.Window*2)
	if err != nil {
		obs.Counter("sf_ratelimit_errors_total", "Rate limiter backend errors",
			obs.Labels{"dimension": dimension})
		if l.failOpen {
			return Decision{Allowed: true, Limit: effective, Remaining: effective}, nil
		}
		return Decision{}, err
	}

	resetAfter := time.Duration((bucket+1)*int64(lim.Window)) - time.Duration(time.Now().UnixNano())
	if resetAfter < 0 {
		resetAfter = 0
	}
	remaining := effective - int(n)
	if remaining < 0 {
		remaining = 0
	}

	allowed := int(n) <= effective
	if !allowed {
		obs.Counter("sf_ratelimit_rejections_total", "Rate limited requests",
			obs.Labels{"dimension": dimension})
	}
	return Decision{
		Allowed: allowed, Limit: effective, Remaining: remaining, ResetAfter: resetAfter,
	}, nil
}

// Config holds the limits applied by the middleware.
type Config struct {
	PerPrincipal Limit
	PerTenant    Limit
}

// PrincipalResolver extracts the identifiers the limiter keys on. Supplied by
// the server so this package does not depend on the authz package.
type PrincipalResolver func(r *http.Request) (tenantID types.TenantID, principalID string, ok bool)

// Middleware applies both limits, principal first so that one noisy user is
// reported as such rather than as a tenant-wide problem.
func (l *Limiter) Middleware(cfg Config, resolve PrincipalResolver,
	onReject func(http.ResponseWriter, *http.Request, error)) func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID, principalID, ok := resolve(r)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			ctx := r.Context()

			if principalID != "" && cfg.PerPrincipal.Requests > 0 {
				d, err := l.Allow(ctx, tenantID, "principal", principalID, cfg.PerPrincipal)
				if err == nil {
					writeHeaders(w, d)
					if !d.Allowed {
						reject(w, r, d, onReject, "principal")
						return
					}
				}
			}

			if cfg.PerTenant.Requests > 0 {
				d, err := l.Allow(ctx, tenantID, "tenant", tenantID.String(), cfg.PerTenant)
				if err == nil && !d.Allowed {
					writeHeaders(w, d)
					reject(w, r, d, onReject, "tenant")
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func writeHeaders(w http.ResponseWriter, d Decision) {
	w.Header().Set("RateLimit-Limit", strconv.Itoa(d.Limit))
	w.Header().Set("RateLimit-Remaining", strconv.Itoa(d.Remaining))
	w.Header().Set("RateLimit-Reset", strconv.Itoa(int(d.ResetAfter.Seconds())+1))
}

func reject(w http.ResponseWriter, r *http.Request, d Decision,
	onReject func(http.ResponseWriter, *http.Request, error), dimension string) {

	retry := int(d.ResetAfter.Seconds()) + 1
	w.Header().Set("Retry-After", strconv.Itoa(retry))
	err := errors.Exhausted("ratelimit.Middleware", "ratelimit.exceeded",
		"Too many requests. Retry in %d seconds.", retry).
		WithDetail("dimension", dimension).
		WithDetail("limit", d.Limit)
	onReject(w, r, err)
}
