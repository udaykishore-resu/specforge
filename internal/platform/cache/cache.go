// Package cache provides a tenant-namespaced cache with two adapters.
//
// The namespace rule is the security-relevant part: keys are built server-side
// from a TenantContext, and a caller cannot supply a key fragment that escapes
// its tenant's prefix. A cache miss is always safe; a cross-tenant hit would not
// be, so the API makes the latter unrepresentable.
//
// Cached values are never authoritative. Anything security-relevant is
// re-verified against the database before it is acted on.
package cache

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/specforge/specforge/internal/platform/obs"
	"github.com/specforge/specforge/internal/platform/types"
)

// Cache is the caching port.
type Cache interface {
	Get(ctx context.Context, key string) ([]byte, bool, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, keys ...string) error
	// DeletePrefix invalidates every key under a prefix, used when a tenant's
	// role assignments or policy set change.
	DeletePrefix(ctx context.Context, prefix string) error
	// Incr atomically increments a counter and returns the new value, used by
	// the rate limiter.
	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)
	Health(ctx context.Context) error
	Close() error
}

// Key builds a tenant-namespaced cache key.
//
// Colons in the caller-supplied parts are escaped so a crafted identifier cannot
// forge a different namespace.
func Key(tenantID types.TenantID, parts ...string) string {
	var sb strings.Builder
	sb.WriteString("sf:")
	sb.WriteString(tenantID.String())
	for _, p := range parts {
		sb.WriteByte(':')
		sb.WriteString(strings.ReplaceAll(p, ":", "%3A"))
	}
	return sb.String()
}

// TenantPrefix returns the invalidation prefix for a tenant.
func TenantPrefix(tenantID types.TenantID) string { return "sf:" + tenantID.String() + ":" }

// ---------------------------------------------------------------------------
// In-memory adapter
// ---------------------------------------------------------------------------

type entry struct {
	value     []byte
	expiresAt time.Time
}

// Memory is an in-process cache with TTL expiry and a size bound.
//
// It is a complete implementation, not a placeholder: single-node deployments
// and the local stack use it, and the eviction and expiry semantics match what
// callers expect from Redis.
type Memory struct {
	mu      sync.RWMutex
	data    map[string]entry
	maxKeys int
	stop    chan struct{}
	once    sync.Once
}

var _ Cache = (*Memory)(nil)

// NewMemory creates an in-memory cache and starts its janitor.
func NewMemory(maxKeys int) *Memory {
	if maxKeys <= 0 {
		maxKeys = 100_000
	}
	m := &Memory{data: make(map[string]entry), maxKeys: maxKeys, stop: make(chan struct{})}
	go m.janitor()
	return m
}

func (m *Memory) janitor() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			now := time.Now()
			m.mu.Lock()
			for k, e := range m.data {
				if !e.expiresAt.IsZero() && now.After(e.expiresAt) {
					delete(m.data, k)
				}
			}
			m.mu.Unlock()
		}
	}
}

func (m *Memory) Get(_ context.Context, key string) ([]byte, bool, error) {
	m.mu.RLock()
	e, ok := m.data[key]
	m.mu.RUnlock()

	if !ok || (!e.expiresAt.IsZero() && time.Now().After(e.expiresAt)) {
		obs.Counter("sf_cache_operations_total", "Cache operations",
			obs.Labels{"op": "get", "result": "miss"})
		return nil, false, nil
	}
	obs.Counter("sf_cache_operations_total", "Cache operations",
		obs.Labels{"op": "get", "result": "hit"})
	out := make([]byte, len(e.value))
	copy(out, e.value)
	return out, true, nil
}

func (m *Memory) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	cp := make([]byte, len(value))
	copy(cp, value)

	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.data) >= m.maxKeys {
		// Bounded memory matters more than hit rate: drop the expired entries
		// first, and if that is not enough, drop an arbitrary slice. A cache miss
		// is always correct.
		m.evictLocked()
	}
	m.data[key] = entry{value: cp, expiresAt: exp}
	obs.Counter("sf_cache_operations_total", "Cache operations",
		obs.Labels{"op": "set", "result": "ok"})
	return nil
}

func (m *Memory) evictLocked() {
	now := time.Now()
	for k, e := range m.data {
		if !e.expiresAt.IsZero() && now.After(e.expiresAt) {
			delete(m.data, k)
		}
	}
	if len(m.data) < m.maxKeys {
		return
	}
	target := m.maxKeys / 10
	for k := range m.data {
		delete(m.data, k)
		target--
		if target <= 0 {
			return
		}
	}
}

func (m *Memory) Delete(_ context.Context, keys ...string) error {
	m.mu.Lock()
	for _, k := range keys {
		delete(m.data, k)
	}
	m.mu.Unlock()
	return nil
}

func (m *Memory) DeletePrefix(_ context.Context, prefix string) error {
	m.mu.Lock()
	for k := range m.data {
		if strings.HasPrefix(k, prefix) {
			delete(m.data, k)
		}
	}
	m.mu.Unlock()
	return nil
}

func (m *Memory) Incr(_ context.Context, key string, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.data[key]
	now := time.Now()
	if !ok || (!e.expiresAt.IsZero() && now.After(e.expiresAt)) {
		exp := time.Time{}
		if ttl > 0 {
			exp = now.Add(ttl)
		}
		m.data[key] = entry{value: []byte("1"), expiresAt: exp}
		return 1, nil
	}
	n := parseInt(e.value) + 1
	e.value = formatInt(n)
	m.data[key] = e
	return n, nil
}

func (m *Memory) Health(context.Context) error { return nil }

func (m *Memory) Close() error {
	m.once.Do(func() { close(m.stop) })
	return nil
}

// Len reports the number of live entries. Test and metrics helper.
func (m *Memory) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.data)
}

func parseInt(b []byte) int64 {
	var n int64
	for _, c := range b {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int64(c-'0')
	}
	return n
}

func formatInt(n int64) []byte {
	if n == 0 {
		return []byte("0")
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return append([]byte(nil), buf[i:]...)
}
