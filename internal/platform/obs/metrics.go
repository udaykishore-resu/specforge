// Package obs provides metrics and tracing.
//
// It implements the Prometheus text exposition format and W3C trace context
// with an OTLP/HTTP JSON exporter directly, so the platform has no third-party
// telemetry dependency. The wire formats are the standard ones: any Prometheus
// scraper and any OpenTelemetry collector consume this output unchanged.
package obs

import (
	"fmt"
	"hash/fnv"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Labels are metric dimensions. Cardinality discipline is the caller's
// responsibility: use templated route names, never concrete URLs, and use
// TenantBucket rather than a raw tenant identifier.
type Labels map[string]string

func (l Labels) key() string {
	if len(l) == 0 {
		return ""
	}
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(l[k])
	}
	return sb.String()
}

func (l Labels) render() string {
	if len(l) == 0 {
		return ""
	}
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(k)
		sb.WriteString(`="`)
		sb.WriteString(escapeLabel(l[k]))
		sb.WriteByte('"')
	}
	sb.WriteByte('}')
	return sb.String()
}

func escapeLabel(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(v)
}

// TenantBucket maps a tenant identifier to one of n buckets, so that tenant
// dimensions can be kept on metrics without unbounded cardinality.
func TenantBucket(tenantID string, n int) string {
	if tenantID == "" {
		return "none"
	}
	if n <= 0 {
		n = 64
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(tenantID))
	return "b" + strconv.Itoa(int(h.Sum32()%uint32(n)))
}

// ---------------------------------------------------------------------------
// Instruments
// ---------------------------------------------------------------------------

type metricKind string

const (
	kindCounter   metricKind = "counter"
	kindGauge     metricKind = "gauge"
	kindHistogram metricKind = "histogram"
)

type series struct {
	labels Labels
	// counter/gauge value, stored as bits so gauges can hold floats atomically
	value atomic.Uint64
	// histogram state
	mu      sync.Mutex
	buckets []uint64
	sum     float64
	count   uint64
}

type metric struct {
	name    string
	help    string
	kind    metricKind
	bounds  []float64
	mu      sync.RWMutex
	seriesM map[string]*series
}

// Registry holds every metric in the process.
type Registry struct {
	mu      sync.RWMutex
	metrics map[string]*metric
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{metrics: make(map[string]*metric)}
}

// Default is the process-wide registry.
var Default = NewRegistry()

func (r *Registry) metricFor(name, help string, kind metricKind, bounds []float64) *metric {
	r.mu.RLock()
	m, ok := r.metrics[name]
	r.mu.RUnlock()
	if ok {
		if m.kind != kind {
			panic(fmt.Sprintf("obs: metric %q already registered as %s, requested %s", name, m.kind, kind))
		}
		return m
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if m, ok := r.metrics[name]; ok {
		return m
	}
	m = &metric{name: name, help: help, kind: kind, bounds: bounds, seriesM: map[string]*series{}}
	r.metrics[name] = m
	return m
}

func (m *metric) seriesFor(l Labels) *series {
	k := l.key()
	m.mu.RLock()
	s, ok := m.seriesM[k]
	m.mu.RUnlock()
	if ok {
		return s
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.seriesM[k]; ok {
		return s
	}
	cp := make(Labels, len(l))
	for k, v := range l {
		cp[k] = v
	}
	s = &series{labels: cp}
	if m.kind == kindHistogram {
		s.buckets = make([]uint64, len(m.bounds))
	}
	m.seriesM[k] = s
	return s
}

// Counter increments a monotonic counter.
func (r *Registry) Counter(name, help string, l Labels) { r.CounterAdd(name, help, l, 1) }

// CounterAdd adds delta to a counter. Negative deltas are ignored: a counter
// that can go down is a gauge, and silently accepting one hides the bug.
func (r *Registry) CounterAdd(name, help string, l Labels, delta float64) {
	if delta < 0 {
		return
	}
	s := r.metricFor(name, help, kindCounter, nil).seriesFor(l)
	for {
		old := s.value.Load()
		next := math.Float64bits(math.Float64frombits(old) + delta)
		if s.value.CompareAndSwap(old, next) {
			return
		}
	}
}

// GaugeSet sets a gauge value.
func (r *Registry) GaugeSet(name, help string, l Labels, v float64) {
	r.metricFor(name, help, kindGauge, nil).seriesFor(l).value.Store(math.Float64bits(v))
}

// GaugeAdd adds delta to a gauge.
func (r *Registry) GaugeAdd(name, help string, l Labels, delta float64) {
	s := r.metricFor(name, help, kindGauge, nil).seriesFor(l)
	for {
		old := s.value.Load()
		next := math.Float64bits(math.Float64frombits(old) + delta)
		if s.value.CompareAndSwap(old, next) {
			return
		}
	}
}

// DefaultBuckets covers the latency range the platform cares about, from a
// cache hit to a slow governance evaluation.
var DefaultBuckets = []float64{
	0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30,
}

// Observe records a value in a histogram.
func (r *Registry) Observe(name, help string, l Labels, v float64) {
	r.ObserveWithBuckets(name, help, l, v, DefaultBuckets)
}

// ObserveWithBuckets records a value using explicit bucket bounds.
func (r *Registry) ObserveWithBuckets(name, help string, l Labels, v float64, bounds []float64) {
	m := r.metricFor(name, help, kindHistogram, bounds)
	s := m.seriesFor(l)
	s.mu.Lock()
	s.sum += v
	s.count++
	for i, b := range m.bounds {
		if v <= b {
			s.buckets[i]++
		}
	}
	s.mu.Unlock()
}

// Gather renders the registry in the Prometheus text exposition format.
func (r *Registry) Gather() string {
	r.mu.RLock()
	names := make([]string, 0, len(r.metrics))
	for n := range r.metrics {
		names = append(names, n)
	}
	metrics := make(map[string]*metric, len(r.metrics))
	for n, m := range r.metrics {
		metrics[n] = m
	}
	r.mu.RUnlock()
	sort.Strings(names)

	var sb strings.Builder
	for _, n := range names {
		m := metrics[n]
		if m.help != "" {
			fmt.Fprintf(&sb, "# HELP %s %s\n", m.name, strings.ReplaceAll(m.help, "\n", " "))
		}
		fmt.Fprintf(&sb, "# TYPE %s %s\n", m.name, m.kind)

		m.mu.RLock()
		keys := make([]string, 0, len(m.seriesM))
		for k := range m.seriesM {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			s := m.seriesM[k]
			switch m.kind {
			case kindCounter, kindGauge:
				fmt.Fprintf(&sb, "%s%s %s\n", m.name, s.labels.render(),
					formatValue(math.Float64frombits(s.value.Load())))
			case kindHistogram:
				s.mu.Lock()
				// Observe increments every bucket whose bound the value satisfies,
				// so the counts are already cumulative as Prometheus requires.
				for i, b := range m.bounds {
					l := cloneWith(s.labels, "le", formatValue(b))
					fmt.Fprintf(&sb, "%s_bucket%s %d\n", m.name, l.render(), s.buckets[i])
				}
				infLabels := cloneWith(s.labels, "le", "+Inf")
				fmt.Fprintf(&sb, "%s_bucket%s %d\n", m.name, infLabels.render(), s.count)
				fmt.Fprintf(&sb, "%s_sum%s %s\n", m.name, s.labels.render(), formatValue(s.sum))
				fmt.Fprintf(&sb, "%s_count%s %d\n", m.name, s.labels.render(), s.count)
				s.mu.Unlock()
			}
		}
		m.mu.RUnlock()
	}
	return sb.String()
}

func cloneWith(l Labels, k, v string) Labels {
	out := make(Labels, len(l)+1)
	for lk, lv := range l {
		out[lk] = lv
	}
	out[k] = v
	return out
}

func formatValue(f float64) string {
	if math.IsInf(f, 1) {
		return "+Inf"
	}
	if math.IsInf(f, -1) {
		return "-Inf"
	}
	if math.IsNaN(f) {
		return "NaN"
	}
	if f == math.Trunc(f) && math.Abs(f) < 1e15 {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// ---------------------------------------------------------------------------
// Package-level helpers against the default registry
// ---------------------------------------------------------------------------

func Counter(name, help string, l Labels)               { Default.Counter(name, help, l) }
func CounterAdd(name, help string, l Labels, d float64) { Default.CounterAdd(name, help, l, d) }
func GaugeSet(name, help string, l Labels, v float64)   { Default.GaugeSet(name, help, l, v) }
func GaugeAdd(name, help string, l Labels, d float64)   { Default.GaugeAdd(name, help, l, d) }
func Observe(name, help string, l Labels, v float64)    { Default.Observe(name, help, l, v) }
func Gather() string                                    { return Default.Gather() }
