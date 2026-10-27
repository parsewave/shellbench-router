package proxy

import (
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var latencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600}

type histogram struct {
	counts []uint64 // per bucket, non-cumulative; last is +Inf
	sum    float64
	n      uint64
}

// Metrics is a minimal Prometheus text-format exporter. It avoids pulling in
// the Prometheus client library to keep the dependency tree empty.
type Metrics struct {
	mu       sync.Mutex
	requests map[[3]string]uint64 // client, endpoint, code
	errors   map[string]uint64    // reason
	tokens   map[[3]string]uint64 // client, model, kind
	latency  map[string]*histogram
	ttfb     map[string]*histogram
	retries  atomic.Uint64
	inflight func() int64
	start    time.Time
}

func NewMetrics() *Metrics {
	return &Metrics{
		requests: map[[3]string]uint64{},
		errors:   map[string]uint64{},
		tokens:   map[[3]string]uint64{},
		latency:  map[string]*histogram{},
		ttfb:     map[string]*histogram{},
		start:    time.Now(),
	}
}

func (m *Metrics) observe(st *reqState) {
	client, route := orDash(st.client), orDash(st.route)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[[3]string{client, route, fmt.Sprint(st.status)}]++
	if st.err != "" {
		m.errors[st.err]++
	}
	if st.route != "" {
		observeHist(m.latency, route, st.latency.Seconds())
		if st.ttfb > 0 {
			observeHist(m.ttfb, route, st.ttfb.Seconds())
		}
	}
	// Model names come from clients; only record them for successful calls,
	// where the upstream has confirmed the model exists (bounded cardinality).
	if st.usage.Total > 0 && st.status/100 == 2 {
		model := st.model
		if len(model) > 128 {
			model = model[:128]
		}
		for kind, v := range map[string]int64{"input": st.usage.Input, "output": st.usage.Output, "reasoning": st.usage.Reasoning, "cached": st.usage.Cached} {
			if v > 0 {
				m.tokens[[3]string{client, model, kind}] += uint64(v)
			}
		}
	}
}

func observeHist(hs map[string]*histogram, key string, v float64) {
	h := hs[key]
	if h == nil {
		h = &histogram{counts: make([]uint64, len(latencyBuckets)+1)}
		hs[key] = h
	}
	i := sort.SearchFloat64s(latencyBuckets, v)
	h.counts[i]++
	h.sum += v
	h.n++
}

func (m *Metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	var b strings.Builder
	m.mu.Lock()
	writeCounter(&b, "oaiproxy_requests_total", "Requests by client, endpoint and status code.", m.requests, "client", "endpoint", "code")
	b.WriteString("# HELP oaiproxy_errors_total Requests that failed or were rejected, by reason.\n# TYPE oaiproxy_errors_total counter\n")
	for _, k := range sortedKeys(m.errors) {
		fmt.Fprintf(&b, "oaiproxy_errors_total{reason=\"%s\"} %d\n", esc(k), m.errors[k])
	}
	writeCounter(&b, "oaiproxy_tokens_total", "Upstream-reported token usage.", m.tokens, "client", "model", "kind")
	writeHists(&b, "oaiproxy_request_duration_seconds", "End-to-end request latency.", m.latency)
	writeHists(&b, "oaiproxy_upstream_ttfb_seconds", "Time until upstream response headers.", m.ttfb)
	m.mu.Unlock()

	fmt.Fprintf(&b, "# TYPE oaiproxy_upstream_retries_total counter\noaiproxy_upstream_retries_total %d\n", m.retries.Load())
	if m.inflight != nil {
		fmt.Fprintf(&b, "# TYPE oaiproxy_inflight_requests gauge\noaiproxy_inflight_requests %d\n", m.inflight())
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	fmt.Fprintf(&b, "# TYPE go_goroutines gauge\ngo_goroutines %d\n", runtime.NumGoroutine())
	fmt.Fprintf(&b, "# TYPE go_memstats_heap_inuse_bytes gauge\ngo_memstats_heap_inuse_bytes %d\n", ms.HeapInuse)
	fmt.Fprintf(&b, "# TYPE go_memstats_sys_bytes gauge\ngo_memstats_sys_bytes %d\n", ms.Sys)
	fmt.Fprintf(&b, "# TYPE process_uptime_seconds gauge\nprocess_uptime_seconds %.0f\n", time.Since(m.start).Seconds())

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.Write([]byte(b.String()))
}

func writeCounter(b *strings.Builder, name, help string, m map[[3]string]uint64, l1, l2, l3 string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	keys := make([][3]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return strings.Join(keys[i][:], "\x00") < strings.Join(keys[j][:], "\x00") })
	for _, k := range keys {
		fmt.Fprintf(b, "%s{%s=\"%s\",%s=\"%s\",%s=\"%s\"} %d\n", name, l1, esc(k[0]), l2, esc(k[1]), l3, esc(k[2]), m[k])
	}
}

func writeHists(b *strings.Builder, name, help string, hs map[string]*histogram) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name)
	for _, k := range sortedKeys(hs) {
		h := hs[k]
		var cum uint64
		for i, le := range latencyBuckets {
			cum += h.counts[i]
			fmt.Fprintf(b, "%s_bucket{endpoint=\"%s\",le=\"%g\"} %d\n", name, esc(k), le, cum)
		}
		fmt.Fprintf(b, "%s_bucket{endpoint=\"%s\",le=\"+Inf\"} %d\n", name, esc(k), h.n)
		fmt.Fprintf(b, "%s_sum{endpoint=\"%s\"} %g\n%s_count{endpoint=\"%s\"} %d\n", name, esc(k), h.sum, name, esc(k), h.n)
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func esc(s string) string { return labelEscaper.Replace(s) }

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
