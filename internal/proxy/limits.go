package proxy

import (
	"sync"
	"time"

	"oaiproxy/internal/tokens"
)

// limiter enforces one client's request rate (token bucket) and in-flight
// concurrency. Limits are rejected immediately with 429 rather than queued, so
// load is pushed back to clients, whose SDKs already retry with backoff.
type limiter struct {
	rpm, cfgBurst, burst, maxConc int

	mu     sync.Mutex
	tokens float64
	last   time.Time

	sem chan struct{}
}

func newLimiter(p *tokens.Principal) *limiter {
	l := &limiter{rpm: p.RPM, cfgBurst: p.Burst, burst: p.Burst, maxConc: p.MaxConcurrent}
	if l.burst <= 0 {
		l.burst = l.rpm
	}
	l.tokens = float64(l.burst)
	if l.maxConc > 0 {
		l.sem = make(chan struct{}, l.maxConc)
	}
	return l
}

func (l *limiter) sameConfig(p *tokens.Principal) bool {
	return l.rpm == p.RPM && l.cfgBurst == p.Burst && l.maxConc == p.MaxConcurrent
}

// allow takes one request token, or reports how long until one is available.
func (l *limiter) allow(now time.Time) (bool, time.Duration) {
	if l.rpm <= 0 {
		return true, 0
	}
	rate := float64(l.rpm) / 60 // per second
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.last.IsZero() {
		l.tokens = min(float64(l.burst), l.tokens+now.Sub(l.last).Seconds()*rate)
	}
	l.last = now
	if l.tokens >= 1 {
		l.tokens--
		return true, 0
	}
	return false, time.Duration((1 - l.tokens) / rate * float64(time.Second))
}

// acquire reserves an in-flight slot. The release func is bound to this
// limiter, so a config reload that replaces it cannot corrupt the count.
func (l *limiter) acquire() (func(), bool) {
	if l.sem == nil {
		return func() {}, true
	}
	select {
	case l.sem <- struct{}{}:
		return func() { <-l.sem }, true
	default:
		return nil, false
	}
}

type limiterSet struct {
	mu sync.Mutex
	m  map[string]*limiter
}

func (s *limiterSet) get(p *tokens.Principal) *limiter {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.m[p.ID]
	if l == nil || !l.sameConfig(p) {
		l = newLimiter(p)
		if s.m == nil {
			s.m = map[string]*limiter{}
		}
		s.m[p.ID] = l
	}
	return l
}

// prune drops state for clients that no longer exist.
func (s *limiterSet) prune(ids []string) {
	keep := make(map[string]bool, len(ids))
	for _, id := range ids {
		keep[id] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.m {
		if !keep[id] {
			delete(s.m, id)
		}
	}
}
