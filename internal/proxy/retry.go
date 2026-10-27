package proxy

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"time"
)

// retryTransport retries upstream calls only when doing so cannot duplicate
// billable work:
//
//   - connection-establishment failures (dial/DNS): the request never left;
//   - HTTP 429 (except insufficient_quota): the upstream rejected the request
//     without processing it;
//   - 5xx and other transport errors, but only for idempotent methods
//     (GET/HEAD/OPTIONS/DELETE). A POST that hit a 5xx or a dropped connection
//     may already have been processed and billed, so it is never replayed.
//
// Retries happen before any response is handed to the ReverseProxy, so a
// stream is never retried after bytes reach the client.
type retryTransport struct {
	base     http.RoundTripper
	max      int
	maxWait  time.Duration
	baseWait time.Duration
	capWait  time.Duration
	onRetry  func()
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	st := stateFrom(req.Context())
	r := req
	for attempt := 0; ; attempt++ {
		resp, err := t.base.RoundTrip(r)
		if attempt >= t.max || req.Context().Err() != nil {
			return resp, err
		}
		wait, ok := t.shouldRetry(r, resp, err, attempt)
		if !ok {
			return resp, err
		}
		if resp != nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
		}
		next := req.Clone(req.Context())
		if req.GetBody != nil {
			if next.Body, err = req.GetBody(); err != nil {
				return nil, err
			}
		}
		if st != nil {
			st.retries++
		}
		if t.onRetry != nil {
			t.onRetry()
		}
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-req.Context().Done():
			timer.Stop()
			return nil, req.Context().Err()
		}
		r = next
	}
}

func (t *retryTransport) shouldRetry(req *http.Request, resp *http.Response, err error, attempt int) (time.Duration, bool) {
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		return 0, false
	}
	idempotent := req.Method == http.MethodGet || req.Method == http.MethodHead ||
		req.Method == http.MethodOptions || req.Method == http.MethodDelete
	if err != nil {
		if isConnectError(err) || idempotent {
			return t.backoff(attempt), true
		}
		return 0, false
	}
	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		if bytes.Contains(peekBody(resp, 64<<10), []byte("insufficient_quota")) {
			return 0, false // retrying will not help
		}
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		if !idempotent {
			return 0, false
		}
	default:
		return 0, false
	}
	wait, ok := retryAfter(resp.Header, time.Now())
	if !ok {
		wait = t.backoff(attempt)
	}
	if wait > t.maxWait {
		return 0, false // let the client decide; don't hold the connection
	}
	return wait, true
}

// backoff is exponential with jitter in [d/2, d].
func (t *retryTransport) backoff(attempt int) time.Duration {
	d := t.baseWait << attempt
	if d > t.capWait || d <= 0 {
		d = t.capWait
	}
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}

func isConnectError(err error) bool {
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return true
	}
	var dns *net.DNSError
	return errors.As(err, &dns)
}

// retryAfter parses retry-after-ms (OpenAI) and Retry-After (seconds or date).
func retryAfter(h http.Header, now time.Time) (time.Duration, bool) {
	if v := h.Get("Retry-After-Ms"); v != "" {
		if ms, err := strconv.ParseFloat(v, 64); err == nil && ms >= 0 {
			return time.Duration(ms * float64(time.Millisecond)), true
		}
	}
	if v := h.Get("Retry-After"); v != "" {
		if s, err := strconv.ParseFloat(v, 64); err == nil && s >= 0 {
			return time.Duration(s * float64(time.Second)), true
		}
		if at, err := http.ParseTime(v); err == nil {
			return max(at.Sub(now), 0), true
		}
	}
	return 0, false
}

// peekBody reads up to n bytes of resp.Body and puts them back.
func peekBody(resp *http.Response, n int64) []byte {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, n))
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(b), resp.Body), resp.Body}
	return b
}
