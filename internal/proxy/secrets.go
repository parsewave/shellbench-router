package proxy

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"strings"
)

type credentialTransport struct {
	base http.RoundTripper
	p    *Proxy
}

func (t *credentialTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// ReverseProxy forwards 1xx headers before ModifyResponse. A newly added
	// trace runs first, sanitizing the shared map before its forwarding hook.
	ctx := httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{Got1xxResponse: func(_ int, h textproto.MIMEHeader) error {
		t.p.sanitizeHeaders(http.Header(h), stateFrom(r.Context()))
		return nil
	}})
	return t.base.RoundTrip(r.WithContext(ctx))
}

func (p *Proxy) scrubFor(st *reqState, b []byte) []byte {
	if st != nil && st.upstreamKey != "" {
		b = bytes.ReplaceAll(b, []byte(st.upstreamKey), []byte("***"))
	}
	return p.scrub(b)
}

func (p *Proxy) sanitizeHeaders(h http.Header, st *reqState) {
	for _, name := range strippedResponseHeaders {
		h.Del(name)
	}
	for name, values := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "X-Ratelimit-") {
			delete(h, name)
			continue
		}
		for i, value := range values {
			values[i] = string(p.scrubFor(st, []byte(value)))
		}
	}
}

// Only retain a suffix that could become the dispatch secret on the next read.
// Same-length masking preserves Content-Length and every unrelated media byte;
// ordinary SSE fragments need no full-event buffering or lookbehind delay.
type credentialBody struct {
	io.ReadCloser
	secret, pending, ready []byte
	err                    error
	sanitize               func()
}

func (b *credentialBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(b.ready) == 0 && b.err == nil {
		var buf [32 << 10]byte
		n, err := b.ReadCloser.Read(buf[:])
		// ReverseProxy logs copy errors directly. Preserve ordinary error
		// identities, but never let a provider echo the dispatch key there.
		if err != nil && len(b.secret) > 0 && strings.Contains(err.Error(), string(b.secret)) {
			err = errors.New(strings.ReplaceAll(err.Error(), string(b.secret), "***"))
		}
		data := append(b.pending, buf[:n]...)
		b.pending = nil
		if len(b.secret) > 0 && bytes.Contains(data, b.secret) {
			data = bytes.ReplaceAll(data, b.secret, bytes.Repeat([]byte{'*'}, len(b.secret)))
		}
		keep := 0
		if err == nil {
			for i := min(len(data), len(b.secret)-1); i > 0; i-- {
				if bytes.Equal(data[len(data)-i:], b.secret[:i]) {
					keep = i
					break
				}
			}
		}
		b.ready = data[:len(data)-keep]
		if keep > 0 {
			b.pending = bytes.Clone(data[len(data)-keep:])
		}
		b.err = err
		if n == 0 && err == nil {
			return 0, nil
		}
	}
	n := copy(p, b.ready)
	b.ready = b.ready[n:]
	if len(b.ready) == 0 {
		return n, b.err
	}
	return n, nil
}

func (b *credentialBody) Close() error {
	err := b.ReadCloser.Close()
	if b.sanitize != nil {
		b.sanitize()
	}
	return err
}
