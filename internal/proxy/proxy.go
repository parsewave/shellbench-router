// Package proxy implements the authenticated OpenAI-compatible reverse proxy.
//
// Request path: authenticate proxy token -> check the client's IP allowlist -> match an allowed route -> apply
// per-client limits -> inspect the JSON body for the model -> rewrite headers
// (client token out, provider key in) -> httputil.ReverseProxy, which streams
// the upstream response back unmodified (SSE is flushed per write).
package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"oaiproxy/internal/tokens"
)

// KeySource supplies the current upstream API key.
type KeySource interface{ Get() string }

type Options struct {
	Upstream          *url.URL
	Key               KeySource
	Organization      string
	Project           string
	ExtraHeaders      http.Header // provider-configured headers added to every upstream request
	Routes            []string
	MaxRequestBytes   int64
	MaxRetries        int
	MaxRetryWait      time.Duration
	RetryBaseWait     time.Duration // default 500ms
	UpstreamTimeout   time.Duration // total per request, 0 = none
	StreamIdleTimeout time.Duration // max gap between upstream reads, 0 = none
	BodyReadTimeout   time.Duration
	MaxInflight       int
	MaxBufferedBytes  int64             // global cap on buffered request bodies, default 1 GiB
	Transport         http.RoundTripper // nil = tuned http.Transport
	Logger            *slog.Logger
	AccessLog         io.Writer // optional JSONL sink
	Metrics           *Metrics  // optional
	// TrustedProxies are the peers (Caddy) whose X-Forwarded-For is used as
	// the client IP for allowlists. Default: loopback and private ranges.
	TrustedProxies []netip.Prefix
}

type Proxy struct {
	opt      Options
	routes   []Route
	store    atomic.Pointer[tokens.Store]
	limits   limiterSet
	rp       *httputil.ReverseProxy
	inflight atomic.Int64
	buffered atomic.Int64 // bytes reserved by in-flight request bodies
	unauthS  atomic.Int64 // log sampling for unauthenticated requests
	unauthN  atomic.Int64
	log      *slog.Logger
	accessMu sync.Mutex
}

var (
	errUpstreamTimeout = errors.New("upstream timeout")
	errStreamIdle      = errors.New("upstream stream idle timeout")
)

func New(o Options) (*Proxy, error) {
	if o.Upstream == nil || o.Key == nil {
		return nil, errors.New("proxy: Upstream and Key are required")
	}
	routes, err := ParseRoutes(o.Routes)
	if err != nil {
		return nil, err
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.MaxRequestBytes <= 0 {
		o.MaxRequestBytes = 32 << 20
	}
	if o.RetryBaseWait <= 0 {
		o.RetryBaseWait = 500 * time.Millisecond
	}
	if o.MaxBufferedBytes <= 0 {
		o.MaxBufferedBytes = 1 << 30
	}
	if o.MaxRetryWait <= 0 {
		o.MaxRetryWait = 20 * time.Second
	}
	if o.TrustedProxies == nil {
		o.TrustedProxies = DefaultTrustedProxies
	}
	if o.Transport == nil {
		o.Transport = NewTransport()
	}
	p := &Proxy{opt: o, routes: routes, log: o.Logger}
	p.store.Store(tokens.NewStore(&tokens.File{Version: 1}))
	rt := &retryTransport{base: o.Transport, max: o.MaxRetries, maxWait: o.MaxRetryWait, baseWait: o.RetryBaseWait, capWait: 8 * time.Second}
	if o.Metrics != nil {
		o.Metrics.inflight = p.inflight.Load
		rt.onRetry = func() { o.Metrics.retries.Add(1) }
	}
	p.rp = &httputil.ReverseProxy{
		Rewrite:        p.rewrite,
		Transport:      &credentialTransport{base: rt, p: p},
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.errorHandler,
		BufferPool:     &bufPool{},
		ErrorLog:       slog.NewLogLogger(o.Logger.Handler(), slog.LevelDebug),
	}
	return p, nil
}

// NewTransport returns an http.Transport tuned for many long-lived
// concurrent upstream requests. Compression is disabled so SSE is never
// delayed by gzip framing and bytes pass through untouched.
func NewTransport() *http.Transport {
	return &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DialContext:       (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true,
		// HTTP/2 (api.openai.com) multiplexes; these matter for HTTP/1.1
		// upstreams, where an idle pool smaller than peak concurrency would
		// churn connections under load.
		MaxIdleConns:          4096,
		MaxIdleConnsPerHost:   4096,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
}

// SetStore atomically installs a new token store (hot reload).
func (p *Proxy) SetStore(s *tokens.Store) {
	p.store.Store(s)
	p.limits.prune(s.IDs())
}

// Handler returns the public HTTP handler: /healthz and /v1/*.
func (p *Proxy) Handler() http.Handler {
	// Not http.ServeMux: it answers unclean paths ("/v1//x", "/v1/a/../b")
	// with redirects, which SDKs follow by re-sending the request. Here such
	// paths are simply rejected by matchRoute.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/"):
			p.serveAPI(w, r)
		case r.URL.Path == "/healthz" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Write([]byte(`{"status":"ok"}` + "\n"))
		default:
			writeError(w, http.StatusNotFound, "invalid_request_error", "unknown_url", "Not found.")
		}
	})
}

type ctxKey struct{}

type reqState struct {
	id          string
	start       time.Time
	method      string
	path        string
	client      string
	principal   *tokens.Principal
	clientIP    netip.Addr
	route       string
	model       string
	stream      bool
	status      int
	upstreamSt  int
	upstreamID  string
	upstreamKey string // pinned for search identity, dispatch and response scrubbing
	retries     int
	usage       usage
	ttfb        time.Duration
	latency     time.Duration
	err         string

	clientCtx       context.Context
	ctx             context.Context
	cancel          context.CancelCauseFunc
	upstreamReadErr bool
	bodyReserved    int64
	rc              *http.ResponseController
	disarm          func()
}

func stateFrom(ctx context.Context) *reqState {
	st, _ := ctx.Value(ctxKey{}).(*reqState)
	return st
}

func (p *Proxy) serveAPI(w http.ResponseWriter, r *http.Request) {
	st := &reqState{id: newRequestID(), start: time.Now(), method: r.Method, path: truncate(r.URL.Path, 256), clientCtx: r.Context(), rc: http.NewResponseController(w)}
	w.Header().Set("X-Proxy-Request-Id", st.id)
	st.clientIP = p.clientIP(r)
	defer func() {
		if v := recover(); v != nil {
			// httputil.ReverseProxy panics with http.ErrAbortHandler when a
			// response fails mid-copy; record why, then let net/http abort the
			// connection so the client sees a truncated stream, not a clean EOF.
			// The proxy's own timeout causes are checked first: they also
			// abort the client connection, which then looks like a disconnect.
			switch {
			case st.ctx != nil && errors.Is(context.Cause(st.ctx), errStreamIdle):
				st.err = "upstream_idle_timeout"
			case st.ctx != nil && errors.Is(context.Cause(st.ctx), errUpstreamTimeout):
				st.err = "upstream_timeout"
			case st.clientCtx.Err() != nil:
				st.err = "client_disconnected"
			case st.upstreamReadErr:
				st.err = "upstream_stream_interrupted"
			default:
				st.err = "response_aborted"
			}
			p.record(st)
			panic(v)
		}
		p.record(st)
	}()

	// 1. Authenticate before revealing anything else about the proxy.
	pr, err := p.store.Load().Authenticate(bearerToken(r), st.start)
	if err != nil {
		st.err = err.Error()
		w.Header().Set("WWW-Authenticate", `Bearer realm="oaiproxy"`)
		p.fail(w, st, http.StatusUnauthorized, "invalid_request_error", "invalid_api_key", "Invalid, expired, or revoked proxy token.")
		return
	}
	st.client, st.principal = pr.ID, pr

	// 1b. Tokens with an IP allowlist only work from those addresses.
	if len(pr.AllowedIPs) > 0 && !pr.AllowsIP(st.clientIP) {
		p.fail(w, st, http.StatusForbidden, "invalid_request_error", "ip_not_allowed",
			fmt.Sprintf("This proxy token can't be used from %s. Ask the operator to add this address to its allowlist.", st.clientIP))
		return
	}

	// 2. Only explicitly configured endpoints are forwarded.
	route := matchRoute(p.routes, r.Method, r.URL)
	if route == nil {
		p.fail(w, st, http.StatusNotFound, "invalid_request_error", "unknown_url", fmt.Sprintf("Unsupported endpoint: %s %s", r.Method, st.path))
		return
	}
	st.route = route.Pattern
	if forwardsQuery(r) {
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			p.fail(w, st, http.StatusBadRequest, "invalid_request_error", "invalid_query", "Malformed query parameters.")
			return
		}
		for _, model := range query["model"] {
			if !pr.AllowsModel(model) {
				p.fail(w, st, http.StatusForbidden, "invalid_request_error", "model_not_allowed", "This proxy token is not permitted to use the requested model.")
				return
			}
		}
	}

	// 3. Backpressure: global in-flight cap, then per-client rate and concurrency.
	if n := p.inflight.Add(1); p.opt.MaxInflight > 0 && n > int64(p.opt.MaxInflight) {
		p.inflight.Add(-1)
		w.Header().Set("Retry-After", "1")
		p.fail(w, st, http.StatusServiceUnavailable, "server_error", "proxy_overloaded", "The proxy is at capacity; retry shortly.")
		return
	}
	defer p.inflight.Add(-1)

	lim := p.limits.get(pr)
	if ok, wait := lim.allow(st.start); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
		p.fail(w, st, http.StatusTooManyRequests, "requests", "rate_limit_exceeded", "Proxy rate limit exceeded for this token.")
		return
	}
	release, ok := lim.acquire()
	if !ok {
		w.Header().Set("Retry-After", "1")
		p.fail(w, st, http.StatusTooManyRequests, "requests", "concurrency_limit_exceeded", "Too many concurrent requests for this token.")
		return
	}
	defer release()

	// 4. Body: bounded read, model extraction and enforcement.
	defer func() { p.buffered.Add(-st.bodyReserved) }()
	if !p.prepareBody(w, r, st, pr) {
		return
	}
	if route.Pattern == "GET /v1/models/*" {
		id := r.URL.Path[len("/v1/models/"):]
		st.model = id
		if !pr.AllowsModel(id) {
			p.fail(w, st, http.StatusNotFound, "invalid_request_error", "model_not_found", fmt.Sprintf("The model `%s` does not exist or you do not have access to it.", truncate(id, 128)))
			return
		}
	}

	// 5. Forward.
	ctx := context.WithValue(r.Context(), ctxKey{}, st)
	if p.opt.UpstreamTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeoutCause(ctx, p.opt.UpstreamTimeout, errUpstreamTimeout)
		defer cancel()
	}
	ctx, st.cancel = context.WithCancelCause(ctx)
	defer st.cancel(nil)
	st.ctx = ctx
	defer func() {
		if st.disarm != nil {
			st.disarm()
		}
	}()
	p.rp.ServeHTTP(w, r.WithContext(ctx))
}

// prepareBody reads the request body (bounded), validates it, and enforces
// model restrictions. The body must be buffered to know the model before
// forwarding; this also makes the narrow set of safe retries possible.
func (p *Proxy) prepareBody(w http.ResponseWriter, r *http.Request, st *reqState, pr *tokens.Principal) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		// Bodies on GET/DELETE are dropped so nothing unvetted is forwarded.
		r.Body, r.ContentLength, r.GetBody = http.NoBody, 0, nil
		return true
	}
	cts := r.Header.Values("Content-Type")
	var mt string
	var params map[string]string
	if len(cts) > 1 {
		p.fail(w, st, http.StatusBadRequest, "invalid_request_error", "invalid_content_type", "Multiple Content-Type headers.")
		return false
	} else if len(cts) == 1 {
		var err error
		if mt, params, err = mime.ParseMediaType(cts[0]); err != nil {
			p.fail(w, st, http.StatusBadRequest, "invalid_request_error", "invalid_content_type", "Malformed Content-Type header.")
			return false
		}
	}
	body, status, err := p.readBody(w, r, st)
	if err != nil {
		code := "invalid_request_body"
		switch status {
		case http.StatusRequestEntityTooLarge:
			code = "request_too_large"
		case http.StatusServiceUnavailable:
			code = "proxy_overloaded"
			w.Header().Set("Retry-After", "1")
		}
		p.fail(w, st, status, "invalid_request_error", code, err.Error())
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	if r.URL.Path == "/v1/alpha/search" && mt != "" && mt != "application/json" {
		p.fail(w, st, http.StatusBadRequest, "invalid_request_error", "invalid_content_type", "Standalone search requires a JSON request body.")
		return false
	}
	if len(body) == 0 && r.URL.Path != "/v1/alpha/search" {
		r.Body = http.NoBody
		return true
	}

	var info bodyInfo
	if mt == "multipart/form-data" && (multipartEndpoint(r.URL.Path) || !pr.Restricted()) {
		info, err = inspectMultipart(body, params["boundary"])
	} else if mt == "application/x-www-form-urlencoded" && !pr.Restricted() {
		info, err = inspectForm(body)
	} else if pr.Restricted() {
		// The model check only understands JSON, so restricted tokens may
		// only send JSON, and upstream is told unambiguously that it is JSON.
		if mt != "" && mt != "application/json" {
			p.fail(w, st, http.StatusForbidden, "invalid_request_error", "model_not_allowed", "This proxy token is limited to specific models and only supports JSON request bodies.")
			return false
		}
		r.Header.Set("Content-Type", "application/json")
		info, err = inspectJSON(body)
	} else {
		info, err = inspectJSON(body)
	}
	if err != nil {
		p.fail(w, st, http.StatusBadRequest, "invalid_request_error", "invalid_json", err.Error())
		return false
	}
	st.model, st.stream = truncate(info.model, 128), info.stream
	if pr.Restricted() && !info.hasModel {
		p.fail(w, st, http.StatusBadRequest, "invalid_request_error", "model_required", `This proxy token requires an explicit "model" field.`)
		return false
	}
	if info.hasModel && !pr.AllowsModel(info.model) {
		p.fail(w, st, http.StatusForbidden, "invalid_request_error", "model_not_allowed", fmt.Sprintf("This proxy token is not permitted to use model `%s`.", truncate(info.model, 128)))
		return false
	}
	// Hosted image generation can select its own model. Inspect only direct
	// tool selectors; arbitrary model keys in user content/schema are not policy.
	if info.tools != nil {
		var tools []json.RawMessage
		if err := json.Unmarshal(info.tools, &tools); err != nil {
			p.fail(w, st, http.StatusBadRequest, "invalid_request_error", "invalid_json", "Tools must be an array.")
			return false
		}
		for _, tool := range tools {
			selector, err := inspectJSON(tool)
			if err != nil {
				p.fail(w, st, http.StatusBadRequest, "invalid_request_error", "invalid_json", err.Error())
				return false
			}
			if selector.hasModel && !tokens.ModelEligible(selector.model) {
				p.fail(w, st, http.StatusForbidden, "invalid_request_error", "model_not_allowed", "The requested tool model is excluded by the proxy.")
				return false
			}
		}
	}
	if r.URL.Path == "/v1/alpha/search" {
		if !info.hasModel {
			p.fail(w, st, http.StatusBadRequest, "invalid_request_error", "model_required", "Standalone search requires an explicit model.")
			return false
		}
		st.upstreamKey = p.opt.Key.Get()
		body, err = scopedSearch(body, pr.ID, p.opt.Upstream.String(), p.opt.Organization, p.opt.Project, st.upstreamKey)
		if err != nil {
			p.fail(w, st, http.StatusBadRequest, "invalid_request_error", "invalid_search_request", err.Error())
			return false
		}
		if int64(len(body)) > p.opt.MaxRequestBytes {
			p.fail(w, st, http.StatusRequestEntityTooLarge, "invalid_request_error", "request_too_large", "Scoped search request exceeds the body limit.")
			return false
		}
		delta := int64(len(body)) - st.bodyReserved
		if p.buffered.Add(delta) > p.opt.MaxBufferedBytes {
			p.buffered.Add(-delta)
			p.fail(w, st, http.StatusServiceUnavailable, "server_error", "proxy_overloaded", "The proxy is at capacity; retry shortly.")
			return false
		}
		st.bodyReserved = int64(len(body))
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	return true
}

func multipartEndpoint(path string) bool {
	switch path {
	case "/v1/images/edits", "/v1/audio/transcriptions", "/v1/audio/translations":
		return true
	}
	return false
}

func (p *Proxy) readBody(w http.ResponseWriter, r *http.Request, st *reqState) ([]byte, int, error) {
	limit := p.opt.MaxRequestBytes
	if r.ContentLength > limit {
		return nil, http.StatusRequestEntityTooLarge, fmt.Errorf("request body exceeds %d bytes", limit)
	}
	// Reserve the worst case against the global body budget before reading,
	// so slow or stalled uploads cannot collectively exhaust memory.
	reserve := limit
	if r.ContentLength >= 0 {
		reserve = r.ContentLength
	}
	if p.buffered.Add(reserve) > p.opt.MaxBufferedBytes {
		p.buffered.Add(-reserve)
		return nil, http.StatusServiceUnavailable, errors.New("The proxy is at capacity; retry shortly.")
	}
	st.bodyReserved = reserve
	if p.opt.BodyReadTimeout > 0 {
		rc := http.NewResponseController(w)
		if rc.SetReadDeadline(time.Now().Add(p.opt.BodyReadTimeout)) == nil {
			defer rc.SetReadDeadline(time.Time{})
		}
	}
	var buf bytes.Buffer
	if r.ContentLength > 0 {
		// Bounded: a client must not make us allocate what it only declares.
		buf.Grow(int(min(r.ContentLength, 1<<20)) + 1)
	}
	_, err := buf.ReadFrom(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, http.StatusRequestEntityTooLarge, fmt.Errorf("request body exceeds %d bytes", limit)
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, http.StatusRequestTimeout, errors.New("timed out reading request body")
		}
		return nil, http.StatusBadRequest, errors.New("could not read request body")
	}
	p.buffered.Add(int64(buf.Len()) - reserve)
	st.bodyReserved = int64(buf.Len())
	return buf.Bytes(), 0, nil
}

// forwardedHeaders is the allow-list of client headers sent upstream.
// Everything else (Authorization, Cookie, X-Forwarded-*, OpenAI-Organization,
// OpenAI-Project, Idempotency-Key, ...) is dropped.
var forwardedHeaders = map[string]bool{
	"Accept":              true,
	"Content-Type":        true,
	"User-Agent":          true,
	"Openai-Beta":         true,
	"X-Client-Request-Id": true,
	// Codex carries routing/continuation state across compaction and turns.
	"Session-Id":                             true,
	"Thread-Id":                              true,
	"Session_id":                             true,
	"Originator":                             true,
	"X-Codex-Turn-State":                     true,
	"X-Codex-Turn-Metadata":                  true,
	"X-Codex-Beta-Features":                  true,
	"X-Openai-Internal-Codex-Responses-Lite": true,
	// Anthropic Messages API: API version and opt-in beta features.
	"Anthropic-Version": true,
	"Anthropic-Beta":    true,
}

func forwardsQuery(r *http.Request) bool {
	return r.Method == http.MethodGet || r.Method == http.MethodDelete || strings.HasPrefix(r.URL.Path, "/v1/messages")
}

func (p *Proxy) rewrite(pr *httputil.ProxyRequest) {
	in, u := pr.In, p.opt.Upstream
	pr.Out.URL = &url.URL{
		Scheme: u.Scheme,
		Host:   u.Host,
		Path:   u.Path + strings.TrimPrefix(in.URL.Path, "/v1"),
	}
	if forwardsQuery(in) {
		pr.Out.URL.RawQuery = in.URL.RawQuery // e.g. include[], after, stream; Anthropic's ?beta=true
	}
	pr.Out.Host = ""
	// The body is fully buffered: no chunking, and no client trailers, which
	// would otherwise bypass the header allow-list.
	pr.Out.Trailer, pr.Out.TransferEncoding = nil, nil
	h := make(http.Header, len(forwardedHeaders)+3)
	for k, vv := range in.Header {
		if forwardedHeaders[k] || strings.HasPrefix(k, "X-Stainless-") {
			h[k] = vv
		}
	}
	st := stateFrom(in.Context())
	if st.upstreamKey == "" {
		st.upstreamKey = p.opt.Key.Get()
	}
	h.Set("Authorization", "Bearer "+st.upstreamKey)
	h.Set("Accept-Encoding", "identity")
	if p.opt.Organization != "" {
		h.Set("OpenAI-Organization", p.opt.Organization)
	}
	if p.opt.Project != "" {
		h.Set("OpenAI-Project", p.opt.Project)
	}
	for k, vv := range p.opt.ExtraHeaders {
		h[k] = vv
	}
	pr.Out.Header = h
}

// strippedResponseHeaders reveal provider account details or are irrelevant
// to clients. X-Ratelimit-* headers are also removed: they expose the
// provider's tier and the aggregate usage of every client sharing the key.
var strippedResponseHeaders = []string{"Openai-Organization", "Openai-Project", "Set-Cookie", "Alt-Svc"}

func (p *Proxy) modifyResponse(resp *http.Response) error {
	st := stateFrom(resp.Request.Context())
	st.upstreamSt, st.status = resp.StatusCode, resp.StatusCode
	st.ttfb = time.Since(st.start)
	p.sanitizeHeaders(resp.Header, st)
	p.sanitizeHeaders(resp.Trailer, st)
	if isModelDiscovery(st.route) {
		resp.Header.Set("Cache-Control", "private, no-store")
	}
	st.upstreamID = truncate(resp.Header.Get("X-Request-Id"), 128)
	// Trailers are populated only after the body has been consumed. The wrapper
	// scrubs them again before ReverseProxy copies them to the client.
	resp.Body = &credentialBody{ReadCloser: resp.Body, secret: []byte(st.upstreamKey), sanitize: func() { p.sanitizeHeaders(resp.Trailer, st) }}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		// The transport requests uncompressed bytes. Do not relay a provider
		// encoding that would hide a credential from the streaming filter.
		st.err = "upstream_encoding_unsupported"
		replaceWithError(resp, http.StatusBadGateway, "server_error", st.err, "The upstream provider returned an unsupported content encoding.")
		resp.Header.Del("Content-Encoding")
	}

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		// The client's proxy token was valid; the provider's key was not.
		// Never relay the upstream message (it quotes a masked key).
		st.err = "upstream_auth_failed"
		p.log.Error("upstream rejected provider credentials", "request_id", st.id, "upstream_request_id", st.upstreamID)
		replaceWithError(resp, http.StatusBadGateway, "server_error", "upstream_auth_error", "The proxy could not authenticate with the upstream provider. Contact the proxy operator.")
	case resp.StatusCode == http.StatusForbidden:
		st.err = "upstream_forbidden"
		replaceWithError(resp, http.StatusForbidden, "invalid_request_error", "upstream_forbidden", "The upstream provider refused this request.")
	case resp.StatusCode >= 400:
		p.scrubErrorBody(resp)
	case resp.StatusCode/100 == 2:
		if isModelDiscovery(st.route) {
			// Small responses: buffer, hide disallowed models, and mask
			// account ids in owned_by.
			return p.rewriteModels(resp, st)
		}
		resp.Body = newTap(resp.Body, st, p.opt.StreamIdleTimeout)
		p.armWriteDeadline(st)
	}
	st.status = resp.StatusCode
	return nil
}

// armWriteDeadline makes cancellation (upstream/idle timeout, client gone)
// also unblock a write to a client that has stopped reading; otherwise such
// a client would pin its request slot indefinitely.
func (p *Proxy) armWriteDeadline(st *reqState) {
	done := make(chan struct{})
	stop := context.AfterFunc(st.ctx, func() {
		defer close(done)
		st.rc.SetWriteDeadline(time.Now())
	})
	st.disarm = func() {
		if !stop() {
			<-done
			st.rc.SetWriteDeadline(time.Time{}) // don't poison a reused connection
		}
	}
}

func (p *Proxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	st := stateFrom(r.Context())
	switch cause := context.Cause(r.Context()); {
	case st.clientCtx.Err() != nil:
		st.status, st.err = 499, "client_disconnected" // nobody to respond to
		return
	case errors.Is(cause, errUpstreamTimeout):
		st.err = "upstream_timeout"
		p.fail(w, st, http.StatusGatewayTimeout, "server_error", "upstream_timeout", "The upstream provider did not respond in time.")
	case errors.Is(cause, errStreamIdle):
		st.err = "upstream_idle_timeout"
		p.fail(w, st, http.StatusGatewayTimeout, "server_error", "upstream_timeout", "The upstream provider stopped responding.")
	default:
		code := "upstream_unavailable"
		p.log.Warn("upstream request failed", "request_id", st.id, "error", string(p.scrubFor(st, []byte(err.Error()))))
		st.err = code
		p.fail(w, st, http.StatusBadGateway, "server_error", code, "The upstream provider could not be reached.")
	}
}

const maxErrorBody = 1 << 20

var (
	reSecretKey = regexp.MustCompile(`sk-[A-Za-z0-9_\-*.]{4,}`)
	reOrg       = regexp.MustCompile(`org-[A-Za-z0-9]{6,}`)
	reProject   = regexp.MustCompile(`proj_[A-Za-z0-9]{6,}`)
	reUser      = regexp.MustCompile(`user-[A-Za-z0-9]{6,}`)
)

// scrubErrorBody passes upstream error details through (they matter to SDK
// users) but masks anything resembling provider credentials or account ids.
// Bodies that can't be inspected (compressed, or over 1 MiB) are replaced.
func (p *Proxy) scrubErrorBody(resp *http.Response) {
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && ce != "identity" {
		replaceWithError(resp, resp.StatusCode, "server_error", "upstream_error", http.StatusText(resp.StatusCode))
		return
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody+1))
	resp.Body.Close()
	if err != nil || len(b) > maxErrorBody {
		replaceWithError(resp, resp.StatusCode, "server_error", "upstream_error", http.StatusText(resp.StatusCode))
		return
	}
	// Some relays send JSON errors labelled text/event-stream on streaming
	// requests; label them correctly so SDKs parse the error message.
	if json.Valid(b) {
		resp.Header.Set("Content-Type", "application/json")
	}
	setBody(resp, p.scrubFor(stateFrom(resp.Request.Context()), b))
}

func (p *Proxy) scrub(b []byte) []byte {
	if k := p.opt.Key.Get(); k != "" {
		b = bytes.ReplaceAll(b, []byte(k), []byte("***"))
	}
	b = reSecretKey.ReplaceAll(b, []byte("sk-***"))
	b = reOrg.ReplaceAll(b, []byte("org-***"))
	b = reProject.ReplaceAll(b, []byte("proj_***"))
	return reUser.ReplaceAll(b, []byte("user-***"))
}

func isModelDiscovery(route string) bool {
	return route == "GET /v1/models" || route == "GET /v1/models/*"
}

func (p *Proxy) rewriteModels(resp *http.Response, st *reqState) error {
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	resp.Body.Close()
	if err != nil {
		return err
	}
	if st.route == "GET /v1/models" {
		if b, err = filterModels(b, st.principal); err != nil {
			return err
		}
	} else {
		var model struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(b, &model); err != nil {
			return fmt.Errorf("decode model detail: %w", err)
		}
		if !st.principal.AllowsModel(model.ID) {
			st.err, st.status = "model_not_found", http.StatusNotFound
			replaceWithError(resp, http.StatusNotFound, "invalid_request_error", "model_not_found", "The requested model is excluded by the proxy.")
			return nil
		}
	}
	setBody(resp, p.scrubFor(st, b))
	return nil
}

// filterModels applies global exclusions and the client's model allowlist.
func filterModels(b []byte, pr *tokens.Principal) ([]byte, error) {
	var doc map[string]json.RawMessage
	var data []json.RawMessage
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("decode model list: %w", err)
	}
	if err := json.Unmarshal(doc["data"], &data); err != nil {
		return nil, fmt.Errorf("decode model list: %w", err)
	}
	kept := make([]json.RawMessage, 0, len(data))
	for _, m := range data {
		var id struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(m, &id) == nil && pr.AllowsModel(id.ID) {
			kept = append(kept, m)
		}
	}
	doc["data"], _ = json.Marshal(kept)
	return json.Marshal(doc)
}

func replaceWithError(resp *http.Response, status int, typ, code, msg string) {
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
	resp.Body.Close()
	resp.StatusCode = status
	resp.Status = fmt.Sprintf("%d %s", status, http.StatusText(status))
	resp.Header.Set("Content-Type", "application/json")
	setBody(resp, errorJSON(typ, code, msg))
}

func setBody(resp *http.Response, b []byte) {
	resp.Body = io.NopCloser(bytes.NewReader(b))
	resp.ContentLength = int64(len(b))
	resp.TransferEncoding = nil
	resp.Header.Del("Content-Encoding")
	resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
}

func (p *Proxy) fail(w http.ResponseWriter, st *reqState, status int, typ, code, msg string) {
	st.status = status
	if st.err == "" {
		st.err = code
	}
	writeError(w, status, typ, code, msg)
}

type apiError struct {
	Error struct {
		Message string  `json:"message"`
		Type    string  `json:"type"`
		Param   *string `json:"param"`
		Code    string  `json:"code"`
	} `json:"error"`
}

func errorJSON(typ, code, msg string) []byte {
	var e apiError
	e.Error.Message, e.Error.Type, e.Error.Code = msg, typ, code
	b, _ := json.Marshal(e)
	return append(b, '\n')
}

func writeError(w http.ResponseWriter, status int, typ, code, msg string) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	w.Write(errorJSON(typ, code, msg))
}

// DefaultTrustedProxies covers where Caddy runs: the same host (loopback,
// host networking) or a Docker network (private ranges). The proxy port
// itself must not be reachable from the internet.
var DefaultTrustedProxies = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fc00::/7"),
}

// clientIP is the address the request came from. Behind a trusted proxy it
// is the last X-Forwarded-For entry: the one that proxy appended itself, so
// anything a client puts in the header is ignored.
func (p *Proxy) clientIP(r *http.Request) netip.Addr {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	ip := peer.Addr().Unmap()
	if !p.trusted(ip) {
		return ip
	}
	xff := r.Header.Values("X-Forwarded-For")
	if len(xff) == 0 {
		return ip
	}
	last := xff[len(xff)-1]
	if i := strings.LastIndexByte(last, ','); i >= 0 {
		last = last[i+1:]
	}
	if fwd, err := netip.ParseAddr(strings.TrimSpace(last)); err == nil {
		return fwd.Unmap()
	}
	return ip
}

func (p *Proxy) trusted(ip netip.Addr) bool {
	for _, pfx := range p.opt.TrustedProxies {
		if pfx.Contains(ip) {
			return true
		}
	}
	return false
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

// bearerToken is the client's proxy token: "Authorization: Bearer" (OpenAI
// clients) or "x-api-key" (Anthropic clients such as Claude Code).
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return strings.TrimSpace(r.Header.Get("X-Api-Key"))
}

func newRequestID() string {
	var b [12]byte
	rand.Read(b[:])
	return "px_" + hex.EncodeToString(b[:])
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

type bufPool struct{ p sync.Pool }

func (b *bufPool) Get() []byte {
	if v, ok := b.p.Get().(*[]byte); ok {
		return *v
	}
	return make([]byte, 32<<10)
}

func (b *bufPool) Put(buf []byte) { b.p.Put(&buf) }

// record emits the access log line and metrics. It never logs headers,
// tokens, prompts or completions.
type accessRecord struct {
	Time              string  `json:"ts"`
	RequestID         string  `json:"request_id"`
	UpstreamRequestID string  `json:"upstream_request_id,omitempty"`
	Client            string  `json:"client"`
	ClientIP          string  `json:"client_ip,omitempty"`
	Method            string  `json:"method"`
	Endpoint          string  `json:"endpoint,omitempty"`
	Path              string  `json:"path"`
	Model             string  `json:"model,omitempty"`
	Stream            bool    `json:"stream"`
	Status            int     `json:"status"`
	UpstreamStatus    int     `json:"upstream_status,omitempty"`
	LatencyMS         float64 `json:"latency_ms"`
	TTFBMS            float64 `json:"ttfb_ms,omitempty"`
	Retries           int     `json:"retries"`
	InputTokens       int64   `json:"input_tokens,omitempty"`
	OutputTokens      int64   `json:"output_tokens,omitempty"`
	ReasoningTokens   int64   `json:"reasoning_tokens,omitempty"`
	CachedTokens      int64   `json:"cached_tokens,omitempty"`
	TotalTokens       int64   `json:"total_tokens,omitempty"`
	Error             string  `json:"error,omitempty"`
}

func (p *Proxy) record(st *reqState) {
	st.latency = time.Since(st.start)
	if p.opt.Metrics != nil {
		p.opt.Metrics.observe(st)
	}
	rec := accessRecord{
		Time: st.start.UTC().Format(time.RFC3339Nano), RequestID: st.id, UpstreamRequestID: st.upstreamID,
		Client: orDash(st.client), ClientIP: addrString(st.clientIP), Method: st.method, Endpoint: st.route, Path: st.path, Model: st.model,
		Stream: st.stream, Status: st.status, UpstreamStatus: st.upstreamSt,
		LatencyMS: ms(st.latency), TTFBMS: ms(st.ttfb), Retries: st.retries,
		InputTokens: st.usage.Input, OutputTokens: st.usage.Output, ReasoningTokens: st.usage.Reasoning,
		CachedTokens: st.usage.Cached, TotalTokens: st.usage.Total, Error: st.err,
	}
	level := slog.LevelInfo
	// Unknown routes are warnings so agents asking for endpoints the
	// gateway doesn't forward stand out: grep for "unknown_url".
	if st.status >= 500 || (st.err != "" && st.status < 400) || st.err == "unknown_url" {
		level = slog.LevelWarn
	}
	if st.client == "" && !p.sampleUnauthenticated(st.start) {
		return // still counted in metrics; caps log volume from unauthenticated floods
	}
	if p.log.Enabled(context.Background(), level) {
		attrs := []slog.Attr{
			slog.String("request_id", rec.RequestID), slog.String("client", rec.Client),
			slog.String("method", rec.Method), slog.String("endpoint", rec.Endpoint), slog.String("path", rec.Path),
			slog.String("model", rec.Model), slog.Bool("stream", rec.Stream), slog.Int("status", rec.Status),
			slog.Float64("latency_ms", rec.LatencyMS), slog.Int("retries", rec.Retries),
		}
		if rec.ClientIP != "" {
			attrs = append(attrs, slog.String("client_ip", rec.ClientIP))
		}
		if rec.UpstreamStatus != 0 {
			attrs = append(attrs, slog.Int("upstream_status", rec.UpstreamStatus))
		}
		if rec.UpstreamRequestID != "" {
			attrs = append(attrs, slog.String("upstream_request_id", rec.UpstreamRequestID))
		}
		if rec.TTFBMS > 0 {
			attrs = append(attrs, slog.Float64("ttfb_ms", rec.TTFBMS))
		}
		if rec.TotalTokens > 0 {
			attrs = append(attrs, slog.Int64("input_tokens", rec.InputTokens), slog.Int64("output_tokens", rec.OutputTokens),
				slog.Int64("reasoning_tokens", rec.ReasoningTokens), slog.Int64("cached_tokens", rec.CachedTokens), slog.Int64("total_tokens", rec.TotalTokens))
		}
		if rec.Error != "" {
			attrs = append(attrs, slog.String("error", rec.Error))
		}
		p.log.LogAttrs(context.Background(), level, "request", attrs...)
	}
	if p.opt.AccessLog != nil {
		b, _ := json.Marshal(rec)
		p.accessMu.Lock()
		p.opt.AccessLog.Write(append(b, '\n'))
		p.accessMu.Unlock()
	}
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// sampleUnauthenticated allows at most 20 log records per second for
// requests that failed authentication.
func (p *Proxy) sampleUnauthenticated(now time.Time) bool {
	sec := now.Unix()
	if old := p.unauthS.Load(); old != sec && p.unauthS.CompareAndSwap(old, sec) {
		p.unauthN.Store(0)
	}
	return p.unauthN.Add(1) <= 20
}
