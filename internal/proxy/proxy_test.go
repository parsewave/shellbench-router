package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"oaiproxy/internal/config"
	"oaiproxy/internal/mockupstream"
	"oaiproxy/internal/tokens"
)

const upstreamKey = "sk-upstream-REALKEY-0123456789abcdef"

type staticKey string

func (k staticKey) Get() string { return string(k) }

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type testEnv struct {
	t            *testing.T
	srv          *httptest.Server
	p            *Proxy
	opt          Options
	logs, access *syncBuf
	tok          map[string]string
}

func newEnv(t *testing.T, upstream http.Handler, mutate func(*Options)) *testEnv {
	t.Helper()
	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)
	u, _ := url.Parse(up.URL + "/v1")
	e := &testEnv{t: t, logs: &syncBuf{}, access: &syncBuf{}, tok: map[string]string{}}
	o := Options{
		Upstream: u, Key: staticKey(upstreamKey), Routes: config.DefaultRoutes,
		MaxRetries: 2, RetryBaseWait: time.Millisecond, MaxRetryWait: time.Second,
		BodyReadTimeout: 5 * time.Second,
		Logger:          slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		AccessLog:       e.access, Metrics: NewMetrics(),
	}
	if mutate != nil {
		mutate(&o)
	}
	p, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	past := now.Add(-time.Hour)
	f := &tokens.File{Version: 1}
	for _, c := range []tokens.Client{
		{ID: "alice", Models: []string{"gpt-4o", "gpt-4o-2024-*"}},
		{ID: "bob", Models: []string{"gpt-4o-mini"}},
		{ID: "carol"},
		{ID: "dave", Disabled: true},
		{ID: "erin", ExpiresAt: &past},
		{ID: "frank", RPM: 60, Burst: 2},
		{ID: "gina", MaxConcurrent: 2},
	} {
		tok, err := f.Add(c, now)
		if err != nil {
			t.Fatal(err)
		}
		e.tok[c.ID] = tok
	}
	p.SetStore(tokens.NewStore(f))
	e.p, e.opt = p, o
	e.srv = httptest.NewServer(p.Handler())
	t.Cleanup(e.srv.Close)
	return e
}

func (e *testEnv) req(ctx context.Context, method, path, token, body string, hdr ...string) *http.Request {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r, err := http.NewRequestWithContext(ctx, method, e.srv.URL+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	return r
}

func (e *testEnv) do(method, path, token, body string, hdr ...string) (*http.Response, []byte) {
	e.t.Helper()
	resp, err := noRedirect.Do(e.req(context.Background(), method, path, token, body, hdr...))
	if err != nil {
		e.t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, b
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func errCode(t *testing.T, b []byte) string {
	t.Helper()
	var e apiError
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("not an OpenAI error body: %q", b)
	}
	return e.Error.Code
}

// waitFor polls until cond is true; access-log lines are written after the
// handler returns, which can be just after the client sees the response.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func chat(model string) string {
	return fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hi"}]}`, model)
}

func mock() *mockupstream.Server { return &mockupstream.Server{Key: upstreamKey} }

// 1, 2: authentication.
func TestAuthentication(t *testing.T) {
	m := mock()
	e := newEnv(t, m, nil)
	resp, body := e.do("POST", "/v1/chat/completions", e.tok["carol"], chat("gpt-4o"))
	if resp.StatusCode != 200 {
		t.Fatalf("valid token: got %d %s", resp.StatusCode, body)
	}
	for name, tok := range map[string]string{
		"missing": "", "garbage": "sk-px-not-a-real-token", "revoked": e.tok["dave"], "expired": e.tok["erin"],
		"upstream key itself": upstreamKey,
	} {
		resp, body := e.do("POST", "/v1/chat/completions", tok, chat("gpt-4o"))
		if resp.StatusCode != 401 || errCode(t, body) != "invalid_api_key" || resp.Header.Get("WWW-Authenticate") == "" {
			t.Errorf("%s: got %d %s", name, resp.StatusCode, body)
		}
	}
	// Wrong scheme.
	resp, _ = e.do("POST", "/v1/chat/completions", "", chat("gpt-4o"), "Authorization", "Basic "+e.tok["carol"])
	if resp.StatusCode != 401 {
		t.Errorf("basic auth: got %d", resp.StatusCode)
	}
	if got := m.Requests.Load(); got != 1 {
		t.Errorf("upstream saw %d requests, want only the authenticated one", got)
	}
}

// 3, 4: per-client model access, including parser-differential bypass attempts.
func TestModelAccess(t *testing.T) {
	m := mock()
	e := newEnv(t, m, nil)
	cases := []struct {
		client, body string
		want         int
		code         string
	}{
		{"alice", chat("gpt-4o"), 200, ""},
		{"alice", chat("gpt-4o-2024-08-06"), 200, ""},
		{"alice", chat("gpt-4o-mini"), 403, "model_not_allowed"},
		{"alice", chat("o3"), 403, "model_not_allowed"},
		{"bob", chat("gpt-4o-mini"), 200, ""},
		{"bob", chat("gpt-4o"), 403, "model_not_allowed"},
		{"carol", chat("o3"), 200, ""},
		// Bypass attempts.
		{"alice", `{"model":"gpt-4o","model":"o3","messages":[]}`, 400, "invalid_json"},
		{"alice", `{"mod\u0065l":"o3","messages":[]}`, 403, "model_not_allowed"},
		{"alice", `{"MODEL":"gpt-4o","model":"o3"}`, 403, "model_not_allowed"},
		{"alice", `{"model":"o3","Model":"gpt-4o"}`, 403, "model_not_allowed"},
		{"alice", `{"meta":{"model":"gpt-4o"},"model":"o3"}`, 403, "model_not_allowed"},
		{"alice", `{"model":["gpt-4o"]}`, 400, "invalid_json"},
		{"alice", `{"messages":[]}`, 400, "model_required"},
		{"alice", `{"model":"gpt-4o"`, 400, "invalid_json"},
		{"alice", `[{"model":"gpt-4o"}]`, 400, "invalid_json"},
	}
	for _, c := range cases {
		before := m.Requests.Load()
		resp, body := e.do("POST", "/v1/chat/completions", e.tok[c.client], c.body)
		if resp.StatusCode != c.want {
			t.Errorf("%s %s: got %d %s, want %d", c.client, c.body, resp.StatusCode, body, c.want)
			continue
		}
		if c.code != "" {
			if got := errCode(t, body); got != c.code {
				t.Errorf("%s %s: code %q, want %q", c.client, c.body, got, c.code)
			}
			if m.Requests.Load() != before {
				t.Errorf("%s %s: rejected request reached upstream", c.client, c.body)
			}
		}
	}
	// Restricted tokens can't send non-JSON bodies the proxy cannot inspect.
	resp, _ := e.do("POST", "/v1/embeddings", e.tok["alice"], "", "Content-Type", "multipart/form-data; boundary=x")
	if resp.StatusCode == 200 {
		t.Errorf("multipart without body should not succeed")
	}
	req := e.req(context.Background(), "POST", "/v1/chat/completions", e.tok["alice"], "--x\r\n")
	req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	r2, _ := http.DefaultClient.Do(req)
	r2.Body.Close()
	if r2.StatusCode != 403 {
		t.Errorf("multipart for restricted token: got %d, want 403", r2.StatusCode)
	}
}

func TestModelsListFiltered(t *testing.T) {
	e := newEnv(t, mock(), nil)
	ids := func(client string) []string {
		resp, body := e.do("GET", "/v1/models", e.tok[client], "")
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", client, resp.StatusCode, body)
		}
		var l struct {
			Object string
			Data   []struct{ ID string }
		}
		json.Unmarshal(body, &l)
		if l.Object != "list" {
			t.Fatalf("object = %q", l.Object)
		}
		var out []string
		for _, d := range l.Data {
			out = append(out, d.ID)
		}
		return out
	}
	if got := strings.Join(ids("alice"), ","); got != "gpt-4o" {
		t.Errorf("alice models = %s", got)
	}
	if got := len(ids("carol")); got != 4 {
		t.Errorf("carol sees %d models, want 4", got)
	}
	if resp, _ := e.do("GET", "/v1/models/o3", e.tok["alice"], ""); resp.StatusCode != 404 {
		t.Errorf("alice GET o3: %d", resp.StatusCode)
	}
	if resp, _ := e.do("GET", "/v1/models/gpt-4o", e.tok["alice"], ""); resp.StatusCode != 200 {
		t.Errorf("alice GET gpt-4o: %d", resp.StatusCode)
	}
}

func TestOnlyConfiguredRoutes(t *testing.T) {
	m := mock()
	e := newEnv(t, m, nil)
	for _, c := range []struct{ method, path string }{
		{"GET", "/v1/files"},
		{"POST", "/v1/fine_tuning/jobs"},
		{"DELETE", "/v1/chat/completions"},
		{"POST", "/v1/chat/completions/extra"},
		{"GET", "/v1/models/a%2Fb"},
		{"POST", "/v1//chat/completions"},
		{"GET", "/v1/../admin"},
		{"GET", "/v1/models/.."},
		{"GET", "/admin"},
	} {
		resp, _ := e.do(c.method, c.path, e.tok["carol"], "")
		if resp.StatusCode != 404 {
			t.Errorf("%s %s: got %d, want 404", c.method, c.path, resp.StatusCode)
		}
	}
	if n := m.Requests.Load(); n != 0 {
		t.Errorf("upstream received %d requests for unconfigured routes", n)
	}
	// Unauthenticated callers learn nothing about routing.
	if resp, _ := e.do("GET", "/v1/files", "", ""); resp.StatusCode != 401 {
		t.Errorf("unauthenticated unknown route: %d", resp.StatusCode)
	}
}

// 5: the provider key never reaches clients, and client credentials never reach upstream.
func TestCredentialIsolation(t *testing.T) {
	var got http.Header
	var mu sync.Mutex
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Clone()
		mu.Unlock()
		w.Header().Set("Openai-Organization", "org-providerSecret123")
		w.Header().Set("Openai-Project", "proj_providerSecret123")
		w.Header().Set("Set-Cookie", "__cf_bm=abc")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("case") {
		case "401":
			w.WriteHeader(401)
			fmt.Fprintf(w, `{"error":{"message":"Incorrect API key provided: %s","code":"invalid_api_key"}}`, upstreamKey)
		case "400":
			w.WriteHeader(400)
			fmt.Fprintf(w, `{"error":{"message":"key %s / sk-proj-****abcd in org-AbCdEf123456 proj_AbCdEf123456 rejected","code":"bad"}}`, upstreamKey)
		default:
			w.Write([]byte(`{"ok":true}`))
		}
	}), func(o *Options) { o.Organization = "org-provider"; o.Routes = append(o.Routes, "GET /v1/probe") })

	resp, body := e.do("GET", "/v1/probe", e.tok["carol"], "",
		"OpenAI-Organization", "org-evil", "OpenAI-Project", "proj_evil", "Cookie", "session=1",
		"X-Forwarded-For", "10.0.0.1", "Idempotency-Key", "abc", "X-Stainless-Lang", "python", "OpenAI-Beta", "assistants=v2", "Api-Key", "x")
	if resp.StatusCode != 200 {
		t.Fatalf("probe: %d %s", resp.StatusCode, body)
	}
	mu.Lock()
	if got.Get("Authorization") != "Bearer "+upstreamKey {
		t.Errorf("upstream Authorization = %q", got.Get("Authorization"))
	}
	if strings.Contains(fmt.Sprint(got), e.tok["carol"]) {
		t.Error("client proxy token was forwarded upstream")
	}
	if got.Get("Openai-Organization") != "org-provider" || got.Get("Openai-Project") != "" {
		t.Errorf("client could override org/project: %v", got)
	}
	for _, h := range []string{"Cookie", "X-Forwarded-For", "Idempotency-Key", "Api-Key"} {
		if got.Get(h) != "" {
			t.Errorf("header %s was forwarded", h)
		}
	}
	if got.Get("X-Stainless-Lang") != "python" || got.Get("Openai-Beta") != "assistants=v2" {
		t.Errorf("SDK headers not forwarded: %v", got)
	}
	mu.Unlock()
	for _, h := range []string{"Openai-Organization", "Openai-Project", "Set-Cookie"} {
		if resp.Header.Get(h) != "" {
			t.Errorf("response header %s leaked", h)
		}
	}

	resp, body = e.do("GET", "/v1/probe?case=401", e.tok["carol"], "")
	if resp.StatusCode != 502 || errCode(t, body) != "upstream_auth_error" {
		t.Errorf("upstream 401: got %d %s", resp.StatusCode, body)
	}
	resp400, body400 := e.do("GET", "/v1/probe?case=400", e.tok["carol"], "")
	if resp400.StatusCode != 400 {
		t.Errorf("upstream 400 status changed: %d", resp400.StatusCode)
	}
	for _, b := range [][]byte{body, body400} {
		for _, secret := range []string{upstreamKey, "sk-up", "sk-proj-", "org-AbCdEf123456", "proj_AbCdEf123456"} {
			if bytes.Contains(b, []byte(secret)) {
				t.Errorf("client response contains %q: %s", secret, b)
			}
		}
	}
	if !bytes.Contains(body400, []byte("rejected")) {
		t.Errorf("useful upstream error detail was lost: %s", body400)
	}
}

// 6: regular responses pass through byte-for-byte, as do request bodies.
func TestPassthrough(t *testing.T) {
	upBody := []byte(`{"id":"chatcmpl-1",  "object":"chat.completion","choices":[{"message":{"content":"hé \u00e9"}}],"usage":{"prompt_tokens":5,"completion_tokens":7,"total_tokens":12}}`)
	var gotBody []byte
	var gotQuery string
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req_abc")
		w.Header().Set("X-Ratelimit-Remaining-Requests", "99")
		w.Write(upBody)
	}), nil)
	reqBody := `{"model":"gpt-4o","messages":[{"role":"user","content":[{"type":"text","text":"x"},{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}]}],` +
		`"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object"}}}],"tool_choice":"auto",` +
		`"response_format":{"type":"json_schema","json_schema":{"name":"s","schema":{"type":"object"},"strict":true}},"reasoning_effort":"high","temperature":0.2,"unknown_future_param":[1,{"a":null}]}`
	resp, body := e.do("POST", "/v1/chat/completions", e.tok["alice"], reqBody)
	if resp.StatusCode != 200 || !bytes.Equal(body, upBody) {
		t.Fatalf("response not passed through: %d %s", resp.StatusCode, body)
	}
	if string(gotBody) != reqBody {
		t.Errorf("request body modified:\n got %s\nwant %s", gotBody, reqBody)
	}
	if resp.Header.Get("X-Request-Id") != "req_abc" || resp.Header.Get("X-Ratelimit-Remaining-Requests") != "" || resp.Header.Get("X-Proxy-Request-Id") == "" {
		t.Errorf("headers: %v", resp.Header)
	}
	e.do("GET", "/v1/responses/resp_123?include[]=reasoning.encrypted_content&stream=false", e.tok["carol"], "")
	if gotQuery != "include[]=reasoning.encrypted_content&stream=false" {
		t.Errorf("query = %q", gotQuery)
	}
	waitFor(t, "usage in access log", func() bool { return strings.Contains(e.access.String(), `"total_tokens":12`) })
}

// 7: SSE is forwarded incrementally, not buffered.
func TestSSEIncremental(t *testing.T) {
	release := make(chan struct{})
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fmt.Fprint(w, "data: {\"n\":1}\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		fmt.Fprint(w, "data: {\"n\":2,\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4,\"total_tokens\":7}}\n\ndata: [DONE]\n\n")
	}), nil)
	resp, err := http.DefaultClient.Do(e.req(context.Background(), "POST", "/v1/chat/completions", e.tok["alice"], `{"model":"gpt-4o","stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type %q", ct)
	}
	br := bufio.NewReader(resp.Body)
	first := make(chan string, 1)
	go func() { l, _ := br.ReadString('\n'); first <- l }()
	select {
	case l := <-first:
		if l != "data: {\"n\":1}\n" {
			t.Fatalf("first line %q", l)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first SSE event was buffered: not received while upstream was still streaming")
	}
	close(release)
	rest, _ := io.ReadAll(br)
	if !strings.HasSuffix(string(rest), "data: [DONE]\n\n") {
		t.Fatalf("stream tail %q", rest)
	}
	waitFor(t, "stream usage", func() bool {
		s := e.access.String()
		return strings.Contains(s, `"stream":true`) && strings.Contains(s, `"total_tokens":7`)
	})
}

func TestMockStreamingShapes(t *testing.T) {
	e := newEnv(t, mock(), nil)
	for _, c := range []struct{ path, body, want string }{
		{"/v1/chat/completions", `{"model":"gpt-4o","stream":true,"stream_options":{"include_usage":true}}`, "data: [DONE]"},
		{"/v1/responses", `{"model":"gpt-4o","stream":true,"input":"hi"}`, "event: response.completed"},
	} {
		resp, body := e.do("POST", c.path, e.tok["alice"], c.body)
		if resp.StatusCode != 200 || !strings.Contains(string(body), c.want) {
			t.Errorf("%s: %d %s", c.path, resp.StatusCode, body)
		}
	}
	waitFor(t, "responses usage", func() bool { return strings.Contains(e.access.String(), `"reasoning_tokens":3`) })
}

// 8: concurrent requests.
func TestConcurrentRequests(t *testing.T) {
	m := &mockupstream.Server{Key: upstreamKey, Latency: 10 * time.Millisecond}
	e := newEnv(t, m, nil)
	const n = 300
	var wg sync.WaitGroup
	var fails atomic.Int32
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: n}}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			stream := i%2 == 0
			resp, err := client.Do(e.req(context.Background(), "POST", "/v1/chat/completions", e.tok["carol"], fmt.Sprintf(`{"model":"gpt-4o","stream":%v}`, stream)))
			if err != nil {
				fails.Add(1)
				return
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || (stream && !bytes.Contains(b, []byte("[DONE]"))) {
				fails.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if fails.Load() != 0 || m.Requests.Load() != n {
		t.Fatalf("fails=%d upstream=%d", fails.Load(), m.Requests.Load())
	}
	waitFor(t, "inflight drained", func() bool { return e.p.inflight.Load() == 0 })
}

func TestPerClientLimits(t *testing.T) {
	release := make(chan struct{})
	var inflight atomic.Int32
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inflight.Add(1)
		defer inflight.Add(-1)
		if r.URL.Query().Get("block") != "" {
			<-release
		}
		w.Write([]byte(`{}`))
	}), func(o *Options) { o.Routes = append(o.Routes, "GET /v1/probe") })

	// Rate: frank has burst 2.
	for i := 0; i < 2; i++ {
		if resp, _ := e.do("GET", "/v1/probe", e.tok["frank"], ""); resp.StatusCode != 200 {
			t.Fatalf("frank request %d: %d", i, resp.StatusCode)
		}
	}
	resp, body := e.do("GET", "/v1/probe", e.tok["frank"], "")
	if resp.StatusCode != 429 || errCode(t, body) != "rate_limit_exceeded" || resp.Header.Get("Retry-After") == "" {
		t.Errorf("frank 3rd: %d %s", resp.StatusCode, body)
	}
	// Other clients are unaffected.
	if resp, _ := e.do("GET", "/v1/probe", e.tok["carol"], ""); resp.StatusCode != 200 {
		t.Errorf("carol affected by frank's limit: %d", resp.StatusCode)
	}

	// Concurrency: gina allows 2 in flight.
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); e.do("GET", "/v1/probe?block=1", e.tok["gina"], "") }()
	}
	waitFor(t, "2 blocked requests", func() bool { return inflight.Load() == 2 })
	resp, body = e.do("GET", "/v1/probe", e.tok["gina"], "")
	if resp.StatusCode != 429 || errCode(t, body) != "concurrency_limit_exceeded" {
		t.Errorf("gina 3rd concurrent: %d %s", resp.StatusCode, body)
	}
	close(release)
	wg.Wait()
	if resp, _ := e.do("GET", "/v1/probe", e.tok["gina"], ""); resp.StatusCode != 200 {
		t.Errorf("gina after release: %d", resp.StatusCode)
	}
}

func TestGlobalInflightCap(t *testing.T) {
	release := make(chan struct{})
	var inflight atomic.Int32
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inflight.Add(1)
		<-release
	}), func(o *Options) { o.MaxInflight = 1; o.Routes = append(o.Routes, "GET /v1/probe") })
	go e.do("GET", "/v1/probe", e.tok["carol"], "")
	waitFor(t, "blocked request", func() bool { return inflight.Load() == 1 })
	resp, body := e.do("GET", "/v1/probe", e.tok["bob"], "")
	close(release)
	if resp.StatusCode != 503 || errCode(t, body) != "proxy_overloaded" {
		t.Errorf("got %d %s", resp.StatusCode, body)
	}
}

func TestRequestTooLarge(t *testing.T) {
	m := mock()
	e := newEnv(t, m, func(o *Options) { o.MaxRequestBytes = 1024 })
	resp, body := e.do("POST", "/v1/chat/completions", e.tok["carol"], `{"model":"gpt-4o","x":"`+strings.Repeat("a", 2048)+`"}`)
	if resp.StatusCode != 413 || errCode(t, body) != "request_too_large" || m.Requests.Load() != 0 {
		t.Errorf("got %d %s", resp.StatusCode, body)
	}
}

// 9: cancellation and timeouts.
func TestClientCancellationPropagates(t *testing.T) {
	upDone := make(chan struct{}, 2)
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, _ := io.ReadAll(r.Body); bytes.Contains(b, []byte(`"stream":true`)) {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {}\n\n")
			w.(http.Flusher).Flush()
		}
		<-r.Context().Done()
		upDone <- struct{}{}
	}), func(o *Options) { o.Routes = append(o.Routes, "POST /v1/probe") })

	// Mid-stream disconnect.
	ctx, cancel := context.WithCancel(context.Background())
	resp, err := http.DefaultClient.Do(e.req(ctx, "POST", "/v1/probe", e.tok["carol"], `{"model":"gpt-4o","stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	bufio.NewReader(resp.Body).ReadString('\n')
	cancel()
	resp.Body.Close()
	select {
	case <-upDone:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream request was not cancelled after client disconnect mid-stream")
	}

	// Disconnect while waiting for headers (long reasoning request).
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := http.DefaultClient.Do(e.req(ctx, "POST", "/v1/probe", e.tok["carol"], `{"model":"o3"}`)); err == nil {
		t.Fatal("expected client timeout")
	}
	select {
	case <-upDone:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream request was not cancelled after client gave up")
	}
	waitFor(t, "disconnect logged", func() bool { return strings.Count(e.access.String(), "client_disconnected") == 2 })
}

func TestUpstreamTimeout(t *testing.T) {
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		<-r.Context().Done()
	}), func(o *Options) { o.UpstreamTimeout = 150 * time.Millisecond })
	start := time.Now()
	resp, body := e.do("POST", "/v1/chat/completions", e.tok["carol"], chat("o3"))
	if resp.StatusCode != 504 || errCode(t, body) != "upstream_timeout" || time.Since(start) > 2*time.Second {
		t.Errorf("got %d %s after %s", resp.StatusCode, body, time.Since(start))
	}
}

func TestStreamIdleTimeout(t *testing.T) {
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"n\":1}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}), func(o *Options) { o.StreamIdleTimeout = 150 * time.Millisecond })
	resp, err := http.DefaultClient.Do(e.req(context.Background(), "POST", "/v1/chat/completions", e.tok["carol"], `{"model":"gpt-4o","stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := io.ReadAll(resp.Body); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("idle stream ended with a clean EOF; client cannot tell it was truncated")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("idle stream was not terminated")
	}
	waitFor(t, "idle timeout logged", func() bool { return strings.Contains(e.access.String(), "upstream_idle_timeout") })
}

// 10: retries never duplicate potentially billable work.
func TestRetryPolicy(t *testing.T) {
	type step struct {
		status int
		header map[string]string
		body   string
	}
	run := func(t *testing.T, method, body string, steps []step) (int, int64, []byte) {
		var n atomic.Int64
		e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			i := int(n.Add(1)) - 1
			s := steps[min(i, len(steps)-1)]
			for k, v := range s.header {
				w.Header().Set(k, v)
			}
			w.WriteHeader(s.status)
			fmt.Fprint(w, s.body)
		}), func(o *Options) { o.Routes = append(o.Routes, "GET /v1/probe", "POST /v1/probe") })
		resp, b := e.do(method, "/v1/probe", e.tok["carol"], body)
		return resp.StatusCode, n.Load(), b
	}
	ok := step{status: 200, body: `{"ok":true}`}
	tests := []struct {
		name       string
		method     string
		steps      []step
		wantStatus int
		wantCalls  int64
	}{
		{"POST 500 is not replayed", "POST", []step{{status: 500}, ok}, 500, 1},
		{"POST 502 is not replayed", "POST", []step{{status: 502}, ok}, 502, 1},
		{"POST 503 is not replayed", "POST", []step{{status: 503, header: map[string]string{"Retry-After": "0"}}, ok}, 503, 1},
		{"POST 429 is retried", "POST", []step{{status: 429, header: map[string]string{"Retry-After": "0"}, body: `{"error":{"code":"rate_limit_exceeded"}}`}, ok}, 200, 2},
		{"POST 429 retry-after-ms", "POST", []step{{status: 429, header: map[string]string{"Retry-After-Ms": "5"}}, ok}, 200, 2},
		{"429 insufficient_quota not retried", "POST", []step{{status: 429, body: `{"error":{"type":"insufficient_quota","code":"insufficient_quota"}}`}, ok}, 429, 1},
		{"429 Retry-After beyond max wait not retried", "POST", []step{{status: 429, header: map[string]string{"Retry-After": "3600"}}, ok}, 429, 1},
		{"429 retries capped at MAX_RETRIES", "POST", []step{{status: 429, header: map[string]string{"Retry-After": "0"}}}, 429, 3},
		{"GET 503 is retried", "GET", []step{{status: 503}, ok}, 200, 2},
		{"GET 500 retries capped", "GET", []step{{status: 500}}, 500, 3},
		{"400 never retried", "POST", []step{{status: 400}, ok}, 400, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := ""
			if tc.method == "POST" {
				body = chat("gpt-4o")
			}
			status, calls, b := run(t, tc.method, body, tc.steps)
			if status != tc.wantStatus || calls != tc.wantCalls {
				t.Errorf("status=%d calls=%d body=%s; want status=%d calls=%d", status, calls, b, tc.wantStatus, tc.wantCalls)
			}
		})
	}
}

// failFirstDial simulates a connection-establishment failure on the first attempt.
type failFirstDial struct {
	n    atomic.Int32
	base http.RoundTripper
}

func (f *failFirstDial) RoundTrip(r *http.Request) (*http.Response, error) {
	if f.n.Add(1) == 1 {
		if r.Body != nil {
			r.Body.Close()
		}
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	}
	return f.base.RoundTrip(r)
}

func TestRetryOnConnectFailureReplaysExactBody(t *testing.T) {
	var bodies []string
	var mu sync.Mutex
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.Write([]byte(`{}`))
	}), func(o *Options) { o.Transport = &failFirstDial{base: NewTransport()} })
	body := chat("gpt-4o")
	resp, _ := e.do("POST", "/v1/chat/completions", e.tok["carol"], body)
	if resp.StatusCode != 200 || len(bodies) != 1 || bodies[0] != body {
		t.Fatalf("status=%d bodies=%q", resp.StatusCode, bodies)
	}
	waitFor(t, "retry logged", func() bool { return strings.Contains(e.access.String(), `"retries":1`) })
}

func TestDroppedConnectionNotReplayed(t *testing.T) {
	var n atomic.Int64
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		if n.Add(1) == 1 {
			w.Write([]byte(`{}`)) // warm the pooled connection
			return
		}
		panic(http.ErrAbortHandler) // request received, then connection dropped
	}), nil)
	e.do("POST", "/v1/chat/completions", e.tok["carol"], chat("gpt-4o"))
	resp, body := e.do("POST", "/v1/chat/completions", e.tok["carol"], chat("gpt-4o"))
	if resp.StatusCode != 502 || n.Load() != 2 {
		t.Errorf("status=%d upstream calls=%d (%s); a POST must not be replayed after it may have been processed", resp.StatusCode, n.Load(), body)
	}
}

func TestInterruptedStreamNotRetried(t *testing.T) {
	var n atomic.Int64
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"n\":1}\n\n")
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}), nil)
	resp, err := http.DefaultClient.Do(e.req(context.Background(), "POST", "/v1/chat/completions", e.tok["carol"], `{"model":"gpt-4o","stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err == nil {
		t.Errorf("truncated stream ended cleanly: %q", b)
	}
	if !strings.HasPrefix(string(b), "data: {\"n\":1}") {
		t.Errorf("partial data not delivered: %q", b)
	}
	if n.Load() != 1 {
		t.Errorf("stream was retried: %d upstream calls", n.Load())
	}
	waitFor(t, "interruption logged", func() bool { return strings.Contains(e.access.String(), "upstream_stream_interrupted") })
}

// 11: logs never contain credentials, prompts or completions.
func TestLogsContainNoSecrets(t *testing.T) {
	const prompt, completion = "TOP-SECRET-PROMPT-TEXT", "SECRET-COMPLETION-TEXT"
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, _ := io.ReadAll(r.Body); bytes.Contains(b, []byte("FAIL-UPSTREAM-AUTH")) {
			w.WriteHeader(401)
			fmt.Fprintf(w, `{"error":{"message":"Incorrect API key provided: %s"}}`, upstreamKey)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"choices":[{"message":{"content":%q}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`, completion)
	}), func(o *Options) { o.Routes = append(o.Routes, "POST /v1/probe") })
	body := fmt.Sprintf(`{"model":"gpt-4o","messages":[{"role":"user","content":%q}]}`, prompt)
	e.do("POST", "/v1/chat/completions", e.tok["alice"], body)
	e.do("POST", "/v1/chat/completions", e.tok["bob"], body)
	e.do("POST", "/v1/chat/completions", "sk-px-guessed-token-value", body)
	e.do("POST", "/v1/chat/completions", e.tok["dave"], body)
	e.do("POST", "/v1/probe", e.tok["carol"], strings.Replace(body, `"model"`, `"note":"FAIL-UPSTREAM-AUTH","model"`, 1))
	waitFor(t, "5 access records", func() bool { return strings.Count(e.access.String(), "\n") >= 5 })

	mrec := httptest.NewRecorder()
	e.opt.Metrics.ServeHTTP(mrec, httptest.NewRequest("GET", "/metrics", nil))
	for name, out := range map[string]string{"stdout log": e.logs.String(), "access log": e.access.String(), "metrics": mrec.Body.String()} {
		secrets := []string{upstreamKey, prompt, completion, "sk-px-guessed-token-value", "Bearer"}
		for _, tok := range e.tok {
			secrets = append(secrets, tok, tok[len(tokens.Prefix):])
		}
		for _, s := range secrets {
			if strings.Contains(out, s) {
				t.Errorf("%s contains secret %q", name, s)
			}
		}
	}
	acc := e.access.String()
	for _, want := range []string{`"client":"alice"`, `"model":"gpt-4o"`, `"status":403`, `"status":401`, `"error":"invalid_token"`, `"error":"revoked_token"`, `"error":"upstream_auth_failed"`, `"request_id":"px_`, `"latency_ms":`} {
		if !strings.Contains(acc, want) {
			t.Errorf("access log missing %s:\n%s", want, acc)
		}
	}
	for _, want := range []string{`oaiproxy_requests_total{client="alice",endpoint="POST /v1/chat/completions",code="200"} 1`, `oaiproxy_tokens_total{client="alice",model="gpt-4o",kind="input"} 1`} {
		if !strings.Contains(mrec.Body.String(), want) {
			t.Errorf("metrics missing %s", want)
		}
	}
}

func TestHealthz(t *testing.T) {
	e := newEnv(t, mock(), nil)
	resp, body := e.do("GET", "/healthz", "", "")
	if resp.StatusCode != 200 || !strings.Contains(string(body), "ok") {
		t.Errorf("healthz: %d %s", resp.StatusCode, body)
	}
}

func TestHotReloadRevokes(t *testing.T) {
	e := newEnv(t, mock(), nil)
	if resp, _ := e.do("POST", "/v1/chat/completions", e.tok["carol"], chat("gpt-4o")); resp.StatusCode != 200 {
		t.Fatal("precondition")
	}
	f := &tokens.File{Version: 1}
	tok, _ := f.Add(tokens.Client{ID: "zed"}, time.Now())
	e.p.SetStore(tokens.NewStore(f))
	if resp, _ := e.do("POST", "/v1/chat/completions", e.tok["carol"], chat("gpt-4o")); resp.StatusCode != 401 {
		t.Errorf("removed client still accepted: %d", resp.StatusCode)
	}
	if resp, _ := e.do("POST", "/v1/chat/completions", tok, chat("gpt-4o")); resp.StatusCode != 200 {
		t.Errorf("new client rejected: %d", resp.StatusCode)
	}
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// Review findings: Content-Type ambiguity, trailers, POST query, body budget.
func TestRequestNormalization(t *testing.T) {
	var got struct {
		ct, query string
		trailer   http.Header
	}
	var mu sync.Mutex
	m := mock()
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got.ct, got.query, got.trailer = r.Header.Get("Content-Type"), r.URL.RawQuery, r.Trailer
		mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(b))
		m.ServeHTTP(w, r)
	}), nil)
	body := `{"model":"gpt-4o","x":"&model=o3&"}`
	for _, c := range []struct {
		name string
		ct   []string
		want int
	}{
		{"form with dup params", []string{"application/x-www-form-urlencoded; a=1; a=2"}, 400},
		{"two content-types", []string{"application/json", "application/x-www-form-urlencoded"}, 400},
		{"text/plain for restricted", []string{"text/plain"}, 403},
		{"json with charset", []string{"application/json; charset=utf-8"}, 200},
		{"none", nil, 200},
	} {
		req := e.req(context.Background(), "POST", "/v1/chat/completions?model=o3", e.tok["alice"], body)
		req.Header.Del("Content-Type")
		for _, v := range c.ct {
			req.Header.Add("Content-Type", v)
		}
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s: got %d want %d", c.name, resp.StatusCode, c.want)
		}
		if c.want == 200 {
			mu.Lock()
			if got.ct != "application/json" || got.query != "" {
				t.Errorf("%s: upstream saw content-type %q query %q", c.name, got.ct, got.query)
			}
			mu.Unlock()
		}
	}

	// Chunked request with trailers: trailers must not reach upstream.
	pr, pw := io.Pipe()
	req := e.req(context.Background(), "POST", "/v1/chat/completions", e.tok["carol"], "")
	req.Body, req.ContentLength = pr, -1
	req.Header.Set("Content-Type", "application/json")
	req.Trailer = http.Header{"Openai-Project": nil, "X-Evil": nil}
	go func() {
		pw.Write([]byte(chat("gpt-4o")))
		req.Trailer.Set("Openai-Project", "proj_attacker")
		req.Trailer.Set("X-Evil", "1")
		pw.Close()
	}()
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	mu.Lock()
	if resp.StatusCode != 200 || len(got.trailer) != 0 {
		t.Errorf("trailers forwarded: status %d trailer %v", resp.StatusCode, got.trailer)
	}
	mu.Unlock()
}

func TestBodyBudget(t *testing.T) {
	e := newEnv(t, mock(), func(o *Options) { o.MaxBufferedBytes = 1 << 20; o.MaxRequestBytes = 1 << 20 })
	// A stalled upload declaring the full limit reserves the whole budget...
	conn, err := net.Dial("tcp", e.srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n{", e.tok["carol"], 1<<20)
	waitFor(t, "reservation", func() bool { return e.p.buffered.Load() == 1<<20 })
	// ...so further uploads are shed with 503 instead of growing memory.
	resp, body := e.do("POST", "/v1/chat/completions", e.tok["bob"], chat("gpt-4o-mini"))
	if resp.StatusCode != 503 || errCode(t, body) != "proxy_overloaded" {
		t.Errorf("got %d %s", resp.StatusCode, body)
	}
	conn.Close()
	waitFor(t, "budget released", func() bool { return e.p.buffered.Load() == 0 })
	if resp, _ := e.do("POST", "/v1/chat/completions", e.tok["bob"], chat("gpt-4o-mini")); resp.StatusCode != 200 {
		t.Errorf("after release: %d", resp.StatusCode)
	}
}

// A client that stops reading must not pin its request slot past the idle timeout.
func TestStalledReaderReleased(t *testing.T) {
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		chunk := []byte("data: " + strings.Repeat("x", 32<<10) + "\n\n")
		for r.Context().Err() == nil {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}), func(o *Options) { o.StreamIdleTimeout = 300 * time.Millisecond })
	conn, err := net.Dial("tcp", e.srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	b := chat("gpt-4o")
	fmt.Fprintf(conn, "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", e.tok["carol"], len(b), b)
	// Never read from conn.
	waitFor(t, "request in flight", func() bool { return e.p.inflight.Load() == 1 })
	waitFor(t, "slot released", func() bool { return e.p.inflight.Load() == 0 })
	waitFor(t, "logged", func() bool { return strings.Contains(e.access.String(), "upstream_idle_timeout") })
}

func TestModelsOwnedByScrubbed(t *testing.T) {
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"object":"list","data":[{"id":"ft:gpt-4o:acme:x:1","owned_by":"org-AbCdEf123456"},{"id":"gpt-4o","owned_by":"user-AbCdEf123456"}]}`)
	}), nil)
	_, body := e.do("GET", "/v1/models", e.tok["carol"], "")
	if bytes.Contains(body, []byte("AbCdEf123456")) || !bytes.Contains(body, []byte("ft:gpt-4o:acme:x:1")) {
		t.Errorf("models body: %s", body)
	}
}

// Relays may send JSON errors labelled text/event-stream on streaming
// requests; the real message must reach the client, scrubbed.
func TestStreamingErrorPassedThrough(t *testing.T) {
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(400)
		fmt.Fprintf(w, `{"error":{"message":"Input must be a list (key %s, org-AbCdEf123456)","code":"invalid_request_error"}}`, upstreamKey)
	}), nil)
	resp, body := e.do("POST", "/v1/responses", e.tok["carol"], `{"model":"gpt-4o","stream":true,"input":"x"}`)
	if resp.StatusCode != 400 || resp.Header.Get("Content-Type") != "application/json" || !bytes.Contains(body, []byte("Input must be a list")) {
		t.Errorf("got %d %q %s", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	if bytes.Contains(body, []byte(upstreamKey)) || bytes.Contains(body, []byte("AbCdEf123456")) {
		t.Errorf("not scrubbed: %s", body)
	}
	waitFor(t, "upstream_status in stdout log", func() bool { return strings.Contains(e.logs.String(), `"upstream_status":400`) })
}

// Provider-configured headers (e.g. OpenRouter attribution) reach upstream,
// and an upstream base path other than /v1 (OpenRouter's /api/v1) is honoured.
func TestExtraHeadersAndBasePath(t *testing.T) {
	var got *http.Request
	var mu sync.Mutex
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		mu.Lock()
		got = r.Clone(context.Background())
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer up.Close()
	e := newEnv(t, http.NotFoundHandler(), func(o *Options) {
		o.Upstream, _ = url.Parse(up.URL + "/api/v1")
		o.ExtraHeaders = http.Header{"Http-Referer": {"https://example.com"}, "X-Title": {"Bench"}}
	})
	resp, body := e.do("POST", "/v1/chat/completions", e.tok["carol"], chat("openai/gpt-4o-mini"), "X-Title", "client-spoofed")
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	mu.Lock()
	defer mu.Unlock()
	if got.URL.Path != "/api/v1/chat/completions" || got.Header.Get("Http-Referer") != "https://example.com" || got.Header.Get("X-Title") != "Bench" {
		t.Errorf("path %q headers %v", got.URL.Path, got.Header)
	}
}
