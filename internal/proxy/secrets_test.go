package proxy

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"strings"
	"sync/atomic"
	"testing"
)

func TestEncodedResponseCannotBypassCredentialFilter(t *testing.T) {
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		fmt.Fprint(gz, upstreamKey)
		gz.Close()
	}), nil)
	resp, body := e.do("POST", "/v1/responses", e.tok["carol"], `{"model":"gpt-4o"}`)
	if resp.StatusCode != 502 || resp.Header.Get("Content-Encoding") != "" || bytes.Contains(body, []byte(upstreamKey)) {
		t.Fatal("encoded response bypassed containment")
	}
}

func TestInformationalHeadersAreSanitized(t *testing.T) {
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Diagnostic", upstreamKey)
		w.Header().Set("OpenAI-Organization", "org-providerSecret")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("X-Diagnostic")
		w.Header().Del("OpenAI-Organization")
		fmt.Fprint(w, `{}`)
	}), nil)
	seen := false
	r := e.req(httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
		seen = true
		if strings.Contains(fmt.Sprint(h), upstreamKey) || h.Get("OpenAI-Organization") != "" {
			t.Error("informational metadata escaped")
		}
		return nil
	}}), "POST", "/v1/responses", e.tok["carol"], `{"model":"gpt-4o"}`)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if !seen {
		t.Fatal("missing informational response")
	}
}

type credentialErrorBody struct{ secret string }

func (b credentialErrorBody) Read([]byte) (int, error) {
	return 0, errors.New("fixture read error: " + b.secret)
}
func (b credentialErrorBody) Close() error { return nil }

type credentialErrorTransport struct{ key *rotatingFixtureKey }

func (rt credentialErrorTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	secret := rt.key.Get()
	rt.key.key.Store("fixture-replacement-key")
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: credentialErrorBody{secret}, Request: r, ContentLength: -1}, nil
}

func TestStreamCopyErrorDoesNotLogRotatedCredential(t *testing.T) {
	key := &rotatingFixtureKey{}
	secret := "fixture-old-key-without-standard-prefix"
	key.key.Store(secret)
	e := newEnv(t, http.NotFoundHandler(), func(o *Options) { o.Key, o.Transport = key, credentialErrorTransport{key} })
	resp, _ := http.DefaultClient.Do(e.req(t.Context(), "POST", "/v1/responses", e.tok["carol"], `{"model":"gpt-4o"}`))
	if resp != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	waitFor(t, "copy error", func() bool { return strings.Contains(e.logs.String(), "read error") })
	if strings.Contains(e.logs.String(), secret) || strings.Contains(e.access.String(), secret) {
		t.Fatal("copy error leaked dispatch credential")
	}
}

type rotatingFixtureKey struct{ key atomic.Value }

func (k *rotatingFixtureKey) Get() string { return k.key.Load().(string) }

func TestCredentialSnapshotSurvivesRotation(t *testing.T) {
	key := &rotatingFixtureKey{}
	key.key.Store("fixture-old-provider-credential-without-standard-prefix")
	old := key.Get()
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+old {
			t.Error("wrong dispatch key")
		}
		key.key.Store("fixture-new-provider-credential")
		w.Header().Set("X-Diagnostic", old)
		fmt.Fprint(w, old)
	}), func(o *Options) { o.Key = key })
	resp, body := e.do("POST", "/v1/responses", e.tok["carol"], `{"model":"gpt-4o"}`)
	if bytes.Contains(body, []byte(old)) || strings.Contains(fmt.Sprint(resp.Header), old) {
		t.Fatal("rotated dispatch credential escaped")
	}
}

func TestCredentialBodyEveryChunkBoundary(t *testing.T) {
	for split := 0; split <= len(upstreamKey); split++ {
		body := &credentialBody{ReadCloser: io.NopCloser(io.MultiReader(strings.NewReader("before:"+upstreamKey[:split]), strings.NewReader(upstreamKey[split:]+":after"))), secret: []byte(upstreamKey)}
		var got bytes.Buffer
		buf := make([]byte, 3)
		if _, err := io.CopyBuffer(&got, struct{ io.Reader }{body}, buf); err != nil {
			t.Fatal(err)
		}
		want := "before:" + strings.Repeat("*", len(upstreamKey)) + ":after"
		if got.String() != want {
			t.Fatalf("credential split %d was not masked", split)
		}
	}
	for _, data := range []string{"ordinary text", "s", "sk-", "sk-upstream-REALKEY-0123456789abcdeX", string([]byte{0, 255, 128, 42})} {
		body := &credentialBody{ReadCloser: io.NopCloser(strings.NewReader(data)), secret: []byte(upstreamKey)}
		got, err := io.ReadAll(body)
		if err != nil || string(got) != data {
			t.Fatal("unrelated bytes changed")
		}
	}
}

func TestCredentialResponseMetadataAndTrailers(t *testing.T) {
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("X-Request-Id", upstreamKey)
		w.Header().Set("X-Diagnostic", "provider="+upstreamKey)
		w.Header().Set("Trailer", "OpenAI-Organization, OpenAI-Project, Set-Cookie, X-Ratelimit-Remaining-Requests, X-Diagnostic")
		w.WriteHeader(200)
		fmt.Fprint(w, "data: "+upstreamKey[:8])
		w.(http.Flusher).Flush()
		fmt.Fprint(w, upstreamKey[8:]+"\n\n")
		w.(http.Flusher).Flush()
		w.Header().Set("OpenAI-Organization", "org-providerSecret")
		w.Header().Set("OpenAI-Project", "proj_providerSecret")
		w.Header().Set("Set-Cookie", "secret=cookie")
		w.Header().Set("X-Ratelimit-Remaining-Requests", "1000")
		w.Header().Set("X-Diagnostic", upstreamKey)
	}), nil)
	resp, b := e.do("POST", "/v1/responses", e.tok["carol"], `{"model":"gpt-4o","stream":true}`)
	if resp.StatusCode != 200 || bytes.Contains(b, []byte(upstreamKey)) || strings.Contains(fmt.Sprint(resp.Header, resp.Trailer), upstreamKey) {
		t.Fatal("credential appeared in response")
	}
	for _, h := range []string{"OpenAI-Organization", "OpenAI-Project", "Set-Cookie", "X-Ratelimit-Remaining-Requests"} {
		if resp.Header.Get(h) != "" || resp.Trailer.Get(h) != "" {
			t.Errorf("sensitive metadata %s survived", h)
		}
	}
	waitFor(t, "request log", func() bool { return strings.Contains(e.logs.String(), `"status":200`) })
	if strings.Contains(e.logs.String(), upstreamKey) || strings.Contains(e.access.String(), upstreamKey) {
		t.Fatal("credential appeared in logs")
	}
}
