package proxy

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

type seenRequest struct {
	method, path, query string
	header              http.Header
	body                string
}

func anthropicEnv(t *testing.T, respond func(w http.ResponseWriter, r *http.Request)) (*testEnv, func() []seenRequest) {
	t.Helper()
	var mu sync.Mutex
	var seen []seenRequest
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, seenRequest{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), string(b)})
		mu.Unlock()
		respond(w, r)
	}), nil)
	return e, func() []seenRequest { mu.Lock(); defer mu.Unlock(); return append([]seenRequest(nil), seen...) }
}

const messagesBody = `{"model":"gpt-4o","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`

// Claude Code: token in x-api-key, anthropic-version/beta headers, ?beta=true.
func TestAnthropicMessages(t *testing.T) {
	e, seen := anthropicEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"OK"}],"usage":{"input_tokens":11,"output_tokens":5}}`))
	})
	resp, b := e.do("POST", "/v1/messages?beta=true", "", messagesBody,
		"X-Api-Key", e.tok["carol"], "Anthropic-Version", "2023-06-01", "Anthropic-Beta", "prompt-caching-2024-07-31")
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"OK"`) {
		t.Fatalf("messages: %d %s", resp.StatusCode, b)
	}
	if resp, b := e.do("POST", "/v1/messages/count_tokens?beta=true", "", messagesBody, "X-Api-Key", e.tok["carol"]); resp.StatusCode != 200 {
		t.Fatalf("count_tokens: %d %s", resp.StatusCode, b)
	}
	got := seen()
	if len(got) != 2 {
		t.Fatalf("upstream saw %d requests", len(got))
	}
	r := got[0]
	if r.path != "/v1/messages" || r.query != "beta=true" || r.body != messagesBody {
		t.Errorf("forwarded %s ?%s %s", r.path, r.query, r.body)
	}
	if got[1].path != "/v1/messages/count_tokens" {
		t.Errorf("count_tokens forwarded to %s", got[1].path)
	}
	if r.header.Get("Anthropic-Version") != "2023-06-01" || r.header.Get("Anthropic-Beta") != "prompt-caching-2024-07-31" {
		t.Errorf("anthropic headers not forwarded: %v", r.header)
	}
	// The client's proxy token never reaches the provider; the provider key does.
	if v := r.header.Get("X-Api-Key"); v != "" {
		t.Errorf("client x-api-key forwarded upstream: %q", v)
	}
	if r.header.Get("Authorization") != "Bearer "+upstreamKey {
		t.Errorf("upstream auth = %q", r.header.Get("Authorization"))
	}
	waitFor(t, "usage logged", func() bool {
		return strings.Contains(e.logs.String(), `"input_tokens":11`) && strings.Contains(e.logs.String(), `"output_tokens":5`)
	})
	if strings.Contains(e.logs.String(), e.tok["carol"]) {
		t.Fatal("x-api-key token logged")
	}
}

func TestAnthropicAuthAndPolicy(t *testing.T) {
	e, seen := anthropicEnv(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) })
	for _, c := range []struct {
		name string
		hdr  []string
		want int
	}{
		{"no token", nil, 401},
		{"bad x-api-key", []string{"X-Api-Key", "sk-px-nope"}, 401},
		{"revoked via x-api-key", []string{"X-Api-Key", e.tok["dave"]}, 401},
		// Model allow-lists apply to Messages bodies too (bob: gpt-4o-mini only).
		{"disallowed model", []string{"X-Api-Key", e.tok["bob"]}, 403},
		// Authorization wins when both are present.
		{"bearer + bad x-api-key", []string{"Authorization", "Bearer " + e.tok["carol"], "X-Api-Key", "garbage"}, 200},
	} {
		resp, b := e.do("POST", "/v1/messages", "", messagesBody, c.hdr...)
		if resp.StatusCode != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, resp.StatusCode, b, c.want)
		}
	}
	if n := len(seen()); n != 1 {
		t.Errorf("upstream saw %d requests, want only the authorized one", n)
	}
	// Query strings on other POST routes are still dropped.
	e.do("POST", "/v1/chat/completions?api-key=x", e.tok["carol"], `{"model":"gpt-4o","messages":[]}`)
	for _, r := range seen() {
		if r.path == "/v1/chat/completions" && r.query != "" {
			t.Errorf("chat completions query forwarded: %q", r.query)
		}
	}
}

// Streaming Messages: usage comes from the message_start / message_delta events.
func TestAnthropicMessagesStreamUsage(t *testing.T) {
	e, _ := anthropicEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for _, ev := range []string{
			`event: message_start` + "\n" + `data: {"type":"message_start","message":{"id":"msg_1","usage":{"input_tokens":21,"output_tokens":1}}}`,
			`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"OK"}}`,
			`event: message_delta` + "\n" + `data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":21,"output_tokens":7}}`,
			`event: message_stop` + "\n" + `data: {"type":"message_stop"}`,
		} {
			w.Write([]byte(ev + "\n\n"))
			w.(http.Flusher).Flush()
		}
	})
	resp, b := e.do("POST", "/v1/messages", "", strings.Replace(messagesBody, `"max_tokens"`, `"stream":true,"max_tokens"`, 1), "X-Api-Key", e.tok["carol"])
	if resp.StatusCode != 200 || !strings.Contains(string(b), "message_stop") {
		t.Fatalf("stream: %d %s", resp.StatusCode, b)
	}
	waitFor(t, "stream usage logged", func() bool {
		return strings.Contains(e.logs.String(), `"output_tokens":7`) && strings.Contains(e.logs.String(), `"stream":true`)
	})
}
