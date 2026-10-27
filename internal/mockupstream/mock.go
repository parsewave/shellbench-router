// Package mockupstream is a small fake of the OpenAI API used for tests,
// smoke tests, SDK compatibility checks and benchmarks. It returns
// realistically shaped JSON and SSE for chat completions, responses,
// embeddings and models.
package mockupstream

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

type Server struct {
	Key        string        // expected bearer key
	Latency    time.Duration // added before every response
	ChunkDelay time.Duration // between SSE events
	Words      int           // words per completion (default 8)
	Requests   atomic.Int64
}

var models = []string{"gpt-4o", "gpt-4o-mini", "o3", "text-embedding-3-small"}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.Requests.Add(1)
	if r.Header.Get("Authorization") != "Bearer "+s.Key {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":{"message":"Incorrect API key provided: %s. You can find your API key at https://platform.openai.com/account/api-keys.","type":"invalid_request_error","param":null,"code":"invalid_api_key"}}`, mask(r.Header.Get("Authorization")))
		return
	}
	if s.Latency > 0 {
		select {
		case <-time.After(s.Latency):
		case <-r.Context().Done():
			return
		}
	}
	w.Header().Set("X-Request-Id", fmt.Sprintf("req_mock%d", time.Now().UnixNano()))
	w.Header().Set("Openai-Organization", "org-mockSecretOrg123")
	w.Header().Set("Openai-Processing-Ms", "1")

	var body struct {
		Model         string `json:"model"`
		Stream        bool   `json:"stream"`
		StreamOptions *struct {
			IncludeUsage bool `json:"include_usage"`
		} `json:"stream_options"`
		Input any `json:"input"`
	}
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]any{"error": map[string]any{"message": "We could not parse the JSON body of your request.", "type": "invalid_request_error", "param": nil, "code": nil}})
			return
		}
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/models":
		var data []map[string]any
		for _, m := range models {
			data = append(data, map[string]any{"id": m, "object": "model", "created": 1700000000, "owned_by": "openai"})
		}
		writeJSON(w, 200, map[string]any{"object": "list", "data": data})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/models/"):
		writeJSON(w, 200, map[string]any{"id": strings.TrimPrefix(r.URL.Path, "/v1/models/"), "object": "model", "created": 1700000000, "owned_by": "openai"})
	case r.URL.Path == "/v1/chat/completions":
		s.chat(w, r, body.Model, body.Stream, body.StreamOptions != nil && body.StreamOptions.IncludeUsage)
	case r.URL.Path == "/v1/responses":
		s.responses(w, r, body.Model, body.Stream)
	case r.URL.Path == "/v1/embeddings":
		n := 1
		if arr, ok := body.Input.([]any); ok {
			n = len(arr)
		}
		var data []map[string]any
		for i := 0; i < n; i++ {
			data = append(data, map[string]any{"object": "embedding", "index": i, "embedding": []float64{0.1, -0.2, 0.3, 0.05}})
		}
		writeJSON(w, 200, map[string]any{"object": "list", "data": data, "model": body.Model, "usage": map[string]any{"prompt_tokens": 4 * n, "total_tokens": 4 * n}})
	default:
		writeJSON(w, 404, map[string]any{"error": map[string]any{"message": "Invalid URL (" + r.Method + " " + r.URL.Path + ")", "type": "invalid_request_error", "param": nil, "code": nil}})
	}
}

func (s *Server) words() []string {
	n := s.Words
	if n <= 0 {
		n = 8
	}
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("word%d ", i)
	}
	return out
}

func (s *Server) chat(w http.ResponseWriter, r *http.Request, model string, stream, includeUsage bool) {
	words := s.words()
	usage := map[string]any{"prompt_tokens": 12, "completion_tokens": len(words), "total_tokens": 12 + len(words),
		"prompt_tokens_details": map[string]any{"cached_tokens": 0}, "completion_tokens_details": map[string]any{"reasoning_tokens": 0}}
	id := "chatcmpl-mock"
	if !stream {
		writeJSON(w, 200, map[string]any{
			"id": id, "object": "chat.completion", "created": time.Now().Unix(), "model": model,
			"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": strings.Join(words, "")}, "finish_reason": "stop"}},
			"usage":   usage,
		})
		return
	}
	sse := startSSE(w)
	for i, word := range words {
		delta := map[string]any{"content": word}
		if i == 0 {
			delta["role"] = "assistant"
		}
		chunk := map[string]any{"id": id, "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": model,
			"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": nil}}}
		if includeUsage {
			chunk["usage"] = nil
		}
		if !sse.event("", chunk, s.ChunkDelay, r) {
			return
		}
	}
	final := map[string]any{"id": id, "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": model,
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}}}
	sse.event("", final, 0, r)
	if includeUsage {
		sse.event("", map[string]any{"id": id, "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": model, "choices": []any{}, "usage": usage}, 0, r)
	}
	sse.raw("data: [DONE]\n\n")
}

func (s *Server) responses(w http.ResponseWriter, r *http.Request, model string, stream bool) {
	words := s.words()
	text := strings.Join(words, "")
	resp := func(status string, out string) map[string]any {
		m := map[string]any{"id": "resp_mock", "object": "response", "created_at": time.Now().Unix(), "status": status, "model": model,
			"output": []any{}, "usage": nil}
		if status == "completed" {
			m["output"] = []any{map[string]any{"type": "message", "id": "msg_mock", "status": "completed", "role": "assistant",
				"content": []any{map[string]any{"type": "output_text", "text": out, "annotations": []any{}}}}}
			m["usage"] = map[string]any{"input_tokens": 10, "output_tokens": len(words), "total_tokens": 10 + len(words),
				"input_tokens_details": map[string]any{"cached_tokens": 2}, "output_tokens_details": map[string]any{"reasoning_tokens": 3}}
		}
		return m
	}
	if !stream {
		writeJSON(w, 200, resp("completed", text))
		return
	}
	sse := startSSE(w)
	seq := 0
	ev := func(typ string, m map[string]any, delay time.Duration) bool {
		m["type"], m["sequence_number"] = typ, seq
		seq++
		return sse.event(typ, m, delay, r)
	}
	item := func(status, txt string) map[string]any {
		return map[string]any{"type": "message", "id": "msg_mock", "status": status, "role": "assistant", "content": []any{}}
	}
	part := func(txt string) map[string]any {
		return map[string]any{"type": "output_text", "text": txt, "annotations": []any{}}
	}
	if !ev("response.created", map[string]any{"response": resp("in_progress", "")}, 0) ||
		!ev("response.output_item.added", map[string]any{"output_index": 0, "item": item("in_progress", "")}, 0) ||
		!ev("response.content_part.added", map[string]any{"item_id": "msg_mock", "output_index": 0, "content_index": 0, "part": part("")}, 0) {
		return
	}
	for _, word := range words {
		if !ev("response.output_text.delta", map[string]any{"item_id": "msg_mock", "output_index": 0, "content_index": 0, "delta": word}, s.ChunkDelay) {
			return
		}
	}
	ev("response.output_text.done", map[string]any{"item_id": "msg_mock", "output_index": 0, "content_index": 0, "text": text}, 0)
	ev("response.content_part.done", map[string]any{"item_id": "msg_mock", "output_index": 0, "content_index": 0, "part": part(text)}, 0)
	done := item("completed", text)
	done["content"] = []any{part(text)}
	ev("response.output_item.done", map[string]any{"output_index": 0, "item": done}, 0)
	ev("response.completed", map[string]any{"response": resp("completed", text)}, 0)
}

type sseWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func startSSE(w http.ResponseWriter) *sseWriter {
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(200)
	f, _ := w.(http.Flusher)
	return &sseWriter{w: w, f: f}
}

func (s *sseWriter) event(name string, v any, delay time.Duration, r *http.Request) bool {
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return false
		}
	}
	b, _ := json.Marshal(v)
	if name != "" {
		fmt.Fprintf(s.w, "event: %s\n", name)
	}
	fmt.Fprintf(s.w, "data: %s\n\n", b)
	if s.f != nil {
		s.f.Flush()
	}
	return r.Context().Err() == nil
}

func (s *sseWriter) raw(str string) {
	fmt.Fprint(s.w, str)
	if s.f != nil {
		s.f.Flush()
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func mask(auth string) string {
	k := strings.TrimPrefix(auth, "Bearer ")
	if len(k) < 8 {
		return "sk-****"
	}
	return k[:3] + strings.Repeat("*", 20) + k[len(k)-4:]
}
