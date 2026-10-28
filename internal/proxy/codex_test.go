package proxy

import (
	"io"
	"net/http"
	"testing"
)

func TestCodexMetadataAndHostedTools(t *testing.T) {
	headers := []string{"Session-Id", "Thread-Id", "Session_id", "Originator", "X-Codex-Turn-State", "X-Codex-Turn-Metadata", "X-Codex-Beta-Features", "X-Openai-Internal-Codex-Responses-Lite"}
	input := `{"model":"gpt-4o","tools":[{"type":"web_search"},{"type":"image_generation"}],"input":"fixture"}`
	for _, path := range []string{"responses", "responses/compact", "responses/input_tokens"} {
		t.Run(path, func(t *testing.T) {
			out := "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"output\":[{\"type\":\"web_search_call\"},{\"type\":\"image_generation_call\",\"result\":\"fixture\"}]}}\n\n"
			e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				if string(b) != input || r.URL.RawQuery != "" {
					t.Error("body/query changed")
				}
				for _, h := range headers {
					if r.Header.Get(h) != "fixture" {
						t.Errorf("lost %s", h)
					}
				}
				if r.Header.Get("OpenAI-Project") != "" || r.Header.Get("Cookie") != "" {
					t.Error("caller identity forwarded")
				}
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, out)
			}), nil)
			hdr := []string{"OpenAI-Project", "untrusted", "Cookie", "untrusted"}
			for _, h := range headers {
				hdr = append(hdr, h, "fixture")
			}
			resp, b := e.do("POST", "/v1/"+path, e.tok["alice"], input, hdr...)
			if resp.StatusCode != 200 || string(b) != out {
				t.Fatal("hosted tool output changed")
			}
		})
	}
}
