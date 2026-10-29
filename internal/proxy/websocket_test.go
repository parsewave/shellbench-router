package proxy

import (
	"net/http"
	"sync/atomic"
	"testing"
)

func TestResponsesWebSocketFallback(t *testing.T) {
	var calls atomic.Int32
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write([]byte(`{"id":"resp_test"}`))
	}), nil)
	for _, tc := range []struct {
		name, path, client, upgrade, connection string
		want                                    int
	}{
		{"upgrade", "/v1/responses", "carol", "websocket", "Upgrade", 426},
		{"restricted token", "/v1/responses", "alice", "WebSocket", "keep-alive, UpGrAdE", 426},
		{"missing token", "/v1/responses", "", "websocket", "Upgrade", 401},
		{"disabled token", "/v1/responses", "dave", "websocket", "Upgrade", 401},
		{"ordinary GET", "/v1/responses", "carol", "", "", 404},
		{"missing Connection", "/v1/responses", "carol", "websocket", "", 404},
		{"wrong protocol", "/v1/responses", "carol", "other", "Upgrade", 404},
		{"other endpoint", "/v1/chat/completions", "carol", "websocket", "Upgrade", 404},
		{"encoded path", "/v1/%72esponses", "carol", "websocket", "Upgrade", 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, b := e.do("GET", tc.path, e.tok[tc.client], "", "Upgrade", tc.upgrade, "Connection", tc.connection)
			if r.StatusCode != tc.want {
				t.Fatalf("status %d, want %d", r.StatusCode, tc.want)
			}
			if tc.want == 426 && (errCode(t, b) != "websocket_unsupported" || r.Header.Get("Cache-Control") != "no-store") {
				t.Fatalf("missing fallback code or private cache policy: %s", b)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("WebSocket negotiation reached upstream")
	}
	if r, _ := e.do("POST", "/v1/responses", e.tok["alice"], `{"model":"gpt-4o","input":"hi"}`); r.StatusCode != 200 {
		t.Fatalf("HTTP Responses status %d", r.StatusCode)
	}
	if r, _ := e.do("POST", "/v1/responses", e.tok["alice"], `{"model":"gpt-4o-mini","input":"hi"}`); r.StatusCode != 403 {
		t.Fatalf("HTTP model restriction status %d", r.StatusCode)
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls %d, want 1", calls.Load())
	}
}

func TestResponsesWebSocketAdmission(t *testing.T) {
	e, tok := allowlistEnv(t, nil)
	for _, tc := range []struct {
		ip   string
		want int
	}{{"203.0.113.7", 426}, {"198.51.100.1", 403}} {
		r := e.req(t.Context(), "GET", "/v1/responses", tok, "", "Upgrade", "websocket", "X-Forwarded-For", tc.ip)
		r.Header.Add("Connection", "keep-alive")
		r.Header.Add("Connection", "Upgrade")
		resp, err := noRedirect.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		readBody(resp)
		if resp.StatusCode != tc.want {
			t.Fatalf("status %d, want %d", resp.StatusCode, tc.want)
		}
	}
	disabled := newEnv(t, http.NotFoundHandler(), func(o *Options) { o.Routes = []string{"GET /v1/models"} })
	if r, _ := disabled.do("GET", "/v1/responses", disabled.tok["carol"], "", "Upgrade", "websocket", "Connection", "Upgrade"); r.StatusCode != 404 {
		t.Fatalf("disabled Responses status %d", r.StatusCode)
	}
}
