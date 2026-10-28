package proxy

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestImageRoutes(t *testing.T) {
	for _, path := range []string{"images/generations", "images/edits"} {
		t.Run(path, func(t *testing.T) {
			payload := []byte{0, 255, 128, 42}
			mime := "audio/mpeg"
			if strings.HasPrefix(path, "images/") {
				mime = "application/json"
				payload = []byte(`{"data":[{"b64_json":"` + strings.Repeat("A", 3<<20) + `"}]}`)
			}
			var calls atomic.Int64
			e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body, _ := io.ReadAll(r.Body)
				if r.URL.Path != "/v1/"+path || string(body) != `{"model":"gpt-4o","input":"fixture"}` || r.Header.Get("Authorization") != "Bearer "+upstreamKey {
					t.Error("upstream request changed")
				}
				w.Header().Set("Content-Type", mime)
				w.Write(payload)
			}), nil)
			resp, body := e.do("POST", "/v1/"+path, e.tok["alice"], `{"model":"gpt-4o","input":"fixture"}`)
			if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != mime || !bytes.Equal(body, payload) {
				t.Fatal("media response was not preserved")
			}
			resp, _ = e.do("POST", "/v1/"+path, e.tok["bob"], `{"model":"gpt-4o"}`)
			if resp.StatusCode != 403 || calls.Load() != 1 {
				t.Fatal("disallowed media model reached upstream")
			}
		})
	}
}
