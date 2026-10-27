package proxy

import (
	"net/http"
	"strings"
	"sync"
	"testing"
)

// The default routes include the stateless endpoints agents call besides
// chat/responses (Codex's /responses/compact, legacy completions,
// moderations), and they reach the upstream.
func TestDefaultRoutesForwarded(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}), nil)
	for _, path := range []string{"/v1/responses/compact", "/v1/completions", "/v1/moderations"} {
		resp, b := e.do("POST", path, e.tok["carol"], `{"model":"gpt-4o","input":"hi"}`)
		if resp.StatusCode != 200 {
			t.Errorf("POST %s: %d %s", path, resp.StatusCode, b)
		}
	}
	mu.Lock()
	got := strings.Join(seen, ",")
	mu.Unlock()
	for _, want := range []string{"POST /v1/responses/compact", "POST /v1/completions", "POST /v1/moderations"} {
		if !strings.Contains(got, want) {
			t.Errorf("upstream did not receive %s (got %s)", want, got)
		}
	}
	// Model restrictions apply to the new routes too.
	if resp, _ := e.do("POST", "/v1/completions", e.tok["bob"], `{"model":"gpt-4o","prompt":"hi"}`); resp.StatusCode != 403 {
		t.Errorf("restricted token, disallowed model on /v1/completions: %d", resp.StatusCode)
	}
}

func TestUnknownRouteLoggedAsWarning(t *testing.T) {
	e := newEnv(t, http.NotFoundHandler(), nil)
	e.do("POST", "/v1/files", e.tok["carol"], "")
	waitFor(t, "warn log for unknown route", func() bool {
		for _, l := range strings.Split(e.logs.String(), "\n") {
			if strings.Contains(l, `"error":"unknown_url"`) && strings.Contains(l, `"path":"/v1/files"`) && strings.Contains(l, `"level":"WARN"`) {
				return true
			}
		}
		return false
	})
}
