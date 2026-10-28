package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSearchCallerNamespaces(t *testing.T) {
	var mu sync.Mutex
	var seen []map[string]json.RawMessage
	wire := `{"output":"fixture search reference","encrypted_output":"fixture ciphertext"}`
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var doc map[string]json.RawMessage
		if json.NewDecoder(r.Body).Decode(&doc) != nil {
			t.Error("invalid upstream JSON")
		}
		mu.Lock()
		seen = append(seen, doc)
		mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+upstreamKey {
			t.Error("wrong upstream credential")
		}
		io.WriteString(w, wire)
	}), nil)
	for _, client := range []string{"alice", "alice", "carol"} {
		resp, body := e.do("POST", "/v1/alpha/search", e.tok[client], `{"model":"gpt-4o","id":"same-session","commands":{"search_query":[{"q":"fixture"}]},"settings":{"external_web_access":false}}`)
		if resp.StatusCode != 200 || string(body) != wire {
			t.Fatal("search result changed")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 3 || string(seen[0]["id"]) == `"same-session"` || string(seen[0]["id"]) != string(seen[1]["id"]) || string(seen[0]["id"]) == string(seen[2]["id"]) {
		t.Fatal("session namespace not stable and caller-isolated")
	}
	if string(seen[0]["settings"]) != `{"external_web_access":false}` {
		t.Fatal("search mode changed")
	}
	for _, property := range []string{"caller", "origin", "org", "project", "key"} {
		args := []string{"caller", "origin", "org", "project", "key"}
		for i, name := range []string{"caller", "origin", "org", "project", "key"} {
			if name == property {
				args[i] += "-changed"
			}
		}
		body := []byte(`{"model":"gpt-4o","id":"session","commands":{"open":[{"ref_id":"turn0search0"}]}}`)
		one, err := scopedSearch(body, "caller", "origin", "org", "project", "key")
		if err != nil {
			t.Fatal(err)
		}
		two, err := scopedSearch(body, args[0], args[1], args[2], args[3], args[4])
		if err != nil {
			t.Fatal(err)
		}
		if string(one) == string(two) {
			t.Errorf("%s did not change namespace", property)
		}
	}
}

func TestSearchRejectsInvalidBeforeDispatch(t *testing.T) {
	e := newEnv(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("invalid search reached upstream") }), nil)
	for _, body := range []string{
		`{"model":"o3","id":"s","commands":{"search_query":[{"q":"test"}]}}`,
		`{"id":"s","commands":{"search_query":[{"q":"test"}]}}`,
		`{"model":"gpt-4o","id":"s","id":"other","commands":{"search_query":[{"q":"test"}]}}`,
		`{"model":"gpt-4o","id":"s","commands":{"weather":[{}]}}`,
		`{"model":"gpt-4o","id":"s","commands":{}}`,
		`{"model":"gpt-4o","id":"s","commands":{"find":[{"ref_id":"turn0","pattern":""}]}}`,
		`{"model":"gpt-4o","id":"s","commands":{"click":[{"ref_id":"turn0","id":-1}]}}`,
		`{"model":"gpt-4o","id":"s","commands":{"search_query":[{"q":"test","q":"other"}]}}`,
		`{"model":"gpt-4o","id":"s","stream":false,"commands":{"search_query":[{"q":"test"}]}}`,
	} {
		resp, _ := e.do("POST", "/v1/alpha/search", e.tok["alice"], body)
		if resp.StatusCode != 400 && resp.StatusCode != 403 {
			t.Errorf("invalid search accepted: %d", resp.StatusCode)
		}
	}
	for _, contentType := range []string{"application/x-www-form-urlencoded", "multipart/form-data; boundary=test"} {
		req, _ := http.NewRequest("POST", e.srv.URL+"/v1/alpha/search", strings.NewReader("id=unscoped"))
		req.Header.Set("Authorization", "Bearer "+e.tok["carol"])
		req.Header.Set("Content-Type", contentType)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatal("non-JSON search bypassed caller scoping")
		}
	}
}

func TestSearchOpenAILive(t *testing.T) {
	if os.Getenv("SHELLBENCH_OPENAI_LIVE") != "1" {
		t.Skip("opt-in billable OpenAI proof")
	}
	key := os.Getenv("OPENAI_API_KEY")
	if key == "" {
		t.Fatal("OPENAI_API_KEY required")
	}
	e := newEnv(t, http.NotFoundHandler(), func(o *Options) {
		o.Upstream, _ = url.Parse("https://api.openai.com/v1")
		o.Key = staticKey(key)
		o.MaxRetries = 0
		o.UpstreamTimeout = 90 * time.Second
	})
	query := func(commands string) string {
		body := fmt.Sprintf(`{"model":"gpt-6.1-sol","id":"shellbench-live-fixture","commands":%s,"settings":{"external_web_access":true}}`, commands)
		resp, b := e.do("POST", "/v1/alpha/search", e.tok["carol"], body)
		if resp.StatusCode != 200 {
			t.Fatalf("live standalone search status %d (body withheld)", resp.StatusCode)
		}
		if strings.Contains(string(b), key) {
			t.Fatal("upstream key appeared in search output")
		}
		var doc struct {
			Output string `json:"output"`
		}
		if json.Unmarshal(b, &doc) != nil || len(doc.Output) == 0 {
			t.Fatal("no search output")
		}
		return doc.Output
	}
	out := query(`{"search_query":[{"q":"OpenAI official website"}],"response_length":"short"}`)
	ref := regexp.MustCompile(`turn[0-9]+search[0-9]+`).FindString(out)
	if ref == "" {
		t.Fatal("no reusable search reference")
	}
	opened := query(fmt.Sprintf(`{"open":[{"ref_id":%q}],"response_length":"short"}`, ref))
	if !strings.Contains(strings.ToLower(opened), "openai") {
		t.Fatal("reference open did not return expected content")
	}
	if strings.Contains(e.logs.String(), key) || strings.Contains(e.access.String(), key) {
		t.Fatal("key appeared in logs")
	}
}
