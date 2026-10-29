package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"oaiproxy/internal/tokens"
)

func TestExcludedModelsNeverDispatch(t *testing.T) {
	var calls atomic.Int64
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.WriteString(w, `{"object":"fixture","output":[]}`)
	}), nil)
	for _, path := range []string{
		"responses", "responses/compact", "responses/input_tokens", "chat/completions", "completions",
		"embeddings", "decisions", "audio/speech", "images/generations", "images/edits",
		"moderations", "messages", "messages/count_tokens", "alpha/search",
	} {
		for _, client := range []string{"carol", "alice"} {
			body := `{"model":"gpt-4o-2024-alpha2","id":"fixture","commands":{"search_query":[{"q":"fixture"}]}}`
			resp, b := e.do("POST", "/v1/"+path, e.tok[client], body)
			if resp.StatusCode != 403 || errCode(t, b) != "model_not_allowed" {
				t.Errorf("%s %s: %d %s", client, path, resp.StatusCode, b)
			}
		}
	}
	for _, path := range []string{"images/edits", "audio/transcriptions", "audio/translations", "chat/completions"} {
		body, ct := upload(t, []string{"gpt-daybreak-red-latest"}, false, false)
		resp, b := e.do("POST", "/v1/"+path, e.tok["carol"], body, "Content-Type", ct)
		if resp.StatusCode != 403 || errCode(t, b) != "model_not_allowed" {
			t.Errorf("multipart %s: %d %s", path, resp.StatusCode, b)
		}
	}
	for _, tc := range []struct {
		body string
		want int
	}{
		{"mod%65l=gpt-4o-exp2026", 403},
		{"model=gpt-4o&model=gpt-4o-test", 400},
		{"model=%zz", 400},
	} {
		resp, b := e.do("POST", "/v1/chat/completions", e.tok["carol"], tc.body, "Content-Type", "application/x-www-form-urlencoded")
		if resp.StatusCode != tc.want {
			t.Errorf("form %q: %d %s", tc.body, resp.StatusCode, b)
		}
	}
	for _, body := range []string{
		`{"model":"gpt-4o","tools":[{"type":"image_generation","model":"gpt-image-1-preview"}]}`,
		`{"model":"gpt-4o","tools":[{"type":"image_generation","mod\u0065l":"gpt-image-1-exp"}]}`,
		`{"model":"gpt-4o","tools":[{"type":"image_generation","model":"gpt-image-1-mini","model":"gpt-image-1-test"}]}`,
		`{"model":"gpt-4o","tools":[],"tools":[{"type":"image_generation","model":"gpt-image-1-alpha"}]}`,
	} {
		resp, _ := e.do("POST", "/v1/responses", e.tok["carol"], body)
		if resp.StatusCode != 400 && resp.StatusCode != 403 {
			t.Errorf("tool override accepted: %d", resp.StatusCode)
		}
	}
	for _, tc := range []struct{ method, path string }{
		{"GET", "/v1/models/gpt-daybreak-red-latest"},
		{"GET", "/v1/models/gpt-4o-preview"},
		{"GET", "/v1/models?model=gpt-4o&mod%65l=gpt-4o-beta"},
		{"GET", "/v1/responses/resp_fixture?model=gpt-4o-test"},
		{"DELETE", "/v1/responses/resp_fixture?model=gpt-4o-experiment"},
		{"POST", "/v1/messages?beta=true&model=gpt-4o-alpha"},
	} {
		resp, _ := e.do(tc.method, tc.path, e.tok["carol"], "")
		if resp.StatusCode != 403 && resp.StatusCode != 404 {
			t.Errorf("%s %s: %d", tc.method, tc.path, resp.StatusCode)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("excluded selectors reached upstream %d times", calls.Load())
	}
	// Markers in user content and endpoint/header names are not model IDs.
	for _, tc := range []struct{ path, body, ct string }{
		{"/v1/responses", `{"model":"fixture-latest","input":"test alpha beta exp daybreak","metadata":{"model":"experiment"}}`, "application/json"},
		{"/v1/messages?beta=true", `{"model":"gpt-4o","messages":[]}`, "application/json"},
		{"/v1/alpha/search", `{"model":"gpt-4o","id":"fixture","commands":{"search_query":[{"q":"daybreak beta test"}]}}`, "application/json"},
		{"/v1/chat/completions", "model=fixture-latest&input=daybreak", "application/x-www-form-urlencoded"},
		{"/v1/responses", `{"model":"gpt-4o","tools":[{"type":"image_generation","model":"gpt-image-1-mini"},{"type":"function","name":"test","parameters":{"type":"object","properties":{"model":{"const":"daybreak"}}}}]}`, "application/json"},
	} {
		resp, b := e.do("POST", tc.path, e.tok["carol"], tc.body, "Content-Type", tc.ct, "OpenAI-Beta", "fixture=v1")
		if resp.StatusCode != 200 {
			t.Errorf("stable %s: %d %s", tc.path, resp.StatusCode, b)
		}
	}
	// Client allowlists still govern the main model, not eligible hosted tools.
	resp, b := e.do("POST", "/v1/responses", e.tok["alice"], `{"model":"gpt-4o","tools":[{"type":"image_generation","model":"gpt-image-1-mini"}]}`)
	if resp.StatusCode != 200 {
		t.Errorf("eligible tool outside client allowlist: %d %s", resp.StatusCode, b)
	}
	if calls.Load() != 6 {
		t.Errorf("stable requests dispatched %d times, want 6", calls.Load())
	}
}

func TestModelExclusionsOpenAILive(t *testing.T) {
	if os.Getenv("SHELLBENCH_OPENAI_LIVE") != "1" {
		t.Skip("opt-in OpenAI model policy proof")
	}
	key := os.Getenv("OPENAI_API_KEY")
	if key == "" {
		t.Fatal("OPENAI_API_KEY required")
	}
	e := newEnv(t, http.NotFoundHandler(), func(o *Options) {
		o.Upstream, _ = url.Parse("https://api.openai.com/v1")
		o.Key, o.MaxRetries, o.UpstreamTimeout = staticKey(key), 0, time.Minute
	})
	resp, b := e.do("GET", "/v1/models", e.tok["carol"], "")
	var doc struct{ Data []struct{ ID string } }
	if resp.StatusCode != 200 || json.Unmarshal(b, &doc) != nil || len(doc.Data) == 0 {
		t.Fatalf("live catalog failed: HTTP %d (body withheld)", resp.StatusCode)
	}
	for _, model := range doc.Data {
		if !tokens.ModelEligible(model.ID) {
			t.Fatal("excluded model in live catalog (ID withheld)")
		}
	}
	if strings.Contains(string(b), key) {
		t.Fatal("upstream credential appeared in catalog")
	}
	resp, b = e.do("POST", "/v1/responses", e.tok["carol"], `{"model":"gpt-6.1-sol","input":"Reply with OK.","reasoning":{"effort":"low"},"max_output_tokens":64,"store":false}`)
	var result struct{ Status string }
	if resp.StatusCode != 200 || json.Unmarshal(b, &result) != nil || result.Status != "completed" {
		t.Fatalf("stable live request failed: HTTP %d (body withheld)", resp.StatusCode)
	}
	if strings.Contains(string(b), key) || strings.Contains(e.logs.String(), key) || strings.Contains(e.access.String(), key) {
		t.Fatal("upstream credential appeared in response or logs")
	}
	t.Logf("eligible live catalog models: %d; stable Responses call completed", len(doc.Data))
}

func TestRetiredAndCyberSelectorsNeverDispatch(t *testing.T) {
	var calls atomic.Int64
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(200)
	}), nil)
	for _, model := range []string{"gpt-4", "gpt-image-1", "openai/ft:o1:org:custom:123", "gpt-5.6-CyBeR", "cybermodel"} {
		for _, client := range []string{"alice", "carol"} {
			for _, tc := range []struct{ method, path, body, ct string }{
				{"POST", "/v1/responses", fmt.Sprintf(`{"model":%q}`, model), "application/json"},
				{"POST", "/v1/responses", fmt.Sprintf(`{"model":"gpt-4o","tools":[{"type":"image_generation","model":%q}]}`, model), "application/json"},
				{"POST", "/v1/chat/completions", "model=" + url.QueryEscape(model), "application/x-www-form-urlencoded"},
				{"GET", "/v1/models/" + url.PathEscape(model), "", ""},
				{"GET", "/v1/responses/resp_fixture?model=" + url.QueryEscape(model), "", ""},
				{"DELETE", "/v1/responses/resp_fixture?model=" + url.QueryEscape(model), "", ""},
				{"POST", "/v1/messages?model=" + url.QueryEscape(model), "", ""},
			} {
				resp, _ := e.do(tc.method, tc.path, e.tok[client], tc.body, "Content-Type", tc.ct)
				if resp.StatusCode != 403 && resp.StatusCode != 404 {
					t.Errorf("%s %s %s %s: %d", client, model, tc.method, tc.path, resp.StatusCode)
				}
			}
			body, ct := upload(t, []string{model}, false, false)
			resp, _ := e.do("POST", "/v1/images/edits", e.tok[client], body, "Content-Type", ct)
			if resp.StatusCode != 403 {
				t.Errorf("%s multipart %s: %d", client, model, resp.StatusCode)
			}
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("excluded selectors reached upstream %d times", calls.Load())
	}
}

func TestExcludedModelDetailAlias(t *testing.T) {
	for _, model := range []string{"gpt-4o-preview", "gpt-4", "gpt-5.6-cyber"} {
		e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"id":%q,"object":"model"}`, model)
		}), nil)
		resp, b := e.do("GET", "/v1/models/alias", e.tok["carol"], "")
		if resp.StatusCode != 404 || errCode(t, b) != "model_not_found" || strings.Contains(string(b), model) {
			t.Fatalf("excluded canonical model leaked: %d %s", resp.StatusCode, b)
		}
	}
}

func TestExcludedModelsHiddenFromCatalog(t *testing.T) {
	data := `[ {"id":"gpt-4o","object":"model","created":123}, {"id":"fixture-latest"}`
	for _, marker := range []string{"alpha", "beta", "test", "exp", "experiment", "experimental", "preview", "daybreak"} {
		data += fmt.Sprintf(`,{"id":"gpt-4o-%s"}`, marker)
	}
	for _, model := range []string{"gpt-4", "gpt-image-1", "gpt-5.6-CyBeR", "cybermodel"} {
		data += fmt.Sprintf(`,{"id":%q}`, model)
	}
	data += `]`
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"object":"list","metadata":"fixture","data":`+data+`}`)
	}), nil)
	for _, tc := range []struct{ client, want string }{{"carol", "gpt-4o,fixture-latest"}, {"alice", "gpt-4o"}} {
		resp, b := e.do("GET", "/v1/models", e.tok[tc.client], "")
		var doc struct {
			Object, Metadata string
			Data             []struct {
				ID      string
				Created int
			}
		}
		if resp.StatusCode != 200 || json.Unmarshal(b, &doc) != nil {
			t.Fatalf("catalog failed: %d %s", resp.StatusCode, b)
		}
		var ids []string
		for _, model := range doc.Data {
			ids = append(ids, model.ID)
		}
		if strings.Join(ids, ",") != tc.want || doc.Object != "list" || doc.Metadata != "fixture" || doc.Data[0].Created != 123 {
			t.Errorf("%s catalog changed: %s", tc.client, b)
		}
	}
}

func TestResolvedModelDetailUsesClientAllowlist(t *testing.T) {
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"id":"gpt-4o-mini","object":"model"}`)
	}), nil)
	for _, tc := range []struct {
		client string
		status int
	}{{"alice", 404}, {"carol", 200}} {
		resp, b := e.do("GET", "/v1/models/gpt-4o", e.tok[tc.client], "")
		if resp.StatusCode != tc.status || tc.status == 404 && strings.Contains(string(b), "gpt-4o-mini") {
			t.Errorf("%s canonical detail: %d %s", tc.client, resp.StatusCode, b)
		}
	}
}

func TestModelDiscoveryCannotCacheSharedRepresentations(t *testing.T) {
	for _, status := range []int{200, 404} {
		e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Trailer", "ETag, Last-Modified, Location, Content-Location, Cache-Control")
			w.Header().Set("Cache-Control", "public, max-age=3600")
			for _, h := range []string{"ETag", "Last-Modified", "Location", "Content-Location"} {
				w.Header().Set(h, "hidden-model-fixture")
			}
			w.WriteHeader(status)
			if strings.HasSuffix(r.URL.Path, "/models") {
				io.WriteString(w, `{"object":"list","data":[{"id":"gpt-4o"},{"id":"gpt-4o-mini"}]}`)
			} else {
				io.WriteString(w, `{"id":"gpt-4o","object":"model"}`)
			}
			w.(http.Flusher).Flush()
			for _, h := range []string{"ETag", "Last-Modified", "Location", "Content-Location", "Cache-Control"} {
				w.Header().Set(h, "late-hidden-model-fixture")
			}
		}), nil)
		for _, path := range []string{"/v1/models", "/v1/models/gpt-4o"} {
			resp, _ := e.do("GET", path, e.tok["alice"], "")
			if resp.StatusCode != status || resp.Header.Get("Cache-Control") != "private, no-store" {
				t.Errorf("%s status/cache: %d %q", path, resp.StatusCode, resp.Header.Get("Cache-Control"))
			}
			for _, h := range []string{"ETag", "Last-Modified", "Location", "Content-Location"} {
				if resp.Header.Get(h) != "" || resp.Trailer.Get(h) != "" {
					t.Errorf("%s exposed %s", path, h)
				}
			}
			if resp.Trailer.Get("Cache-Control") != "" {
				t.Errorf("%s exposed upstream cache policy in trailers", path)
			}
		}
	}
}
