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
		{"/v1/responses", `{"model":"chatgpt-4o-latest","input":"test alpha beta exp daybreak","metadata":{"model":"experiment"}}`, "application/json"},
		{"/v1/messages?beta=true", `{"model":"gpt-4o","messages":[]}`, "application/json"},
		{"/v1/alpha/search", `{"model":"gpt-4o","id":"fixture","commands":{"search_query":[{"q":"daybreak beta test"}]}}`, "application/json"},
		{"/v1/chat/completions", "model=chatgpt-4o-latest&input=daybreak", "application/x-www-form-urlencoded"},
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

func TestExcludedModelDetailAlias(t *testing.T) {
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"id":"gpt-4o-preview","object":"model"}`)
	}), nil)
	resp, b := e.do("GET", "/v1/models/alias", e.tok["carol"], "")
	if resp.StatusCode != 404 || errCode(t, b) != "model_not_found" || strings.Contains(string(b), "gpt-4o-preview") {
		t.Fatalf("excluded canonical model leaked: %d %s", resp.StatusCode, b)
	}
}

func TestExcludedModelsHiddenFromCatalog(t *testing.T) {
	data := `[ {"id":"gpt-4o","object":"model","created":123}, {"id":"chatgpt-4o-latest"}`
	for _, marker := range []string{"alpha", "beta", "test", "exp", "experiment", "experimental", "preview", "daybreak"} {
		data += fmt.Sprintf(`,{"id":"gpt-4o-%s"}`, marker)
	}
	data += `]`
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"object":"list","metadata":"fixture","data":`+data+`}`)
	}), nil)
	for _, tc := range []struct{ client, want string }{{"carol", "gpt-4o,chatgpt-4o-latest"}, {"alice", "gpt-4o"}} {
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
