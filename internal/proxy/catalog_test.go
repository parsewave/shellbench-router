package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

type catalogTransport func(*http.Request) (*http.Response, error)

func (f catalogTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func catalogResponse(r *http.Request, body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r, ContentLength: int64(len(body))}
}

func TestCodexCatalogUsesProviderMetadataAndClientPolicy(t *testing.T) {
	for _, tc := range []struct{ client, want string }{{"alice", "gpt-4o"}, {"carol", "gpt-4o,gpt-image-1-mini"}} {
		e := newEnv(t, http.NotFoundHandler(), func(o *Options) {
			o.Upstream, _ = url.Parse("https://api.openai.com/v1")
			o.Organization, o.Project = "org-fixture", "proj_fixture"
			o.ExtraHeaders = http.Header{"X-Operator-Secret": {"fixture"}}
			o.Transport = catalogTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != "https://chatgpt.com/backend-api/codex/models?client_version=0.165.0" || r.Header.Get("Authorization") != "Bearer "+upstreamKey {
					t.Error("catalog destination/auth changed")
				}
				for _, h := range []string{"Cookie", "OpenAI-Organization", "OpenAI-Project", "ChatGPT-Account-ID", "X-Operator-Secret", "X-Codex-Turn-State"} {
					if r.Header.Get(h) != "" {
						t.Errorf("catalog forwarded %s", h)
					}
				}
				return catalogResponse(r, `{"models":[{"slug":"gpt-4o","supported_in_api":true,"base_instructions":"preserve beta/test wording","extra":{"untouched":true}},{"slug":"gpt-image-1-mini","supported_in_api":true},{"slug":"gpt-4","supported_in_api":true},{"slug":"gpt-5.6-cyber","supported_in_api":true},{"slug":"gpt-4o-alpha","supported_in_api":true},{"slug":"internal-only","supported_in_api":false}],"metadata":"preserved"}`), nil
			})
		})
		resp, b := e.do("GET", "/v1/models?client_version=0.165.0", e.tok[tc.client], "", "Cookie", "fixture", "ChatGPT-Account-ID", "fixture", "X-Codex-Turn-State", "fixture")
		var doc struct {
			Metadata string
			Models   []struct {
				Slug             string
				BaseInstructions string `json:"base_instructions"`
				Extra            struct{ Untouched bool }
			}
		}
		if resp.StatusCode != 200 || json.Unmarshal(b, &doc) != nil || len(doc.Models) == 0 {
			t.Fatalf("native catalog failed: %d %s", resp.StatusCode, b)
		}
		var ids []string
		for _, m := range doc.Models {
			ids = append(ids, m.Slug)
		}
		if strings.Join(ids, ",") != tc.want || doc.Metadata != "preserved" || doc.Models[0].BaseInstructions != "preserve beta/test wording" || !doc.Models[0].Extra.Untouched {
			t.Errorf("native metadata/policy changed: %s", b)
		}
		if !strings.Contains(resp.Header.Get("Cache-Control"), "no-store") {
			t.Error("native catalog is cacheable")
		}
	}
}

func TestCodexCatalogKeepsCustomProviderOrigin(t *testing.T) {
	e := newEnv(t, http.NotFoundHandler(), func(o *Options) {
		o.Upstream, _ = url.Parse("https://gateway.example/v1")
		o.Transport = catalogTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() != "https://gateway.example/v1/models?client_version=0.165.0" {
				t.Error("custom provider credential crossed origins")
			}
			return catalogResponse(r, `{"models":[{"slug":"gpt-4o","supported_in_api":true}]}`), nil
		})
	})
	resp, _ := e.do("GET", "/v1/models?client_version=0.165.0", e.tok["carol"], "")
	if resp.StatusCode != 200 {
		t.Errorf("custom native catalog: %d", resp.StatusCode)
	}
}

func TestInvalidCodexCatalogVersionNeverDispatches(t *testing.T) {
	var calls atomic.Int64
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }), nil)
	for _, query := range []string{"client_version=", "client_version=latest", "client_version=0.165", "client_version=0.165.0-alpha.1", "client_version=0.165.0&client_version=0.164.0"} {
		resp, _ := e.do("GET", "/v1/models?"+query, e.tok["carol"], "")
		if resp.StatusCode != 400 {
			t.Errorf("invalid version %q: %d", query, resp.StatusCode)
		}
	}
	if calls.Load() != 0 {
		t.Error("invalid version reached upstream")
	}
}

func TestCodexCatalogOriginIsExact(t *testing.T) {
	for _, raw := range []string{"https://api.openai.com:443/v1", "https://api.openai.com.example/v1", "http://api.openai.com/v1", "https://api.openai.com/custom", "https://user@api.openai.com/v1", "https://api.openai.com/v1?key=fixture"} {
		u, err := url.Parse(raw)
		if err != nil || openAICatalogUpstream(u) {
			t.Errorf("unexpected cross-origin catalog for %s", raw)
		}
	}
}

func TestMalformedCodexCatalogFailsClosed(t *testing.T) {
	for _, body := range []string{
		`{"data":[]}`, `{"models":null}`, `{"models":[{}]}`, `{"models":[{"slug":123}]}`,
		`{"models":[{"slug":"gpt-4o","supported_in_api":true},{"slug":"gpt-4o","supported_in_api":true}]}`,
		`{"models":[]}` + strings.Repeat(" ", 1<<20),
	} {
		e := newEnv(t, http.NotFoundHandler(), func(o *Options) {
			o.Transport = catalogTransport(func(r *http.Request) (*http.Response, error) { return catalogResponse(r, body), nil })
		})
		resp, _ := e.do("GET", "/v1/models?client_version=0.165.0", e.tok["carol"], "")
		if resp.StatusCode != 502 {
			t.Errorf("malformed native catalog accepted: %d", resp.StatusCode)
		}
		if !strings.Contains(resp.Header.Get("Cache-Control"), "no-store") {
			t.Error("native catalog error is cacheable")
		}
	}
}
