package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	imagepkg "image"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Opt-in, billable proof against OpenAI. Inject the key into this process;
// never put it in a fixture, command argument, test failure, or saved response.
func TestOpenAILive(t *testing.T) {
	if os.Getenv("SHELLBENCH_OPENAI_LIVE") != "1" {
		t.Skip("set SHELLBENCH_OPENAI_LIVE=1 and inject OPENAI_API_KEY")
	}
	key := strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
	if key == "" {
		t.Fatal("OPENAI_API_KEY is required")
	}
	e := newEnv(t, http.NotFoundHandler(), func(o *Options) {
		o.Upstream, _ = url.Parse("https://api.openai.com/v1")
		o.Key = staticKey(key)
		o.MaxRetries = 0
		o.UpstreamTimeout = 3 * time.Minute
	})
	client := &http.Client{Timeout: 3 * time.Minute, CheckRedirect: noRedirect.CheckRedirect}
	call := func(t *testing.T, path, ct string, body []byte) []byte {
		t.Helper()
		r := e.req(context.Background(), "POST", "/v1/"+path, e.tok["carol"], string(body), "Content-Type", ct)
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal("live request failed before response")
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal("live response interrupted")
		}
		if bytes.Contains(b, []byte(key)) || strings.Contains(fmt.Sprint(resp.Header, resp.Trailer), key) {
			t.Fatal("upstream key appeared in response")
		}
		if resp.StatusCode != 200 {
			var doc struct {
				Error struct {
					Code json.RawMessage `json:"code"`
				} `json:"error"`
			}
			json.Unmarshal(b, &doc)
			t.Log(string(e.p.scrub([]byte(e.logs.String()))))
			t.Fatalf("POST %s: status %d code %s (response body withheld)", path, resp.StatusCode, e.p.scrub(doc.Error.Code))
		}
		return b
	}
	var image, audio []byte
	t.Run("hosted_web_search", func(t *testing.T) {
		b := call(t, "responses", "application/json", []byte(`{"model":"gpt-4.1-mini","tools":[{"type":"web_search"}],"tool_choice":"required","max_output_tokens":256,"input":"Search for the official OpenAI website and give its URL.","store":false}`))
		if !bytes.Contains(b, []byte(`"web_search_call"`)) || !bytes.Contains(b, []byte(`"url_citation"`)) {
			t.Fatal("no actual web search/citation output")
		}
	})
	t.Run("image_generation", func(t *testing.T) {
		b := call(t, "images/generations", "application/json", []byte(`{"model":"gpt-image-1-mini","prompt":"A solid blue square.","size":"1024x1024","quality":"low","n":1}`))
		var doc struct {
			Data []struct {
				Base64 string `json:"b64_json"`
			} `json:"data"`
		}
		if json.Unmarshal(b, &doc) != nil || len(doc.Data) != 1 {
			t.Fatal("invalid image response")
		}
		var err error
		image, err = base64.StdEncoding.DecodeString(doc.Data[0].Base64)
		if err != nil {
			t.Fatal("invalid generated image encoding")
		}
		requireLiveImage(t, image)
	})
	t.Run("image_edit", func(t *testing.T) {
		if len(image) == 0 {
			var fixture bytes.Buffer
			if err := png.Encode(&fixture, imagepkg.NewRGBA(imagepkg.Rect(0, 0, 1024, 1024))); err != nil {
				t.Fatal("cannot encode image fixture")
			}
			image = fixture.Bytes()
		}
		var body bytes.Buffer
		w := multipart.NewWriter(&body)
		w.WriteField("model", "gpt-image-1-mini")
		w.WriteField("prompt", "Make the square green.")
		w.WriteField("quality", "low")
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", `form-data; name="image"; filename="fixture.png"`)
		h.Set("Content-Type", "image/png")
		part, err := w.CreatePart(h)
		if err != nil {
			t.Fatal("cannot create image upload")
		}
		part.Write(image)
		w.Close()
		b := call(t, "images/edits", w.FormDataContentType(), body.Bytes())
		var doc struct {
			Data []struct {
				Base64 string `json:"b64_json"`
			}
		}
		if json.Unmarshal(b, &doc) != nil || len(doc.Data) != 1 {
			t.Fatal("invalid edited image response")
		}
		edited, err := base64.StdEncoding.DecodeString(doc.Data[0].Base64)
		if err != nil {
			t.Fatal("invalid edited image encoding")
		}
		requireLiveImage(t, edited)
	})
	t.Run("speech", func(t *testing.T) {
		audio = call(t, "audio/speech", "application/json", []byte(`{"model":"gpt-4o-mini-tts","input":"Hello, this is a routing test.","voice":"alloy","response_format":"wav"}`))
		if !bytes.HasPrefix(audio, []byte("RIFF")) {
			t.Fatal("missing WAV audio")
		}
	})
	for _, endpoint := range []string{"transcriptions", "translations"} {
		t.Run(endpoint, func(t *testing.T) {
			if len(audio) == 0 {
				t.Skip("speech prerequisite failed")
			}
			var body bytes.Buffer
			w := multipart.NewWriter(&body)
			w.WriteField("model", "whisper-1")
			part, err := w.CreateFormFile("file", "fixture.wav")
			if err != nil {
				t.Fatal("cannot create audio upload")
			}
			part.Write(audio)
			w.Close()
			b := call(t, "audio/"+endpoint, w.FormDataContentType(), body.Bytes())
			var doc struct {
				Text string `json:"text"`
			}
			if json.Unmarshal(b, &doc) != nil || !strings.Contains(strings.ToLower(doc.Text), "hello") {
				t.Fatal("missing recognized speech")
			}
		})
	}
	t.Run("embeddings", func(t *testing.T) {
		b := call(t, "embeddings", "application/json", []byte(`{"model":"text-embedding-3-small","input":"routing test","dimensions":8}`))
		var doc struct {
			Data []struct {
				Embedding []float64 `json:"embedding"`
			} `json:"data"`
		}
		if json.Unmarshal(b, &doc) != nil || len(doc.Data) != 1 || len(doc.Data[0].Embedding) != 8 {
			t.Fatal("missing embedding")
		}
	})
	if strings.Contains(e.logs.String(), key) || strings.Contains(e.access.String(), key) {
		t.Fatal("upstream key appeared in proxy logs")
	}
}

// The server gets the provider key; the isolated native client receives only
// its proxy token. Use an explicit standalone binary, never a login wrapper.
func TestNativeCodexOpenAILive(t *testing.T) {
	if os.Getenv("SHELLBENCH_OPENAI_LIVE") != "1" || os.Getenv("SHELLBENCH_CODEX_BIN") == "" {
		t.Skip("opt-in native Codex proof requires SHELLBENCH_CODEX_BIN")
	}
	key := os.Getenv("OPENAI_API_KEY")
	if key == "" {
		t.Fatal("OPENAI_API_KEY required")
	}
	proof := &nativeProofTransport{base: NewTransport()}
	e := newEnv(t, http.NotFoundHandler(), func(o *Options) {
		o.Upstream, _ = url.Parse("https://api.openai.com/v1")
		o.Key, o.MaxRetries, o.UpstreamTimeout = staticKey(key), 0, 3*time.Minute
		o.Transport = proof
	})
	home := t.TempDir()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	args := []string{}
	for _, setting := range []string{
		`features.plugins=false`, `features.standalone_web_search=true`, `model_provider="shellbench"`, `model="gpt-6.1-sol"`,
		`model_providers.shellbench.name="OpenAI"`,
		`model_providers.shellbench.base_url=` + strconv.Quote(e.srv.URL+"/v1"),
		`model_providers.shellbench.env_key="SHELLBENCH_PROXY_TOKEN"`,
		`model_providers.shellbench.wire_api="responses"`,
		`model_providers.shellbench.requires_openai_auth=false`,
		`model_providers.shellbench.supports_websockets=false`,
		`web_search="live"`, `model_reasoning_effort="low"`,
		`shell_environment_policy.inherit="none"`,
	} {
		args = append(args, "-c", setting)
	}
	args = append(args, "exec", "--json", "--skip-git-repo-check", "--sandbox", "read-only",
		"Use web.run to search for the official OpenAI homepage, open a returned reference, then give one sentence with its source URL. Do not run local commands.")
	cmd := exec.CommandContext(ctx, os.Getenv("SHELLBENCH_CODEX_BIN"), args...)
	cmd.Dir = home
	cmd.Env = []string{"HOME=" + home, "CODEX_HOME=" + home, "PATH=" + os.Getenv("PATH"), "SHELLBENCH_PROXY_TOKEN=" + e.tok["carol"]}
	out := &liveOutput{}
	cmd.Stdout, cmd.Stderr = out, out
	err := cmd.Run()
	if bytes.Contains(out.data, []byte(key)) || strings.Contains(e.logs.String(), key) || strings.Contains(e.access.String(), key) {
		t.Fatal("provider credential appeared in native client output or logs")
	}
	if err != nil {
		t.Fatal("isolated native Codex failed (output withheld)")
	}
	if !bytes.Contains(out.data, []byte(`"turn.completed"`)) || !bytes.Contains(out.data, []byte("openai.com")) {
		t.Fatal("native Codex did not complete with the requested source")
	}
	paths := map[string]int{}
	for _, line := range strings.Split(e.access.String(), "\n") {
		var rec struct {
			Path   string
			Status int
			Error  string
		}
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec.Status != 200 || rec.Error != "" {
			t.Fatalf("native request %s status %d code %s (body withheld)", rec.Path, rec.Status, rec.Error)
		}
		paths[rec.Path]++
	}
	if paths["/v1/responses"] == 0 || paths["/v1/alpha/search"] < 2 {
		t.Fatal("native Codex did not successfully exercise Responses and search/open")
	}
	if proof.searches.Load() == 0 || proof.opens.Load() == 0 {
		t.Fatal("native client did not successfully search and open a reference")
	}

}

type liveOutput struct{ data []byte }

func (b *liveOutput) Write(p []byte) (int, error) {
	if len(b.data)+len(p) > 1<<20 {
		return 0, fmt.Errorf("native fixture output exceeded 1 MiB")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func requireLiveImage(t *testing.T, b []byte) {
	t.Helper()
	info, err := png.DecodeConfig(bytes.NewReader(b))
	if err != nil || info.Width <= 0 || info.Height <= 0 {
		t.Fatal("missing valid PNG image dimensions")
	}
}

// Codex emits "other" for reference opens (only literal URLs get an open_page
// action). Record command categories at dispatch instead, without retaining
// prompts, result text, references or credentials.
type nativeProofTransport struct {
	base            http.RoundTripper
	searches, opens atomic.Int64
}

func (rt *nativeProofTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	var searches, opens int64
	if r.URL.Path == "/v1/alpha/search" && r.GetBody != nil {
		body, err := r.GetBody()
		if err == nil {
			var doc struct {
				Commands struct {
					SearchQuery []json.RawMessage `json:"search_query"`
					Open        []struct {
						RefID string `json:"ref_id"`
					}
				}
			}
			if json.NewDecoder(body).Decode(&doc) == nil {
				searches = int64(len(doc.Commands.SearchQuery))
				for _, op := range doc.Commands.Open {
					if strings.HasPrefix(op.RefID, "turn") {
						opens++
					}
				}
			}
			body.Close()
		}
	}
	resp, err := rt.base.RoundTrip(r)
	if err == nil && resp.StatusCode == 200 {
		rt.searches.Add(searches)
		rt.opens.Add(opens)
	}
	return resp, err
}
