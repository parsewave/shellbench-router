package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

const decisionFixture = `{"model":"gpt-6-luna","input":"The sky is blue.","questions":[{"type":"predicate","name":"blue","instructions":"Does the text say the sky is blue?"}]}`

func TestDecisionsForwardingAndModelPolicy(t *testing.T) {
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/v1/decisions" || r.Header.Get("Authorization") != "Bearer "+upstreamKey || string(body) != decisionFixture {
			t.Error("decision dispatch changed")
		}
		io.WriteString(w, `{"answers":[{"type":"predicate","name":"blue","probability":0.99}]}`)
	}), nil)
	resp, b := e.do("POST", "/v1/decisions", e.tok["carol"], decisionFixture)
	if resp.StatusCode != 200 || !bytes.Contains(b, []byte(`"probability":0.99`)) {
		t.Fatal("decision not forwarded")
	}
	resp, _ = e.do("POST", "/v1/decisions", e.tok["alice"], decisionFixture)
	if resp.StatusCode != 403 {
		t.Fatal("decision bypassed model restriction")
	}
}

func TestDecisionsOpenAILive(t *testing.T) {
	if os.Getenv("SHELLBENCH_OPENAI_LIVE") != "1" {
		t.Skip("opt-in billable OpenAI proof")
	}
	key := os.Getenv("OPENAI_API_KEY")
	if key == "" {
		t.Fatal("OPENAI_API_KEY required")
	}
	e := newEnv(t, http.NotFoundHandler(), func(o *Options) {
		o.Upstream, _ = url.Parse("https://api.openai.com/v1")
		o.Key, o.MaxRetries, o.UpstreamTimeout = staticKey(key), 0, time.Minute
	})
	resp, b := e.do("POST", "/v1/decisions", e.tok["carol"], decisionFixture)
	if resp.StatusCode != 200 {
		t.Fatalf("live decision status %d (body withheld)", resp.StatusCode)
	}
	var doc struct {
		Answers []struct {
			Name        string
			Probability float64
		}
	}
	if json.Unmarshal(b, &doc) != nil || len(doc.Answers) != 1 || doc.Answers[0].Name != "blue" || doc.Answers[0].Probability < 0.5 {
		t.Fatal("missing expected predicate answer")
	}
	for _, output := range [][]byte{b, []byte(e.logs.String()), []byte(e.access.String())} {
		if bytes.Contains(output, []byte(key)) {
			t.Fatal("credential appeared in decision output or logs")
		}
	}
}
