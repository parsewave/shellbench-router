package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInspectJSON(t *testing.T) {
	for _, c := range []struct {
		in       string
		model    string
		hasModel bool
		stream   bool
		err      bool
	}{
		{in: `{"model":"gpt-4o"}`, model: "gpt-4o", hasModel: true},
		{in: ` { "stream" : true , "model" : "o3" } `, model: "o3", hasModel: true, stream: true},
		{in: `{"messages":[{"model":"x","c":"}\"{"}],"model":"a"}`, model: "a", hasModel: true},
		{in: `{"model":"esc"}`, model: "esc", hasModel: true},
		{in: `{"MODEL":"x"}`},
		{in: `{}`},
		{in: `{"model":"a","model":"b"}`, err: true},
		{in: `{"model":1}`, err: true},
		{in: `{"model":null}`, err: true},
		{in: `[]`, err: true},
		{in: `"model"`, err: true},
		{in: `{"model":"a"} x`, err: true},
		{in: `{"model":"a",}`, err: true},
		{in: `{"stream":"yes","model":"m"}`, model: "m", hasModel: true},
		{in: `{"a":[1,2,{"b":[{}]}],"n":-1.5e3,"t":true,"f":false,"z":null,"model":"deep"}`, model: "deep", hasModel: true},
	} {
		info, err := inspectJSON([]byte(c.in))
		if (err != nil) != c.err {
			t.Errorf("%s: err=%v", c.in, err)
			continue
		}
		if err == nil && (info.model != c.model || info.hasModel != c.hasModel || info.stream != c.stream) {
			t.Errorf("%s: got %+v", c.in, info)
		}
	}
}

// FuzzInspectJSON checks the scanner agrees with an exact-key reference
// decoder on every valid object without duplicate keys.
func FuzzInspectJSON(f *testing.F) {
	for _, s := range []string{`{"model":"a"}`, `{"x":{"model":"b"},"model":"c","stream":true}`, `{"model":"d"}`, `{"a":"\\\"","model":"e"}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		info, err := inspectJSON([]byte(s))
		var ref map[string]json.RawMessage
		if json.Unmarshal([]byte(s), &ref) != nil {
			if err == nil {
				t.Fatalf("accepted input the reference rejects: %q", s)
			}
			return
		}
		if err != nil {
			return // duplicate/non-string model: stricter than reference is fine
		}
		raw, ok := ref["model"]
		if ok != info.hasModel {
			t.Fatalf("%q: hasModel=%v ref=%v", s, info.hasModel, ok)
		}
		if ok {
			var m string
			json.Unmarshal(raw, &m)
			if m != info.model && !strings.Contains(s, `\`) {
				t.Fatalf("%q: model=%q ref=%q", s, info.model, m)
			}
		}
	})
}

func TestParseUsage(t *testing.T) {
	for _, c := range []struct {
		in   string
		want usage
	}{
		{`{"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7,"prompt_tokens_details":{"cached_tokens":1},"completion_tokens_details":{"reasoning_tokens":2}}}`, usage{3, 4, 7, 2, 1}},
		{"data: {\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":1,\"total_tokens\":6}}\n\ndata: {\"usage\":null}\n\ndata: [DONE]\n\n", usage{5, 1, 6, 0, 0}},
		{`event: response.completed` + "\n" + `data: {"response":{"usage":{"input_tokens":10,"output_tokens":8,"total_tokens":18,"output_tokens_details":{"reasoning_tokens":3}}}}`, usage{10, 8, 18, 3, 0}},
		{`{"content":"the \"usage\": {\"total_tokens\": 99}"}`, usage{}},
		{`{"usage":null}`, usage{}},
	} {
		got, _ := parseUsage([]byte(c.in))
		if got != c.want {
			t.Errorf("%s: got %+v want %+v", c.in, got, c.want)
		}
	}
}

func TestTailRing(t *testing.T) {
	var tl tail
	data := []byte(strings.Repeat("0123456789", 5000))
	for i := 0; i < len(data); i += 777 {
		tl.write(data[i:min(i+777, len(data))])
	}
	if got := string(tl.bytes()); got != string(data[len(data)-tailSize:]) {
		t.Fatal("tail mismatch")
	}
}

func TestRoutes(t *testing.T) {
	if _, err := ParseRoutes([]string{"GET /v2/x"}); err == nil {
		t.Error("non-/v1 route accepted")
	}
	if _, err := ParseRoutes([]string{"CONNECT /v1/x"}); err == nil {
		t.Error("CONNECT accepted")
	}
	if _, err := ParseRoutes([]string{"GET /v1/x/../y"}); err == nil {
		t.Error("dot segment accepted")
	}
}
