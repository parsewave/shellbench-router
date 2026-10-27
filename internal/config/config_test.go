package config

import "testing"

func TestParseHeaders(t *testing.T) {
	h, err := ParseHeaders(" HTTP-Referer=https://example.com/app ; X-Title=My Bench ;")
	if err != nil || h.Get("Http-Referer") != "https://example.com/app" || h.Get("X-Title") != "My Bench" {
		t.Fatalf("got %v %v", h, err)
	}
	for _, bad := range []string{"Authorization=Bearer x", "openai-project=p", "noequals", "Bad Name=x", "X-A=a\nb"} {
		if _, err := ParseHeaders(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseUpstream(t *testing.T) {
	if u, err := ParseUpstream("https://openrouter.ai/api/v1/", false); err != nil || u.Path != "/api/v1" {
		t.Errorf("openrouter: %v %v", u, err)
	}
	for _, bad := range []string{"http://x/v1", "https://user:pw@x/v1", "https://x/v1?k=1", "/v1"} {
		if _, err := ParseUpstream(bad, false); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := ParseUpstream("http://127.0.0.1:9/v1", true); err != nil {
		t.Errorf("insecure local: %v", err)
	}
}
