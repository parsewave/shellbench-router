package proxy

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"oaiproxy/internal/tokens"
)

func allowlistEnv(t *testing.T, mutate func(*Options)) (*testEnv, string) {
	t.Helper()
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"object":"list","data":[]}`))
	}), mutate)
	f := &tokens.File{Version: 1}
	tok, err := f.Add(tokens.Client{ID: "ci", AllowedIPs: []string{"203.0.113.7", "10.0.0.0/8"}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e.p.SetStore(tokens.NewStore(f))
	return e, tok
}

func TestIPAllowlist(t *testing.T) {
	e, tok := allowlistEnv(t, nil) // test client connects from 127.0.0.1, a trusted proxy
	cases := []struct {
		name string
		xff  []string
		want int
	}{
		{"allowed host", []string{"203.0.113.7"}, 200},
		{"allowed range", []string{"10.9.8.7"}, 200},
		{"other ip", []string{"198.51.100.1"}, 403},
		{"no xff: peer itself", nil, 403},
		// The proxy in front appends the real address last; whatever the
		// client wrote before it is ignored.
		{"spoofed first entry", []string{"203.0.113.7, 198.51.100.1"}, 403},
		{"spoofed earlier header", []string{"203.0.113.7", "198.51.100.1"}, 403},
		{"real last entry", []string{"198.51.100.1, 203.0.113.7"}, 200},
		{"garbage", []string{"not-an-ip"}, 403},
	}
	for _, c := range cases {
		r := e.req(t.Context(), "GET", "/v1/models", tok, "")
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		resp, err := noRedirect.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		b := readBody(resp)
		if resp.StatusCode != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, resp.StatusCode, b, c.want)
		}
		if c.want == 403 && errCode(t, b) != "ip_not_allowed" {
			t.Errorf("%s: code %s", c.name, errCode(t, b))
		}
	}
	// Unknown tokens get 401, not 403: the allowlist reveals nothing to them.
	if resp, _ := e.do("GET", "/v1/models", "sk-px-nope", "", "X-Forwarded-For", "198.51.100.1"); resp.StatusCode != 401 {
		t.Errorf("unknown token: %d", resp.StatusCode)
	}
	waitFor(t, "client_ip in access log", func() bool { return strings.Contains(e.access.String(), `"client_ip":"198.51.100.1"`) })
}

// X-Forwarded-For from an untrusted peer is ignored entirely.
func TestIPAllowlistUntrustedPeer(t *testing.T) {
	e, tok := allowlistEnv(t, func(o *Options) { o.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")} })
	resp, b := e.do("GET", "/v1/models", tok, "", "X-Forwarded-For", "203.0.113.7")
	if resp.StatusCode != 403 || !strings.Contains(string(b), "127.0.0.1") {
		t.Fatalf("untrusted peer with forged XFF: %d %s", resp.StatusCode, b)
	}
}

func readBody(resp *http.Response) []byte {
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			return []byte(sb.String())
		}
	}
}
