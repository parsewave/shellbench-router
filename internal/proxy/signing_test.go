package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"oaiproxy/internal/signing"
	"oaiproxy/internal/tokens"
)

type signEnv struct {
	*testEnv
	priv, other ed25519.PrivateKey
	sam, carol  string // sam must sign; carol has no keys

	mu       sync.Mutex
	upHeader http.Header
	upCalls  int
}

func newSignEnv(t *testing.T, mutate func(*tokens.File, ed25519.PublicKey)) *signEnv {
	t.Helper()
	se := &signEnv{}
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		se.mu.Lock()
		se.upHeader, se.upCalls = r.Header.Clone(), se.upCalls+1
		se.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"object":"list","data":[{"id":"gpt-4o","object":"model"}]}`))
	}), nil)
	se.testEnv = e
	_, se.priv, _ = ed25519.GenerateKey(rand.Reader)
	_, se.other, _ = ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	f := &tokens.File{Version: 1}
	se.sam, _ = f.Add(tokens.Client{ID: "sam"}, now)
	se.carol, _ = f.Add(tokens.Client{ID: "carol"}, now)
	pub := se.priv.Public().(ed25519.PublicKey)
	if _, err := f.AddKey("sam", tokens.FormatPublicKey(pub), "", nil, now); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(f, pub)
	}
	e.p.SetStore(tokens.NewStore(f))
	return se
}

func nonce() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// signed sends a request signed with priv; tweak may alter the request
// after signing.
func (se *signEnv) signed(priv ed25519.PrivateKey, method, path, token, body string, at time.Time, n string, tweak func(*http.Request)) (*http.Response, []byte) {
	se.t.Helper()
	u, _ := url.Parse(se.srv.URL)
	ts, sig := signing.Sign(priv, method, u.Host, path, []byte(body), at, n)
	hdr := []string{signing.HeaderTimestamp, ts, signing.HeaderNonce, n, signing.HeaderSignature, sig}
	r := se.req(se.t.Context(), method, path, token, body, hdr...)
	if tweak != nil {
		tweak(r)
	}
	resp, err := noRedirect.Do(r)
	if err != nil {
		se.t.Fatal(err)
	}
	b := readAll(resp)
	return resp, b
}

func readAll(resp *http.Response) []byte {
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

const chatBody = `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`

func TestSignedRequestAccepted(t *testing.T) {
	se := newSignEnv(t, nil)
	resp, b := se.signed(se.priv, "POST", "/v1/chat/completions", se.sam, chatBody, time.Now(), nonce(), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	// GET with an empty body, and a query string covered by the signature.
	resp, b = se.signed(se.priv, "GET", "/v1/models", se.sam, "", time.Now(), nonce(), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("GET status %d: %s", resp.StatusCode, b)
	}
	se.mu.Lock()
	defer se.mu.Unlock()
	for k := range se.upHeader {
		if strings.HasPrefix(strings.ToLower(k), "x-px-") {
			t.Errorf("signature header %s forwarded upstream", k)
		}
	}
	waitFor(t, "key_id in log", func() bool { return strings.Contains(se.logs.String(), `"key_id":"k_`) })
}

func TestSignedRequestRejected(t *testing.T) {
	se := newSignEnv(t, nil)
	now := time.Now()
	cases := []struct {
		name string
		send func() (*http.Response, []byte)
		code string
	}{
		{"unsigned", func() (*http.Response, []byte) {
			return se.do("POST", "/v1/chat/completions", se.sam, chatBody)
		}, "signature_required"},
		{"wrong key", func() (*http.Response, []byte) {
			return se.signed(se.other, "POST", "/v1/chat/completions", se.sam, chatBody, now, nonce(), nil)
		}, "invalid_signature"},
		{"stale", func() (*http.Response, []byte) {
			return se.signed(se.priv, "POST", "/v1/chat/completions", se.sam, chatBody, now.Add(-5*time.Minute), nonce(), nil)
		}, "signature_expired"},
		{"future", func() (*http.Response, []byte) {
			return se.signed(se.priv, "POST", "/v1/chat/completions", se.sam, chatBody, now.Add(5*time.Minute), nonce(), nil)
		}, "signature_expired"},
		{"bad nonce", func() (*http.Response, []byte) {
			return se.signed(se.priv, "POST", "/v1/chat/completions", se.sam, chatBody, now, "x", nil)
		}, "malformed_signature"},
		{"body swapped", func() (*http.Response, []byte) {
			return se.signed(se.priv, "POST", "/v1/chat/completions", se.sam, chatBody, now, nonce(), func(r *http.Request) {
				b := strings.Replace(chatBody, "hi", "ho", 1)
				r.Body, r.ContentLength = nopCloser{strings.NewReader(b)}, int64(len(b))
			})
		}, "invalid_signature"},
		{"path swapped", func() (*http.Response, []byte) {
			return se.signed(se.priv, "POST", "/v1/chat/completions", se.sam, chatBody, now, nonce(), func(r *http.Request) {
				r.URL.Path = "/v1/responses"
			})
		}, "invalid_signature"},
		{"query added", func() (*http.Response, []byte) {
			return se.signed(se.priv, "GET", "/v1/models", se.sam, "", now, nonce(), func(r *http.Request) {
				r.URL.RawQuery = "limit=1"
			})
		}, "invalid_signature"},
		{"host swapped", func() (*http.Response, []byte) {
			return se.signed(se.priv, "GET", "/v1/models", se.sam, "", now, nonce(), func(r *http.Request) {
				r.Host = "evil.example"
			})
		}, "invalid_signature"},
	}
	for _, c := range cases {
		resp, b := c.send()
		if resp.StatusCode != http.StatusUnauthorized || errCode(t, b) != c.code {
			t.Errorf("%s: %d %s, want 401 %s", c.name, resp.StatusCode, b, c.code)
		}
	}
	se.mu.Lock()
	defer se.mu.Unlock()
	if se.upCalls != 0 {
		t.Fatalf("%d rejected requests reached upstream", se.upCalls)
	}
}

func TestSignedRequestReplay(t *testing.T) {
	se := newSignEnv(t, nil)
	n, now := nonce(), time.Now()
	if resp, b := se.signed(se.priv, "POST", "/v1/chat/completions", se.sam, chatBody, now, n, nil); resp.StatusCode != 200 {
		t.Fatalf("first: %d %s", resp.StatusCode, b)
	}
	resp, b := se.signed(se.priv, "POST", "/v1/chat/completions", se.sam, chatBody, now, n, nil)
	if resp.StatusCode != 401 || errCode(t, b) != "signature_replayed" {
		t.Fatalf("replay: %d %s", resp.StatusCode, b)
	}
}

// A valid signature is bound to its client: it can't be paired with another
// client's token, and unsigned clients are unaffected.
func TestSignatureBoundToClient(t *testing.T) {
	se := newSignEnv(t, nil)
	if resp, b := se.do("POST", "/v1/chat/completions", se.carol, chatBody); resp.StatusCode != 200 {
		t.Fatalf("unsigned client: %d %s", resp.StatusCode, b)
	}
	// carol has no keys, so signature headers are simply ignored for her.
	if resp, b := se.signed(se.other, "POST", "/v1/chat/completions", se.carol, chatBody, time.Now(), nonce(), nil); resp.StatusCode != 200 {
		t.Fatalf("unsigned client with stray headers: %d %s", resp.StatusCode, b)
	}
	// Leaked private key without sam's token is useless.
	resp, b := se.signed(se.priv, "POST", "/v1/chat/completions", "sk-px-guessed", chatBody, time.Now(), nonce(), nil)
	if resp.StatusCode != 401 || errCode(t, b) != "invalid_api_key" {
		t.Fatalf("key without token: %d %s", resp.StatusCode, b)
	}
}

func TestExpiredSigningKey(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	se := newSignEnv(t, func(f *tokens.File, _ ed25519.PublicKey) {
		f.Find("sam").PublicKeys[0].ExpiresAt = &past
	})
	resp, b := se.signed(se.priv, "POST", "/v1/chat/completions", se.sam, chatBody, time.Now(), nonce(), nil)
	if resp.StatusCode != 401 || errCode(t, b) != "invalid_signature" {
		t.Fatalf("expired key: %d %s", resp.StatusCode, b)
	}
}

type nopCloser struct{ *strings.Reader }

func (nopCloser) Close() error { return nil }
