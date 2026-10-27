package admin

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"oaiproxy/internal/tokens"
)

const adminKey = "sk-pxadmin-0123456789abcdefghijklmnopqrstuv"

type staticKey string

func (k staticKey) Get() string { return string(k) }

type env struct {
	t       *testing.T
	srv     *httptest.Server
	file    string
	reloads atomic.Int32
	logs    *bytes.Buffer
}

func newEnv(t *testing.T, key string) *env {
	e := &env{t: t, file: filepath.Join(t.TempDir(), "tokens.json"), logs: &bytes.Buffer{}}
	s := &Server{
		TokensFile: e.file, Key: staticKey(key), Reload: func() { e.reloads.Add(1) },
		Log: slog.New(slog.NewJSONHandler(e.logs, nil)),
	}
	e.srv = httptest.NewServer(s)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) call(method, path, key, body string) (int, map[string]any) {
	e.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if key != "" {
		r.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		e.t.Errorf("%s %s: Cache-Control %q", method, path, cc)
	}
	b, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(bytes.TrimSpace(b)) > 0 {
		if err := json.Unmarshal(b, &out); err != nil {
			e.t.Fatalf("%s %s: non-JSON body %q", method, path, b)
		}
	}
	return resp.StatusCode, out
}

func errorCode(m map[string]any) string {
	e, _ := m["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

func (e *env) authenticate(tok string) (*tokens.Principal, error) {
	f, err := tokens.Read(e.file)
	if err != nil {
		e.t.Fatal(err)
	}
	return tokens.NewStore(f).Authenticate(tok, time.Now())
}

func pubKey(seed byte) string {
	s := make([]byte, ed25519.SeedSize)
	s[0] = seed
	return tokens.FormatPublicKey(ed25519.NewKeyFromSeed(s).Public().(ed25519.PublicKey))
}

func TestDisabledAndAuth(t *testing.T) {
	off := newEnv(t, "")
	if st, out := off.call("GET", "/admin/clients", adminKey, ""); st != 404 || errorCode(out) != "unknown_url" {
		t.Fatalf("disabled: %d %v", st, out)
	}
	e := newEnv(t, adminKey)
	for _, key := range []string{"", "wrong", adminKey + "x", "sk-px-something"} {
		if st, out := e.call("GET", "/admin/clients", key, ""); st != 401 || errorCode(out) != "invalid_admin_key" {
			t.Errorf("key %q: %d %v", key, st, out)
		}
	}
	// Auth comes before routing, so unknown paths don't reveal the API shape.
	if st, _ := e.call("GET", "/admin/nope", "", ""); st != 401 {
		t.Errorf("unauthenticated unknown path: %d", st)
	}
	if st, _ := e.call("GET", "/admin/nope", adminKey, ""); st != 404 {
		t.Errorf("unknown path: %d", st)
	}
	if st, out := e.call("GET", "/admin/clients", adminKey, ""); st != 200 || len(out["clients"].([]any)) != 0 {
		t.Fatalf("empty list: %d %v", st, out)
	}
	if strings.Contains(e.logs.String(), adminKey) {
		t.Fatal("admin key logged")
	}
}

func TestClientLifecycle(t *testing.T) {
	e := newEnv(t, adminKey)
	st, out := e.call("POST", "/admin/clients", adminKey, `{"id":"alice","models":["gpt-4o","o3*"],"rpm":600,"max_concurrent":32,"expires":"90d","note":"bench"}`)
	if st != 201 {
		t.Fatalf("create: %d %v", st, out)
	}
	tok, _ := out["token"].(string)
	if !strings.HasPrefix(tok, tokens.Prefix) {
		t.Fatalf("token %q", tok)
	}
	if strings.Contains(e.logs.String(), tok) {
		t.Fatal("token logged")
	}
	c := out["client"].(map[string]any)
	if c["status"] != "active" || c["max_concurrent"].(float64) != 32 || c["signature_required"] != false {
		t.Fatalf("client view %v", c)
	}
	p, err := e.authenticate(tok)
	if err != nil || p.ID != "alice" || !p.AllowsModel("o3-mini") || p.AllowsModel("gpt-4o-mini") {
		t.Fatalf("authenticate: %+v %v", p, err)
	}
	if e.reloads.Load() == 0 {
		t.Fatal("no reload after create")
	}

	if st, out := e.call("POST", "/admin/clients", adminKey, `{"id":"alice"}`); st != 409 || errorCode(out) != "already_exists" {
		t.Fatalf("duplicate: %d %v", st, out)
	}
	if st, out := e.call("GET", "/admin/clients/alice", adminKey, ""); st != 200 || out["id"] != "alice" {
		t.Fatalf("get: %d %v", st, out)
	}
	if st, out := e.call("GET", "/admin/clients/bob", adminKey, ""); st != 404 || errorCode(out) != "not_found" {
		t.Fatalf("get missing: %d %v", st, out)
	}

	// PATCH changes only the given fields; ["*"] means all models.
	st, out = e.call("PATCH", "/admin/clients/alice", adminKey, `{"models":["*"],"rpm":1200,"expires":"never"}`)
	if st != 200 || len(out["models"].([]any)) != 0 || out["rpm"].(float64) != 1200 || out["max_concurrent"].(float64) != 32 || out["expires_at"] != nil {
		t.Fatalf("patch: %d %v", st, out)
	}
	if st, out := e.call("PATCH", "/admin/clients/alice", adminKey, `{"rpm":-1}`); st != 400 {
		t.Fatalf("invalid patch: %d %v", st, out)
	}

	st, out = e.call("POST", "/admin/clients/alice/rotate", adminKey, `{"grace":"1h"}`)
	if st != 200 {
		t.Fatalf("rotate: %d %v", st, out)
	}
	tok2 := out["token"].(string)
	if _, err := e.authenticate(tok); err != nil {
		t.Fatalf("old token should survive the grace period: %v", err)
	}
	if _, err := e.authenticate(tok2); err != nil {
		t.Fatal(err)
	}

	if st, out := e.call("POST", "/admin/clients/alice/revoke", adminKey, ""); st != 200 || out["status"] != "revoked" {
		t.Fatalf("revoke: %d %v", st, out)
	}
	if _, err := e.authenticate(tok2); err != tokens.ErrRevoked {
		t.Fatalf("revoked token: %v", err)
	}
	if st, out := e.call("POST", "/admin/clients/alice/enable", adminKey, ""); st != 200 || out["status"] != "active" {
		t.Fatalf("enable: %d %v", st, out)
	}

	if st, _ := e.call("DELETE", "/admin/clients/alice", adminKey, ""); st != 204 {
		t.Fatalf("delete: %d", st)
	}
	if st, _ := e.call("DELETE", "/admin/clients/alice", adminKey, ""); st != 404 {
		t.Fatalf("delete again: %d", st)
	}
	if !strings.Contains(e.logs.String(), `"action":"rotate"`) {
		t.Fatal("no audit log")
	}
}

func TestSigningKeys(t *testing.T) {
	e := newEnv(t, adminKey)
	// Keys can be registered at creation time.
	st, out := e.call("POST", "/admin/clients", adminKey, `{"id":"sam","max_concurrent":4,"public_keys":[{"public_key":"`+pubKey(1)+`","note":"ci"}]}`)
	if st != 201 || out["client"].(map[string]any)["signature_required"] != true {
		t.Fatalf("create with key: %d %v", st, out)
	}
	p, _ := e.authenticate(out["token"].(string))
	if !p.SignatureRequired() {
		t.Fatal("principal does not require signature")
	}
	k1 := out["client"].(map[string]any)["public_keys"].([]any)[0].(map[string]any)["id"].(string)

	st, out = e.call("POST", "/admin/clients/sam/keys", adminKey, `{"public_key":"`+pubKey(2)+`","expires":"30d"}`)
	if st != 201 {
		t.Fatalf("add key: %d %v", st, out)
	}
	k2 := out["key"].(map[string]any)["id"].(string)
	if st, out := e.call("POST", "/admin/clients/sam/keys", adminKey, `{"public_key":"`+pubKey(2)+`"}`); st != 409 {
		t.Fatalf("duplicate key: %d %v", st, out)
	}
	if st, out := e.call("POST", "/admin/clients/sam/keys", adminKey, `{"public_key":"ed25519:AAAA"}`); st != 400 {
		t.Fatalf("bad key: %d %v", st, out)
	}

	if st, _ := e.call("DELETE", "/admin/clients/sam/keys/"+k1, adminKey, ""); st != 204 {
		t.Fatalf("remove key: %d", st)
	}
	if st, out := e.call("DELETE", "/admin/clients/sam/keys/"+k2, adminKey, ""); st != 409 || errorCode(out) != "last_signing_key" {
		t.Fatalf("remove last key: %d %v", st, out)
	}
	if st, _ := e.call("DELETE", "/admin/clients/sam/keys/"+k2+"?allow_unsigned=true", adminKey, ""); st != 204 {
		t.Fatalf("remove last key with allow_unsigned: %d", st)
	}
	if st, out := e.call("GET", "/admin/clients/sam", adminKey, ""); out["signature_required"] != false {
		t.Fatalf("after removing keys: %d %v", st, out)
	}
}

func TestBadRequests(t *testing.T) {
	e := newEnv(t, adminKey)
	cases := []struct{ method, path, body, code string }{
		{"POST", "/admin/clients", `{"id":"bad id"}`, "invalid_request"},
		{"POST", "/admin/clients", `{"id":"a","unknown":1}`, "invalid_json"},
		{"POST", "/admin/clients", `{"id":"a","expires":"soon"}`, "invalid_request"},
		{"POST", "/admin/clients", `{"id":"a","models":["has space"]}`, "invalid_request"},
		{"POST", "/admin/clients", `not json`, "invalid_json"},
		{"POST", "/admin/clients", `{"id":"a","public_keys":[{"public_key":"nope"}]}`, "invalid_request"},
		{"POST", "/admin/clients", `{"id":"a","x":"` + strings.Repeat("a", 70<<10) + `"}`, "request_too_large"},
		{"POST", "/admin/clients/nobody/rotate", ``, "not_found"},
		{"PATCH", "/admin/clients/nobody", `{}`, "not_found"},
	}
	for _, c := range cases {
		st, out := e.call(c.method, c.path, adminKey, c.body)
		if errorCode(out) != c.code || st < 400 {
			t.Errorf("%s %s %.40s: %d %v, want %s", c.method, c.path, c.body, st, out, c.code)
		}
	}
	// Failed creates must not leave a half-created client behind.
	if _, err := os.Stat(e.file); err == nil {
		f, _ := tokens.Read(e.file)
		if len(f.Clients) != 0 {
			t.Fatalf("clients after failed requests: %+v", f.Clients)
		}
	}
	for _, p := range []string{"/admin//clients", "/admin/clients/../clients", "/admin/clients/a%2Fb"} {
		if st, _ := e.call("GET", p, adminKey, ""); st != 404 {
			t.Errorf("unclean path %s: %d", p, st)
		}
	}
}
