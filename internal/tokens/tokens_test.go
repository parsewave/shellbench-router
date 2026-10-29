package tokens

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAddAuthenticateRotate(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := &File{Version: 1}
	tok, err := f.Add(Client{ID: "alice", Models: []string{"gpt-4o"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, Prefix) || len(tok) != len(Prefix)+43 {
		t.Fatalf("token format: %q", tok)
	}
	if strings.Contains(f.Clients[0].Secrets[0].SHA256, tok) {
		t.Fatal("plaintext stored")
	}
	s := NewStore(f)
	p, err := s.Authenticate(tok, now)
	if err != nil || p.ID != "alice" || !p.AllowsModel("gpt-4o") || p.AllowsModel("o3") {
		t.Fatalf("auth: %v %+v", err, p)
	}
	if _, err := s.Authenticate(tok+"x", now); err != ErrInvalid {
		t.Fatalf("want ErrInvalid, got %v", err)
	}

	// Rotation with grace: both valid until the grace period ends.
	tok2, err := f.Rotate("alice", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	s = NewStore(f)
	for _, tk := range []string{tok, tok2} {
		if _, err := s.Authenticate(tk, now.Add(30*time.Minute)); err != nil {
			t.Errorf("during grace: %v", err)
		}
	}
	if _, err := s.Authenticate(tok, now.Add(2*time.Hour)); err != ErrExpired {
		t.Errorf("old token after grace: %v", err)
	}
	if _, err := s.Authenticate(tok2, now.Add(2*time.Hour)); err != nil {
		t.Errorf("new token after grace: %v", err)
	}

	// Rotation without grace revokes immediately.
	tok3, _ := f.Rotate("alice", 0, now)
	s = NewStore(f)
	if _, err := s.Authenticate(tok2, now); err != ErrInvalid {
		t.Errorf("immediate rotate: old token %v", err)
	}
	if _, err := s.Authenticate(tok3, now); err != nil {
		t.Errorf("immediate rotate: new token %v", err)
	}

	f.Find("alice").Disabled = true
	if _, err := NewStore(f).Authenticate(tok3, now); err != ErrRevoked {
		t.Errorf("revoked: %v", err)
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	f := &File{Version: 1}
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if _, err := f.Add(Client{ID: "bob", RPM: 10, MaxConcurrent: 2, ExpiresAt: &exp, Models: []string{"gpt-4o-*"}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, f); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	g, err := Read(path)
	if err != nil || g.Clients[0].RPM != 10 || !g.Clients[0].ExpiresAt.Equal(exp) {
		t.Fatalf("roundtrip: %v %+v", err, g)
	}
}

func TestValidate(t *testing.T) {
	bad := []File{
		{Version: 2},
		{Version: 1, Clients: []Client{{ID: "bad id"}}},
		{Version: 1, Clients: []Client{{ID: "a"}, {ID: "a"}}},
		{Version: 1, Clients: []Client{{ID: "a", RPM: -1}}},
		{Version: 1, Clients: []Client{{ID: "a", Models: []string{"gp*t"}}}},
		{Version: 1, Clients: []Client{{ID: "a", Secrets: []Secret{{SHA256: "zz"}}}}},
	}
	for i, f := range bad {
		if f.Validate() == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	path := filepath.Join(t.TempDir(), "t.json")
	os.WriteFile(path, []byte(`{"version":1,"clients":[],"typo":true}`), 0o600)
	if _, err := Read(path); err == nil {
		t.Error("unknown field accepted")
	}
}

func TestModelPatterns(t *testing.T) {
	p := &Principal{Models: []string{"gpt-4o", "o3-*"}}
	for m, want := range map[string]bool{"gpt-4o": true, "gpt-4o-mini": false, "GPT-4O": false, "o3-2025-04-16": true, "o3": false, "": false} {
		if p.AllowsModel(m) != want {
			t.Errorf("%q: want %v", m, want)
		}
	}
	if !(&Principal{Models: []string{"*"}}).AllowsModel("anything") {
		t.Error("* should allow all")
	}
}

func TestExcludedModelLabels(t *testing.T) {
	for _, marker := range []string{"alpha", "beta", "test", "testing", "exp", "experiment", "experimental", "preview", "daybreak"} {
		for _, delimiter := range []string{"-", "_", ".", ":", "/"} {
			model := "provider/model" + delimiter + strings.ToUpper(marker) + "2-latest"
			for _, patterns := range [][]string{nil, {"*"}, {model}, {"provider/*"}} {
				if (&Principal{Models: patterns}).AllowsModel(model) {
					t.Errorf("excluded %q allowed by %v", model, patterns)
				}
			}
		}
		if ModelEligible(marker) {
			t.Errorf("bare marker %q allowed", marker)
		}
	}
	for _, model := range []string{"fixture-latest", "gpt-6.1-sol", "gpt-image-1-mini", "text-embedding-3-small", "whisper-1", "alphafold", "contest", "expanse", "snapshot-2026-10-01"} {
		if !(&Principal{}).AllowsModel(model) {
			t.Errorf("stable model %q excluded", model)
		}
	}
}
