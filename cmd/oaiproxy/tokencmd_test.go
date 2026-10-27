package main

import (
	"bytes"
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oaiproxy/internal/tokens"
)

func run(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	err := tokenCmd(args, &out, &errb, time.Now())
	return out.String(), errb.String(), err
}

func TestAddIsSignedByDefault(t *testing.T) {
	file := filepath.Join(t.TempDir(), "tokens.json")
	if _, _, err := run(t, "add", "-file", file, "-id", "alice"); err != errSignedDefault {
		t.Fatalf("add without key: %v", err)
	}
	pub := tokens.FormatPublicKey(ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey))
	if _, _, err := run(t, "add", "-file", file, "-id", "x", "-pubkey", pub, "-unsigned"); err == nil {
		t.Fatal("-pubkey with -unsigned accepted")
	}
	tok, _, err := run(t, "add", "-file", file, "-id", "alice", "-pubkey", pub, "-concurrency", "4")
	if err != nil || !strings.HasPrefix(tok, tokens.Prefix) {
		t.Fatalf("signed add: %q %v", tok, err)
	}
	tok2, msg, err := run(t, "add", "-file", file, "-id", "bot", "-unsigned")
	if err != nil || !strings.HasPrefix(tok2, tokens.Prefix) || !strings.Contains(msg, "Unsigned") {
		t.Fatalf("unsigned add: %q %q %v", tok2, msg, err)
	}
	f, _ := tokens.Read(file)
	s := tokens.NewStore(f)
	pa, _ := s.Authenticate(strings.TrimSpace(tok), time.Now())
	pb, _ := s.Authenticate(strings.TrimSpace(tok2), time.Now())
	if !pa.SignatureRequired() || pb.SignatureRequired() {
		t.Fatalf("alice signed=%v bot signed=%v", pa.SignatureRequired(), pb.SignatureRequired())
	}
	list, _, _ := run(t, "list", "-file", file)
	if !strings.Contains(list, "k_") || !strings.Contains(list, "(unsigned)") {
		t.Fatalf("list:\n%s", list)
	}
}
