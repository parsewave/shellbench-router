package main

import (
	"bytes"
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

func TestAllowIPs(t *testing.T) {
	file := t.TempDir() + "/tokens.json"
	if _, _, err := run(t, "add", "-file", file, "-id", "a", "-allow-ips", "1.2.3.4,nope"); err == nil {
		t.Fatal("invalid -allow-ips accepted")
	}
	tok, msg, err := run(t, "add", "-file", file, "-id", "a", "-allow-ips", "203.0.113.7, 10.0.0.0/8")
	if err != nil || !strings.HasPrefix(tok, tokens.Prefix) || strings.Contains(msg, "any IP") {
		t.Fatalf("add: %q %q %v", tok, msg, err)
	}
	if _, msg, _ := run(t, "add", "-file", file, "-id", "b"); !strings.Contains(msg, "any IP") {
		t.Fatalf("no hint for unrestricted token: %q", msg)
	}
	list, _, _ := run(t, "list", "-file", file)
	if !strings.Contains(list, "203.0.113.7,10.0.0.0/8") || !strings.Contains(list, "any") {
		t.Fatalf("list:\n%s", list)
	}
	if _, _, err := run(t, "set", "-file", file, "-id", "a", "-allow-ips", "*"); err != nil {
		t.Fatal(err)
	}
	f, _ := tokens.Read(file)
	if c := f.Find("a"); len(c.AllowedIPs) != 0 {
		t.Fatalf("allowlist not cleared: %v", c.AllowedIPs)
	}
}
