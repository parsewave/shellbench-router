package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"testing"
	"time"
)

// Shared with clients/python/tests: seed 00 01 .. 1f, so any client
// implementation can check it produces byte-identical signatures.
const (
	vectorPub = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="
	vectorMsg = "PX-ED25519-V1\nPOST\nproxy.example.com\n/v1/responses?x=1\n1793093230\nnonce-0123456789abcdef\nafdd3df91505360960ddc9dc239b4cd1b771d5d990e5881599da557d56dc8677"
	vectorSig = "9hfW4A5m7JaiWesAubRjlGDYJCH5BZv7IL-DNT4T-IL0kFbgCMsvJKN1z1zrGpleMoFzwPKqHFfQjnODwQ9JDg"
)

func vectorKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestVector(t *testing.T) {
	priv := vectorKey()
	if got := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)); got != vectorPub {
		t.Fatalf("public key %s, want %s", got, vectorPub)
	}
	body := []byte(`{"model":"gpt-4o","input":"hi"}`)
	sum := sha256.Sum256(body)
	msg := StringToSign("post", "Proxy.Example.com", "/v1/responses?x=1", 1793093230, "nonce-0123456789abcdef", sum[:])
	if string(msg) != vectorMsg {
		t.Fatalf("string to sign:\n%q\nwant\n%q", msg, vectorMsg)
	}
	ts, sig := Sign(priv, "POST", "proxy.example.com", "/v1/responses?x=1", body, time.Unix(1793093230, 0), "nonce-0123456789abcdef")
	if ts != "1793093230" || sig != vectorSig {
		t.Fatalf("Sign = %s %s, want %s", ts, sig, vectorSig)
	}
}

func TestParseHeaders(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	good := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	nonce := "abcdefghijklmnop"
	cases := []struct {
		name, ts, nonce, sig string
		want                 error
	}{
		{"none", "", "", "", ErrMissing},
		{"ok", ts, nonce, good, nil},
		{"std base64 padded", ts, nonce, base64.StdEncoding.EncodeToString(make([]byte, 64)), nil},
		{"missing sig", ts, nonce, "", ErrMalformed},
		{"short nonce", ts, "short", good, ErrMalformed},
		{"bad nonce chars", ts, "abcdefghijklmnop!", good, ErrMalformed},
		{"bad ts", "12x", nonce, good, ErrMalformed},
		{"short sig", ts, nonce, base64.RawURLEncoding.EncodeToString(make([]byte, 63)), ErrMalformed},
		{"too old", strconv.FormatInt(now.Add(-3*time.Minute).Unix(), 10), nonce, good, ErrStale},
		{"too new", strconv.FormatInt(now.Add(3*time.Minute).Unix(), 10), nonce, good, ErrStale},
		{"edge of window", strconv.FormatInt(now.Add(-2*time.Minute).Unix(), 10), nonce, good, nil},
	}
	for _, c := range cases {
		_, err := ParseHeaders(c.ts, c.nonce, c.sig, now, 2*time.Minute)
		if err != c.want {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

func TestVerify(t *testing.T) {
	now := time.Now()
	priv := vectorKey()
	other := ed25519.NewKeyFromSeed(make([]byte, 32))
	past := now.Add(-time.Second)
	body := []byte("{}")
	ts, sig := Sign(priv, "POST", "h", "/v1/x", body, now, "abcdefghijklmnop")
	h, err := ParseHeaders(ts, "abcdefghijklmnop", sig, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	msg := StringToSign("POST", "h", "/v1/x", h.Timestamp, h.Nonce, sum[:])
	pub := priv.Public().(ed25519.PublicKey)
	opub := other.Public().(ed25519.PublicKey)

	if id, err := Verify([]Key{{ID: "o", Pub: opub}, {ID: "k", Pub: pub}}, h, msg, now); err != nil || id != "k" {
		t.Fatalf("Verify = %q, %v", id, err)
	}
	if _, err := Verify([]Key{{ID: "o", Pub: opub}}, h, msg, now); err != ErrInvalid {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := Verify([]Key{{ID: "k", Pub: pub, ExpiresAt: &past}}, h, msg, now); err != ErrInvalid {
		t.Fatalf("expired key: %v", err)
	}
	for _, tampered := range [][]byte{
		StringToSign("POST", "h", "/v1/y", h.Timestamp, h.Nonce, sum[:]),
		StringToSign("POST", "other-host", "/v1/x", h.Timestamp, h.Nonce, sum[:]),
		StringToSign("POST", "h", "/v1/x", h.Timestamp+1, h.Nonce, sum[:]),
		StringToSign("POST", "h", "/v1/x", h.Timestamp, "abcdefghijklmnoq", sum[:]),
		StringToSign("PUT", "h", "/v1/x", h.Timestamp, h.Nonce, sum[:]),
		StringToSign("POST", "h", "/v1/x", h.Timestamp, h.Nonce, make([]byte, 32)),
	} {
		if _, err := Verify([]Key{{ID: "k", Pub: pub}}, h, tampered, now); err != ErrInvalid {
			t.Errorf("tampered %q verified", tampered)
		}
	}
}

func TestNonceCache(t *testing.T) {
	now := time.Now()
	c := NewNonceCache(time.Minute, 3)
	if err := c.Use("a", "n1", now); err != nil {
		t.Fatal(err)
	}
	if err := c.Use("a", "n1", now.Add(time.Second)); err != ErrReplayed {
		t.Fatalf("replay: %v", err)
	}
	if err := c.Use("b", "n1", now); err != nil {
		t.Fatalf("same nonce, other client: %v", err)
	}
	if err := c.Use("a", "n2", now); err != nil {
		t.Fatal(err)
	}
	if err := c.Use("a", "n3", now); err != ErrBusy {
		t.Fatalf("full cache: %v", err)
	}
	// Entries expire after 2x skew and are swept.
	later := now.Add(2*time.Minute + time.Second)
	if err := c.Use("a", "n1", later); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
	if err := c.Use("a", "n3", later); err != nil {
		t.Fatalf("after sweep: %v", err)
	}
}
