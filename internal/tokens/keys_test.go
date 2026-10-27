package tokens

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newPub(t *testing.T, seed byte) ed25519.PublicKey {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	s[0] = seed
	return ed25519.NewKeyFromSeed(s).Public().(ed25519.PublicKey)
}

func TestParsePublicKey(t *testing.T) {
	pub := newPub(t, 1)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	for _, in := range []string{
		FormatPublicKey(pub),
		base64.StdEncoding.EncodeToString(pub),
		base64.RawURLEncoding.EncodeToString(pub),
		"  " + FormatPublicKey(pub) + "\n",
		pemKey,
	} {
		got, err := ParsePublicKey(in)
		if err != nil || !got.Equal(pub) {
			t.Errorf("ParsePublicKey(%q) = %x, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "ed25519:", "ed25519:AAAA", "not base64 !!", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"} {
		if _, err := ParsePublicKey(in); err == nil {
			t.Errorf("ParsePublicKey(%q) succeeded", in)
		}
	}
}

func TestAddRemoveKey(t *testing.T) {
	now := time.Now()
	f := &File{Version: 1}
	for _, id := range []string{"a", "b"} {
		if _, err := f.Add(Client{ID: id}, now); err != nil {
			t.Fatal(err)
		}
	}
	k1, err := f.AddKey("a", FormatPublicKey(newPub(t, 1)), "laptop", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if k1.ID != KeyID(newPub(t, 1)) || k1.Note != "laptop" {
		t.Fatalf("key = %+v", k1)
	}
	if _, err := f.AddKey("a", FormatPublicKey(newPub(t, 1)), "", nil, now); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate key: %v", err)
	}
	if _, err := f.AddKey("nobody", FormatPublicKey(newPub(t, 2)), "", nil, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown client: %v", err)
	}
	// The same key may not be shared by two clients.
	g := *f
	g.Clients = append([]Client(nil), f.Clients...)
	if _, err := g.AddKey("b", FormatPublicKey(newPub(t, 1)), "", nil, now); err == nil {
		t.Fatal("key shared across clients accepted")
	}

	k2, err := f.AddKey("a", FormatPublicKey(newPub(t, 2)), "", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.RemoveKey("a", k1.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := f.RemoveKey("a", k2.ID, false); !errors.Is(err, ErrLastKey) {
		t.Fatalf("last key removed without allowUnsigned: %v", err)
	}
	if err := f.RemoveKey("a", k2.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := f.RemoveKey("a", k2.ID, true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing key: %v", err)
	}
}

func TestValidateKeys(t *testing.T) {
	now := time.Now()
	pub := newPub(t, 3)
	ok := PublicKey{ID: KeyID(pub), Key: FormatPublicKey(pub), CreatedAt: now}
	bad := []PublicKey{
		{ID: "k_000000000000", Key: ok.Key, CreatedAt: now},
		{ID: ok.ID, Key: "ed25519:AAAA", CreatedAt: now},
	}
	for _, k := range bad {
		f := &File{Version: 1, Clients: []Client{{ID: "a", PublicKeys: []PublicKey{k}}}}
		if err := f.Validate(); err == nil {
			t.Errorf("accepted %+v", k)
		}
	}
	many := make([]PublicKey, MaxPublicKeys+1)
	for i := range many {
		p := newPub(t, byte(10+i))
		many[i] = PublicKey{ID: KeyID(p), Key: FormatPublicKey(p), CreatedAt: now}
	}
	if err := (&File{Version: 1, Clients: []Client{{ID: "a", PublicKeys: many}}}).Validate(); err == nil {
		t.Error("accepted too many keys")
	}
}

func TestStoreSignatureRequired(t *testing.T) {
	now := time.Now()
	f := &File{Version: 1}
	ta, _ := f.Add(Client{ID: "a"}, now)
	tb, _ := f.Add(Client{ID: "b"}, now)
	if _, err := f.AddKey("a", FormatPublicKey(newPub(t, 1)), "", nil, now); err != nil {
		t.Fatal(err)
	}
	s := NewStore(f)
	pa, _ := s.Authenticate(ta, now)
	pb, _ := s.Authenticate(tb, now)
	if !pa.SignatureRequired() || len(pa.Keys) != 1 || !pa.Keys[0].Pub.Equal(newPub(t, 1)) {
		t.Fatalf("a: %+v", pa)
	}
	if pb.SignatureRequired() {
		t.Fatal("b requires signature")
	}
}

// Concurrent writers (CLI runs and admin API calls) must not lose updates.
func TestUpdateConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	const n = 40
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- Update(path, true, func(f *File) error {
				_, err := f.Add(Client{ID: fmt.Sprintf("c%d", i)}, time.Now())
				return err
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	f, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Clients) != n {
		t.Fatalf("%d clients after %d concurrent adds", len(f.Clients), n)
	}
}

func TestUpdateErrorWritesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	if err := Update(path, false, func(*File) error { return nil }); err == nil {
		t.Fatal("missing file without create succeeded")
	}
	if err := Update(path, true, func(f *File) error { _, err := f.Add(Client{ID: "a"}, time.Now()); return err }); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	if err := Update(path, false, func(f *File) error { f.Clients = nil; return boom }); err != boom {
		t.Fatalf("got %v", err)
	}
	if f, _ := Read(path); len(f.Clients) != 1 {
		t.Fatal("failed update was written")
	}
}
