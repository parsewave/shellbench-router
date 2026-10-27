package tokens

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestParseIPPrefix(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":         "203.0.113.7/32",
		" 10.1.2.3/8 ":        "10.0.0.0/8",
		"2001:db8::1":         "2001:db8::1/128",
		"::ffff:192.0.2.1":    "192.0.2.1/32",
		"::ffff:10.0.0.0/104": "10.0.0.0/8",
	} {
		got, err := ParseIPPrefix(in)
		if err != nil || got.String() != want {
			t.Errorf("ParseIPPrefix(%q) = %v, %v; want %s", in, got, err, want)
		}
	}
	for _, in := range []string{"", "1.2.3", "1.2.3.4/33", "example.com", "*"} {
		if _, err := ParseIPPrefix(in); err == nil {
			t.Errorf("ParseIPPrefix(%q) succeeded", in)
		}
	}
	if l, err := ParseIPList("1.2.3.4, 10.0.0.0/8,"); err != nil || len(l) != 2 {
		t.Errorf("ParseIPList = %v, %v", l, err)
	}
	if l, err := ParseIPList("*"); err != nil || l != nil {
		t.Errorf("ParseIPList(*) = %v, %v", l, err)
	}
	if _, err := ParseIPList("1.2.3.4,nope"); err == nil {
		t.Error("ParseIPList accepted garbage")
	}
}

func TestAllowsIP(t *testing.T) {
	now := time.Now()
	f := &File{Version: 1}
	ta, _ := f.Add(Client{ID: "a", AllowedIPs: []string{"203.0.113.7", "10.0.0.0/8", "2001:db8::/32"}}, now)
	tb, _ := f.Add(Client{ID: "b"}, now)
	s := NewStore(f)
	pa, _ := s.Authenticate(ta, now)
	pb, _ := s.Authenticate(tb, now)
	for ip, want := range map[string]bool{
		"203.0.113.7": true, "203.0.113.8": false, "10.200.0.1": true, "11.0.0.1": false,
		"::ffff:203.0.113.7": true, "2001:db8::5": true, "2001:db9::5": false,
	} {
		if got := pa.AllowsIP(netip.MustParseAddr(ip)); got != want {
			t.Errorf("a.AllowsIP(%s) = %v", ip, got)
		}
		if !pb.AllowsIP(netip.MustParseAddr(ip)) {
			t.Errorf("unrestricted client rejected %s", ip)
		}
	}
	bad := &File{Version: 1, Clients: []Client{{ID: "x", AllowedIPs: []string{"nope"}}}}
	if err := bad.Validate(); err == nil {
		t.Error("invalid allowed_ips accepted")
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
