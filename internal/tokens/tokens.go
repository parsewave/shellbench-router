// Package tokens manages proxy client credentials.
//
// Tokens are 256-bit random strings shown to the operator exactly once. Only
// their SHA-256 digests are stored; because the tokens are high-entropy, a
// fast hash is sufficient (a slow KDF would add latency to every request
// without improving security). Verification compares the presented digest
// against every stored digest in constant time.
package tokens

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Prefix marks proxy tokens so they are easy to recognise in secret scanners.
const Prefix = "sk-px-"

var idRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// File is the on-disk token configuration.
type File struct {
	Version int      `json:"version"`
	Clients []Client `json:"clients"`
}

// Client is one independently revocable consumer (e.g. "alice").
type Client struct {
	ID            string     `json:"id"`
	Note          string     `json:"note,omitempty"`
	Disabled      bool       `json:"disabled,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	Models        []string   `json:"models,omitempty"`         // empty = all models; "prefix*" globs allowed
	RPM           int        `json:"rpm,omitempty"`            // requests per minute, 0 = unlimited
	Burst         int        `json:"burst,omitempty"`          // token-bucket size, 0 = RPM
	MaxConcurrent int        `json:"max_concurrent,omitempty"` // in-flight requests, 0 = unlimited
	Secrets       []Secret   `json:"secrets"`
	// AllowedIPs restricts where the token works: IP addresses or CIDR
	// ranges. Empty = any IP. A leaked token is useless from anywhere else.
	AllowedIPs []string `json:"allowed_ips,omitempty"`
}

// Secret is one valid credential for a client. Several may be valid at once
// during a rotation grace period.
type Secret struct {
	SHA256    string     `json:"sha256"`
	Hint      string     `json:"hint,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Generate creates a new random token and its stored form.
func Generate(now time.Time) (string, Secret, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", Secret{}, err
	}
	tok := Prefix + base64.RawURLEncoding.EncodeToString(b[:])
	sum := sha256.Sum256([]byte(tok))
	return tok, Secret{
		SHA256:    hex.EncodeToString(sum[:]),
		Hint:      tok[:len(Prefix)+4] + "...",
		CreatedAt: now.UTC().Truncate(time.Second),
	}, nil
}

// Read loads and validates a token file.
func Read(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := f.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &f, nil
}

// Write validates f and atomically replaces path with it (mode 0600), so the
// running server never observes a partially written file.
func Write(path string, f *File) error {
	if err := f.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tokens-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Validate checks structural invariants.
func (f *File) Validate() error {
	if f.Version != 1 {
		return fmt.Errorf("unsupported token file version %d (want 1)", f.Version)
	}
	ids := map[string]bool{}
	hashes := map[string]bool{}
	for _, c := range f.Clients {
		if !idRE.MatchString(c.ID) {
			return fmt.Errorf("invalid client id %q (allowed: letters, digits, _ . -, max 64)", c.ID)
		}
		if ids[c.ID] {
			return fmt.Errorf("duplicate client id %q", c.ID)
		}
		ids[c.ID] = true
		if c.RPM < 0 || c.Burst < 0 || c.MaxConcurrent < 0 {
			return fmt.Errorf("client %q: limits must not be negative", c.ID)
		}
		for _, m := range c.Models {
			if m == "" || strings.ContainsAny(m, " \t\r\n") || strings.Contains(strings.TrimSuffix(m, "*"), "*") {
				return fmt.Errorf("client %q: invalid model pattern %q (exact name, or prefix ending in *)", c.ID, m)
			}
		}
		for _, s := range c.Secrets {
			raw, err := hex.DecodeString(s.SHA256)
			if err != nil || len(raw) != sha256.Size {
				return fmt.Errorf("client %q: secret hash must be 64 hex characters", c.ID)
			}
			h := strings.ToLower(s.SHA256)
			if hashes[h] {
				return fmt.Errorf("client %q: duplicate secret hash", c.ID)
			}
			hashes[h] = true
		}
		if len(c.AllowedIPs) > MaxAllowedIPs {
			return fmt.Errorf("client %q: at most %d allowed IP entries", c.ID, MaxAllowedIPs)
		}
		for _, ip := range c.AllowedIPs {
			if _, err := ParseIPPrefix(ip); err != nil {
				return fmt.Errorf("client %q: %w", c.ID, err)
			}
		}
	}
	return nil
}

// Find returns the client with the given id, or nil.
func (f *File) Find(id string) *Client {
	for i := range f.Clients {
		if f.Clients[i].ID == id {
			return &f.Clients[i]
		}
	}
	return nil
}

// Add creates a client with a fresh secret and returns the plaintext token.
func (f *File) Add(c Client, now time.Time) (string, error) {
	if f.Find(c.ID) != nil {
		return "", fmt.Errorf("client %q %w", c.ID, ErrExists)
	}
	tok, s, err := Generate(now)
	if err != nil {
		return "", err
	}
	c.Secrets = []Secret{s}
	f.Clients = append(f.Clients, c)
	return tok, f.Validate()
}

// Rotate issues a new secret for id. Existing secrets stay valid for grace
// (0 = revoked immediately); already-expired secrets are pruned.
func (f *File) Rotate(id string, grace time.Duration, now time.Time) (string, error) {
	c := f.Find(id)
	if c == nil {
		return "", fmt.Errorf("client %q %w", id, ErrNotFound)
	}
	tok, s, err := Generate(now)
	if err != nil {
		return "", err
	}
	deadline := now.UTC().Add(grace).Truncate(time.Second)
	kept := c.Secrets[:0]
	for _, old := range c.Secrets {
		if grace <= 0 || (old.ExpiresAt != nil && !old.ExpiresAt.After(now)) {
			continue
		}
		if old.ExpiresAt == nil || old.ExpiresAt.After(deadline) {
			old.ExpiresAt = &deadline
		}
		kept = append(kept, old)
	}
	c.Secrets = append(kept, s)
	return tok, f.Validate()
}

// Remove deletes a client entirely.
func (f *File) Remove(id string) error {
	for i := range f.Clients {
		if f.Clients[i].ID == id {
			f.Clients = append(f.Clients[:i], f.Clients[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("client %q %w", id, ErrNotFound)
}

// Status describes a client's effective state at now.
func (c *Client) Status(now time.Time) string {
	switch {
	case c.Disabled:
		return "revoked"
	case c.ExpiresAt != nil && !c.ExpiresAt.After(now):
		return "expired"
	}
	for _, s := range c.Secrets {
		if s.ExpiresAt == nil || s.ExpiresAt.After(now) {
			return "active"
		}
	}
	return "no-valid-secret"
}

// MaxAllowedIPs bounds a client's IP allowlist.
const MaxAllowedIPs = 64

// ParseIPPrefix accepts an address ("203.0.113.7", "2001:db8::1") or a
// CIDR range ("10.0.0.0/8"); an address means exactly that host.
func ParseIPPrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid IP range %q", s)
		}
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP address %q", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// ParseIPList splits a comma-separated allowlist; "", "*" or "any" = any IP.
func ParseIPList(s string) ([]string, error) {
	var out []string
	for _, v := range strings.Split(s, ",") {
		v = strings.TrimSpace(v)
		switch v {
		case "":
			continue
		case "*", "any":
			return nil, nil
		}
		if _, err := ParseIPPrefix(v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// Lookup errors returned (wrapped) by File methods.
var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
)

// Authentication failures. Clients receive the same generic 401 for all of
// them; the distinction is only logged.
var (
	ErrMissing = errors.New("missing_token")
	ErrInvalid = errors.New("invalid_token")
	ErrRevoked = errors.New("revoked_token")
	ErrExpired = errors.New("expired_token")
)

// Principal is an authenticated client with its effective policy.
type Principal struct {
	ID            string
	Models        []string
	RPM           int
	Burst         int
	MaxConcurrent int
	AllowedIPs    []netip.Prefix // empty = any IP
}

// AllowsIP reports whether requests from ip may use this token.
func (p *Principal) AllowsIP(ip netip.Addr) bool {
	if len(p.AllowedIPs) == 0 {
		return true
	}
	ip = ip.Unmap()
	for _, pfx := range p.AllowedIPs {
		if pfx.Contains(ip) {
			return true
		}
	}
	return false
}

// Restricted reports whether the client has a model allow-list.
func (p *Principal) Restricted() bool {
	for _, m := range p.Models {
		if m == "*" {
			return false
		}
	}
	return len(p.Models) > 0
}

// AllowsModel applies the global exclusions before the client's allowlist.
// Allowlist matching is exact and case-sensitive; a trailing * matches a prefix.
func (p *Principal) AllowsModel(m string) bool {
	if !ModelEligible(m) {
		return false
	}
	if !p.Restricted() {
		return true
	}
	for _, pat := range p.Models {
		if strings.HasSuffix(pat, "*") {
			if strings.HasPrefix(m, pat[:len(pat)-1]) {
				return true
			}
		} else if m == pat {
			return true
		}
	}
	return false
}

type entry struct {
	principal *Principal
	disabled  bool
	clientExp *time.Time
	secretExp *time.Time
}

// Store is an immutable, compiled view of a File used on the request path.
type Store struct {
	hashes  [][sha256.Size]byte
	entries []entry
	ids     []string
}

// NewStore compiles f. f must already be valid.
func NewStore(f *File) *Store {
	s := &Store{}
	for _, c := range f.Clients {
		p := &Principal{ID: c.ID, Models: append([]string(nil), c.Models...), RPM: c.RPM, Burst: c.Burst, MaxConcurrent: c.MaxConcurrent}
		for _, ip := range c.AllowedIPs {
			pfx, _ := ParseIPPrefix(ip) // validated by File.Validate
			p.AllowedIPs = append(p.AllowedIPs, pfx)
		}
		s.ids = append(s.ids, c.ID)
		for _, sec := range c.Secrets {
			var h [sha256.Size]byte
			hex.Decode(h[:], []byte(sec.SHA256))
			s.hashes = append(s.hashes, h)
			s.entries = append(s.entries, entry{principal: p, disabled: c.Disabled, clientExp: c.ExpiresAt, secretExp: sec.ExpiresAt})
		}
	}
	return s
}

// IDs returns the configured client ids.
func (s *Store) IDs() []string { return s.ids }

// Authenticate verifies a presented token. Every stored digest is compared
// in constant time so timing reveals nothing about which (if any) matched.
func (s *Store) Authenticate(token string, now time.Time) (*Principal, error) {
	if token == "" {
		return nil, ErrMissing
	}
	sum := sha256.Sum256([]byte(token))
	idx := -1
	for i := range s.hashes {
		idx = subtle.ConstantTimeSelect(subtle.ConstantTimeCompare(s.hashes[i][:], sum[:]), i, idx)
	}
	if idx < 0 {
		return nil, ErrInvalid
	}
	e := &s.entries[idx]
	switch {
	case e.disabled:
		return nil, ErrRevoked
	case e.clientExp != nil && !e.clientExp.After(now), e.secretExp != nil && !e.secretExp.After(now):
		return nil, ErrExpired
	}
	return e.principal, nil
}
