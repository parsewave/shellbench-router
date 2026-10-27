package tokens

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// MaxPublicKeys bounds per-client signing keys; each signed request may be
// checked against all of them.
const MaxPublicKeys = 8

// PublicKey is a client's Ed25519 request-signing key. Only the public half
// is ever stored or sent to the proxy; the private key never leaves the
// client.
type PublicKey struct {
	ID        string     `json:"id"`  // KeyID of Key
	Key       string     `json:"key"` // "ed25519:" + base64 of the 32-byte key
	Note      string     `json:"note,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// ParsePublicKey accepts "ed25519:<base64>", bare base64 (standard or URL
// alphabet, padded or not) of the 32-byte key, or a PEM "PUBLIC KEY" block
// as printed by `openssl pkey -pubout`.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "-----BEGIN") {
		blk, _ := pem.Decode([]byte(s))
		if blk == nil || blk.Type != "PUBLIC KEY" {
			return nil, errors.New("expected a PEM PUBLIC KEY block")
		}
		k, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PEM public key: %w", err)
		}
		pub, ok := k.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("PEM key is not Ed25519")
		}
		return pub, nil
	}
	s = strings.TrimPrefix(s, "ed25519:")
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			if len(b) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("Ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(b))
			}
			return ed25519.PublicKey(b), nil
		}
	}
	return nil, errors.New(`public key must be "ed25519:<base64>" or a PEM PUBLIC KEY block`)
}

// FormatPublicKey is the canonical stored form of pub.
func FormatPublicKey(pub ed25519.PublicKey) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(pub)
}

// KeyID is a short, stable identifier derived from the key itself.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "k_" + hex.EncodeToString(sum[:6])
}

// AddKey registers a signing key for client id. Once a client has a key,
// unsigned requests with its token are rejected.
func (f *File) AddKey(id, key, note string, expires *time.Time, now time.Time) (PublicKey, error) {
	c := f.Find(id)
	if c == nil {
		return PublicKey{}, fmt.Errorf("client %q %w", id, ErrNotFound)
	}
	pub, err := ParsePublicKey(key)
	if err != nil {
		return PublicKey{}, err
	}
	k := PublicKey{ID: KeyID(pub), Key: FormatPublicKey(pub), Note: note, CreatedAt: now.UTC().Truncate(time.Second), ExpiresAt: expires}
	for _, old := range c.PublicKeys {
		if old.ID == k.ID {
			return PublicKey{}, fmt.Errorf("client %q key %s %w", id, k.ID, ErrExists)
		}
	}
	c.PublicKeys = append(c.PublicKeys, k)
	return k, f.Validate()
}

// ErrLastKey guards against silently turning signing off: removing a
// client's last key makes its bearer token sufficient again.
var ErrLastKey = errors.New("removing the last signing key would allow unsigned requests; add the replacement key first, or pass allow-unsigned")

// RemoveKey deletes one signing key. The last key can only be removed with
// allowUnsigned, which turns request signing off for the client.
func (f *File) RemoveKey(id, keyID string, allowUnsigned bool) error {
	c := f.Find(id)
	if c == nil {
		return fmt.Errorf("client %q %w", id, ErrNotFound)
	}
	for i, k := range c.PublicKeys {
		if k.ID == keyID {
			if len(c.PublicKeys) == 1 && !allowUnsigned {
				return ErrLastKey
			}
			c.PublicKeys = append(c.PublicKeys[:i], c.PublicKeys[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("client %q key %q %w", id, keyID, ErrNotFound)
}
