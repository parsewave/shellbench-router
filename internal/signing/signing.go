// Package signing implements proxy request signing.
//
// A client that has registered an Ed25519 public key signs every request in
// addition to sending its bearer token. The signature covers
//
//	PX-ED25519-V1
//	<METHOD>
//	<host>                      lower-cased Host header
//	<path?query>                exactly as sent (the request URI)
//	<unix timestamp>
//	<nonce>
//	<hex sha256 of the body>
//
// joined with "\n", and is sent as
//
//	X-Px-Timestamp: <unix seconds>
//	X-Px-Nonce:     <16-128 chars of [A-Za-z0-9_-], unique per request>
//	X-Px-Signature: <base64url of the 64-byte signature>
//
// The proxy accepts timestamps within MaxSkew of its clock and remembers
// nonces for that window, so a captured request can't be replayed or
// altered, and a leaked bearer token is useless without the private key.
package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	Version         = "PX-ED25519-V1"
	HeaderTimestamp = "X-Px-Timestamp"
	HeaderNonce     = "X-Px-Nonce"
	HeaderSignature = "X-Px-Signature"
)

// Verification failures; clients see the code, the distinction is logged.
var (
	ErrMissing   = errors.New("signature_required")
	ErrMalformed = errors.New("malformed_signature")
	ErrStale     = errors.New("signature_expired")
	ErrInvalid   = errors.New("invalid_signature")
	ErrReplayed  = errors.New("signature_replayed")
	ErrBusy      = errors.New("replay_cache_full")
)

var nonceRE = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

// StringToSign builds the canonical message for a request.
func StringToSign(method, host, requestURI string, ts int64, nonce string, bodySHA256 []byte) []byte {
	return []byte(strings.Join([]string{
		Version,
		strings.ToUpper(method),
		strings.ToLower(host),
		requestURI,
		strconv.FormatInt(ts, 10),
		nonce,
		hex.EncodeToString(bodySHA256),
	}, "\n"))
}

// Sign returns the header values for a request; used by Go clients and tests.
func Sign(priv ed25519.PrivateKey, method, host, requestURI string, body []byte, now time.Time, nonce string) (ts, sig string) {
	sum := sha256.Sum256(body)
	t := now.Unix()
	msg := StringToSign(method, host, requestURI, t, nonce, sum[:])
	return strconv.FormatInt(t, 10), base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, msg))
}

// Headers are the parsed signature headers of one request.
type Headers struct {
	Timestamp int64
	Nonce     string
	Signature []byte
}

// ParseHeaders checks presence, format and freshness. It is cheap, so it
// runs before the request body is read.
func ParseHeaders(ts, nonce, sig string, now time.Time, maxSkew time.Duration) (Headers, error) {
	if ts == "" && nonce == "" && sig == "" {
		return Headers{}, ErrMissing
	}
	t, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || !nonceRE.MatchString(nonce) {
		return Headers{}, ErrMalformed
	}
	var raw []byte
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding, base64.RawStdEncoding} {
		if raw, err = enc.DecodeString(sig); err == nil {
			break
		}
	}
	if err != nil || len(raw) != ed25519.SignatureSize {
		return Headers{}, ErrMalformed
	}
	if d := now.Sub(time.Unix(t, 0)); d > maxSkew || d < -maxSkew {
		return Headers{}, ErrStale
	}
	return Headers{Timestamp: t, Nonce: nonce, Signature: raw}, nil
}

// Key is one candidate verification key.
type Key struct {
	ID        string
	Pub       ed25519.PublicKey
	ExpiresAt *time.Time
}

// Verify returns the id of the key that signed msg, trying every unexpired
// key (clients have at most a handful).
func Verify(keys []Key, h Headers, msg []byte, now time.Time) (string, error) {
	for _, k := range keys {
		if k.ExpiresAt != nil && !k.ExpiresAt.After(now) {
			continue
		}
		if ed25519.Verify(k.Pub, msg, h.Signature) {
			return k.ID, nil
		}
	}
	return "", ErrInvalid
}

// NonceCache remembers recently used nonces so a signed request is accepted
// at most once. Entries live for twice the allowed skew, which covers every
// timestamp that could still pass ParseHeaders.
type NonceCache struct {
	ttl  time.Duration
	max  int
	mu   sync.Mutex
	seen map[string]time.Time
	next time.Time // next sweep
}

// NewNonceCache bounds memory to max entries (default 1M); beyond that new
// signed requests fail closed with ErrBusy until old entries expire.
func NewNonceCache(maxSkew time.Duration, max int) *NonceCache {
	if max <= 0 {
		max = 1 << 20
	}
	return &NonceCache{ttl: 2 * maxSkew, max: max, seen: map[string]time.Time{}}
}

// Use records nonce for client, failing if it was already seen.
func (c *NonceCache) Use(client, nonce string, now time.Time) error {
	key := client + "\x00" + nonce
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.After(c.next) {
		for k, exp := range c.seen {
			if !exp.After(now) {
				delete(c.seen, k)
			}
		}
		c.next = now.Add(c.ttl / 4)
	}
	if exp, ok := c.seen[key]; ok && exp.After(now) {
		return ErrReplayed
	}
	if len(c.seen) >= c.max {
		return ErrBusy
	}
	c.seen[key] = now.Add(c.ttl)
	return nil
}
