// Package config loads the proxy's runtime configuration from environment
// variables. Secrets (the upstream API key) come from UPSTREAM_API_KEY or,
// preferably, UPSTREAM_API_KEY_FILE so they can be supplied by a secret
// manager and rotated without a restart.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultRoutes are the upstream endpoints forwarded when ALLOWED_ROUTES is
// unset. `*` matches exactly one path segment.
var DefaultRoutes = []string{
	"GET /v1/models",
	"GET /v1/models/*",
	"POST /v1/chat/completions",
	"POST /v1/responses",
	"POST /v1/responses/input_tokens",
	"POST /v1/alpha/search",
	"POST /v1/responses/compact",
	"GET /v1/responses/*",
	"DELETE /v1/responses/*",
	"POST /v1/responses/*/cancel",
	"GET /v1/responses/*/input_items",
	"POST /v1/embeddings",
	"POST /v1/images/generations",
	"POST /v1/images/edits",
	"POST /v1/audio/speech",
	"POST /v1/audio/transcriptions",
	"POST /v1/audio/translations",
	"POST /v1/completions",
	"POST /v1/moderations",
	// Anthropic Messages API (Claude Code, Anthropic SDKs).
	"POST /v1/messages",
	"POST /v1/messages/count_tokens",
}

type Config struct {
	ListenAddr        string
	MetricsAddr       string
	TokensFile        string
	ReloadInterval    time.Duration
	Upstream          *url.URL
	UpstreamOrg       string
	UpstreamProject   string
	UpstreamHeaders   http.Header
	Key               *UpstreamKey
	AdminKey          *UpstreamKey   // nil = admin API disabled
	TrustedProxies    []netip.Prefix // nil = proxy.DefaultTrustedProxies
	Routes            []string
	MaxRequestBytes   int64
	MaxRetries        int
	MaxRetryWait      time.Duration
	UpstreamTimeout   time.Duration
	StreamIdleTimeout time.Duration
	BodyReadTimeout   time.Duration
	MaxInflight       int
	MaxBufferedBytes  int64
	ShutdownTimeout   time.Duration
	LogFormat         string
	LogLevel          string
	AccessLogFile     string
}

// Load reads configuration from the environment and validates it.
func Load() (*Config, error) {
	var errs []error
	c := &Config{
		ListenAddr:        str("LISTEN_ADDR", ":8080"),
		MetricsAddr:       str("METRICS_ADDR", ""),
		TokensFile:        str("TOKENS_FILE", "tokens.json"),
		ReloadInterval:    dur("TOKENS_RELOAD_INTERVAL", 2*time.Second, &errs),
		UpstreamOrg:       str("UPSTREAM_ORGANIZATION", ""),
		UpstreamProject:   str("UPSTREAM_PROJECT", ""),
		MaxRequestBytes:   int64(num("MAX_REQUEST_BYTES", 32<<20, &errs)),
		MaxRetries:        num("MAX_RETRIES", 2, &errs),
		MaxRetryWait:      dur("MAX_RETRY_WAIT", 20*time.Second, &errs),
		UpstreamTimeout:   dur("UPSTREAM_TIMEOUT", 30*time.Minute, &errs),
		StreamIdleTimeout: dur("STREAM_IDLE_TIMEOUT", 10*time.Minute, &errs),
		BodyReadTimeout:   dur("BODY_READ_TIMEOUT", 60*time.Second, &errs),
		MaxInflight:       num("MAX_INFLIGHT", 2048, &errs),
		MaxBufferedBytes:  int64(num("MAX_BUFFERED_BYTES", 1<<30, &errs)),
		ShutdownTimeout:   dur("SHUTDOWN_TIMEOUT", 30*time.Second, &errs),
		LogFormat:         str("LOG_FORMAT", "json"),
		LogLevel:          str("LOG_LEVEL", "info"),
		AccessLogFile:     str("ACCESS_LOG_FILE", ""),
	}

	var err error
	if c.UpstreamHeaders, err = ParseHeaders(os.Getenv("UPSTREAM_HEADERS")); err != nil {
		errs = append(errs, err)
	}

	u, err := ParseUpstream(str("UPSTREAM_BASE_URL", "https://api.openai.com/v1"), boolean("ALLOW_INSECURE_UPSTREAM"))
	if err != nil {
		errs = append(errs, err)
	}
	c.Upstream = u

	if c.MaxRetries < 0 || c.MaxRetries > 3 {
		errs = append(errs, errors.New("MAX_RETRIES must be between 0 and 3"))
	}
	if c.MaxRequestBytes <= 0 {
		errs = append(errs, errors.New("MAX_REQUEST_BYTES must be positive"))
	}
	if c.ReloadInterval <= 0 {
		errs = append(errs, errors.New("TOKENS_RELOAD_INTERVAL must be positive"))
	}
	switch c.LogFormat {
	case "json", "text":
	default:
		errs = append(errs, errors.New("LOG_FORMAT must be json or text"))
	}

	if s := os.Getenv("ALLOWED_ROUTES"); strings.TrimSpace(s) != "" {
		for _, r := range strings.Split(s, ",") {
			if r = strings.TrimSpace(r); r != "" {
				c.Routes = append(c.Routes, r)
			}
		}
	} else {
		c.Routes = append([]string(nil), DefaultRoutes...)
	}

	c.Key, err = NewUpstreamKey(os.Getenv("UPSTREAM_API_KEY"), os.Getenv("UPSTREAM_API_KEY_FILE"))
	if err != nil {
		errs = append(errs, err)
	}
	if v, f := os.Getenv("ADMIN_API_KEY"), os.Getenv("ADMIN_API_KEY_FILE"); v != "" || f != "" {
		if c.AdminKey, err = newKey("ADMIN_API_KEY", "admin API key", v, f); err != nil {
			errs = append(errs, err)
		} else if len(c.AdminKey.Get()) < 32 {
			errs = append(errs, errors.New("admin API key must be at least 32 characters (generate one with scripts/keys.sh admin-key)"))
		}
	}
	if v := str("TRUSTED_PROXIES", ""); v != "" {
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s == "" {
				continue
			}
			p, err := netip.ParsePrefix(s)
			if err != nil {
				errs = append(errs, fmt.Errorf("TRUSTED_PROXIES: invalid CIDR %q", s))
				continue
			}
			c.TrustedProxies = append(c.TrustedProxies, p.Masked())
		}
	}
	return c, errors.Join(errs...)
}

// ParseHeaders parses UPSTREAM_HEADERS: extra headers the proxy adds to every
// upstream request, as "Name=value;Name2=value2" (e.g. OpenRouter's
// HTTP-Referer and X-Title attribution headers). Credentials can't be set here.
func ParseHeaders(s string) (http.Header, error) {
	h := http.Header{}
	for _, kv := range strings.Split(s, ";") {
		if kv = strings.TrimSpace(kv); kv == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || k == "" || !validHeaderName(k) || !validHeaderValue(v) {
			return nil, fmt.Errorf("UPSTREAM_HEADERS: invalid entry %q (want Name=value;...)", kv)
		}
		switch http.CanonicalHeaderKey(k) {
		case "Authorization", "Host", "Content-Length", "Content-Type", "Openai-Organization", "Openai-Project":
			return nil, fmt.Errorf("UPSTREAM_HEADERS: %s cannot be set here", k)
		}
		h.Set(k, v)
	}
	return h, nil
}

func validHeaderName(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}

func validHeaderValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < ' ' && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

// ParseUpstream validates the upstream base URL. Plain http is only accepted
// when explicitly allowed (local mocks and tests).
func ParseUpstream(raw string, allowInsecure bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("UPSTREAM_BASE_URL %q is not an absolute URL", raw)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && allowInsecure) {
		return nil, errors.New("UPSTREAM_BASE_URL must use https (set ALLOW_INSECURE_UPSTREAM=true only for local testing)")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("UPSTREAM_BASE_URL must not contain credentials, a query, or a fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

// UpstreamKey holds the provider's real API key. When backed by a file it can
// be reloaded in place, so the key can be rotated without a restart.
type UpstreamKey struct {
	label string
	file  string
	val   atomic.Pointer[string]
	mu    sync.Mutex
	info  os.FileInfo
}

func NewUpstreamKey(value, file string) (*UpstreamKey, error) {
	return newKey("UPSTREAM_API_KEY", "upstream API key", value, file)
}

// newKey loads a secret from env var <env> or file <env>_FILE; the file
// form is re-read by Reload.
func newKey(env, label, value, file string) (*UpstreamKey, error) {
	k := &UpstreamKey{label: label, file: file}
	switch {
	case value != "" && file != "":
		return nil, fmt.Errorf("set only one of %s and %s_FILE", env, env)
	case file != "":
		if _, err := k.Reload(); err != nil {
			return nil, err
		}
	case value != "":
		if err := validKey(label, value); err != nil {
			return nil, err
		}
		k.val.Store(&value)
	default:
		return nil, fmt.Errorf("%s or %s_FILE is required", env, env)
	}
	return k, nil
}

// Get returns the current key.
func (k *UpstreamKey) Get() string { return *k.val.Load() }

// File returns the backing file path, if any.
func (k *UpstreamKey) File() string { return k.file }

// Fingerprint is a short, non-reversible identifier for logs, so operators
// can confirm a rotation took effect without the key ever being printed.
func (k *UpstreamKey) Fingerprint() string {
	sum := sha256.Sum256([]byte(k.Get()))
	return hex.EncodeToString(sum[:4])
}

// Reload re-reads the key file if it changed. It is a no-op for env keys.
func (k *UpstreamKey) Reload() (bool, error) {
	if k.file == "" {
		return false, nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	fi, err := os.Stat(k.file)
	if err != nil {
		return false, fmt.Errorf("%s file: %w", k.label, err)
	}
	if k.info != nil && os.SameFile(k.info, fi) && fi.ModTime().Equal(k.info.ModTime()) && fi.Size() == k.info.Size() {
		return false, nil
	}
	b, err := os.ReadFile(k.file)
	if err != nil {
		return false, fmt.Errorf("%s file: %w", k.label, err)
	}
	v := strings.TrimSpace(string(b))
	if err := validKey(k.label, v); err != nil {
		return false, err
	}
	k.info = fi
	k.val.Store(&v)
	return true, nil
}

func validKey(label, v string) error {
	if v == "" {
		return fmt.Errorf("%s is empty", label)
	}
	if len(v) > 1024 {
		return fmt.Errorf("%s is implausibly long", label)
	}
	for i := 0; i < len(v); i++ {
		if v[i] <= ' ' || v[i] == 0x7f {
			return fmt.Errorf("%s contains whitespace or control characters", label)
		}
	}
	return nil
}

func str(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func num(name string, def int, errs *[]error) int {
	v := str(name, "")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %w", name, err))
		return def
	}
	return n
}

// dur accepts Go durations ("90s", "30m") or a bare number of seconds.
func dur(name string, def time.Duration, errs *[]error) time.Duration {
	v := str(name, "")
	if v == "" {
		return def
	}
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		*errs = append(*errs, fmt.Errorf("%s: invalid duration %q", name, v))
		return def
	}
	return d
}

func boolean(name string) bool {
	b, _ := strconv.ParseBool(str(name, "false"))
	return b
}
