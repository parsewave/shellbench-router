// Package admin serves the token-management HTTP API under /admin/.
//
// It is the HTTP equivalent of `oaiproxy token ...`: both edit the same
// tokens file through tokens.Update, so changes from either are serialised
// and take effect immediately. Requests authenticate with the admin key
// (ADMIN_API_KEY_FILE); without one the API is disabled and /admin/ is 404.
//
//	GET    /admin/clients                     list clients
//	POST   /admin/clients                     create; returns the token once
//	GET    /admin/clients/{id}                show one client
//	PATCH  /admin/clients/{id}                change models, limits, expiry, note
//	DELETE /admin/clients/{id}                delete
//	POST   /admin/clients/{id}/rotate         new token; {"grace":"24h"} keeps the old one
//	POST   /admin/clients/{id}/revoke         disable immediately
//	POST   /admin/clients/{id}/enable         re-enable
//	POST   /admin/clients/{id}/keys           register a request-signing public key
//	DELETE /admin/clients/{id}/keys/{key_id}  remove a signing key
package admin

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"oaiproxy/internal/tokens"
)

// KeySource supplies the current admin key ("" = API disabled).
type KeySource interface{ Get() string }

// Server is the admin API handler.
type Server struct {
	TokensFile string
	Key        KeySource    // nil or empty = disabled
	Reload     func()       // applies the tokens file now instead of at the next poll
	Log        *slog.Logger // audit log of every admin call
	Now        func() time.Time

	mux *http.ServeMux
}

const maxBody = 64 << 10

func (s *Server) init() {
	if s.mux != nil {
		return
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Log == nil {
		s.Log = slog.Default()
	}
	m := http.NewServeMux()
	m.HandleFunc("GET /admin/clients", s.list)
	m.HandleFunc("POST /admin/clients", s.create)
	m.HandleFunc("GET /admin/clients/{id}", s.get)
	m.HandleFunc("PATCH /admin/clients/{id}", s.patch)
	m.HandleFunc("DELETE /admin/clients/{id}", s.remove)
	m.HandleFunc("POST /admin/clients/{id}/rotate", s.rotate)
	m.HandleFunc("POST /admin/clients/{id}/revoke", s.setDisabled(true))
	m.HandleFunc("POST /admin/clients/{id}/enable", s.setDisabled(false))
	m.HandleFunc("POST /admin/clients/{id}/keys", s.addKey)
	m.HandleFunc("DELETE /admin/clients/{id}/keys/{key}", s.removeKey)
	s.mux = m
}

// Enabled reports whether an admin key is configured.
func (s *Server) Enabled() bool { return s.Key != nil && s.Key.Get() != "" }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.init()
	w.Header().Set("Cache-Control", "no-store")
	if !s.Enabled() {
		writeError(w, http.StatusNotFound, "unknown_url", "Not found.")
		return
	}
	if !s.authorized(r) {
		s.Log.Warn("admin request rejected", "method", r.Method, "path", truncate(r.URL.Path, 128), "remote", remote(r))
		w.Header().Set("WWW-Authenticate", `Bearer realm="oaiproxy-admin"`)
		writeError(w, http.StatusUnauthorized, "invalid_admin_key", "Invalid or missing admin key.")
		return
	}
	// ServeMux would redirect unclean paths; reject them instead.
	if r.URL.RawPath != "" || strings.Contains(r.URL.Path, "//") || strings.Contains(r.URL.Path, "/.") {
		writeError(w, http.StatusNotFound, "unknown_url", "Not found.")
		return
	}
	if _, pattern := s.mux.Handler(r); pattern == "" {
		writeError(w, http.StatusNotFound, "unknown_url", "Not found.")
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) authorized(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	if len(h) <= 7 || !strings.EqualFold(h[:7], "Bearer ") {
		return false
	}
	got := sha256.Sum256([]byte(strings.TrimSpace(h[7:])))
	want := sha256.Sum256([]byte(s.Key.Get()))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

// --- views -----------------------------------------------------------------

type secretView struct {
	Hint      string     `json:"hint"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type clientView struct {
	ID                string             `json:"id"`
	Status            string             `json:"status"`
	Note              string             `json:"note,omitempty"`
	Models            []string           `json:"models"` // empty = all models
	RPM               int                `json:"rpm"`
	Burst             int                `json:"burst"`
	MaxConcurrent     int                `json:"max_concurrent"`
	ExpiresAt         *time.Time         `json:"expires_at,omitempty"`
	SignatureRequired bool               `json:"signature_required"`
	Secrets           []secretView       `json:"secrets"`
	PublicKeys        []tokens.PublicKey `json:"public_keys"`
}

func view(c *tokens.Client, now time.Time) clientView {
	v := clientView{
		ID: c.ID, Status: c.Status(now), Note: c.Note, Models: c.Models, RPM: c.RPM, Burst: c.Burst,
		MaxConcurrent: c.MaxConcurrent, ExpiresAt: c.ExpiresAt, SignatureRequired: len(c.PublicKeys) > 0,
		Secrets: []secretView{}, PublicKeys: c.PublicKeys,
	}
	if v.Models == nil {
		v.Models = []string{}
	}
	if v.PublicKeys == nil {
		v.PublicKeys = []tokens.PublicKey{}
	}
	for _, sec := range c.Secrets {
		v.Secrets = append(v.Secrets, secretView{Hint: sec.Hint, CreatedAt: sec.CreatedAt, ExpiresAt: sec.ExpiresAt})
	}
	return v
}

// --- handlers --------------------------------------------------------------

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	f, err := tokens.Read(s.TokensFile)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.fail(w, r, "", err)
		return
	}
	out := []clientView{}
	if f != nil {
		now := s.Now()
		for i := range f.Clients {
			out = append(out, view(&f.Clients[i], now))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": out})
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	f, err := tokens.Read(s.TokensFile)
	if err != nil {
		s.fail(w, r, id, err)
		return
	}
	c := f.Find(id)
	if c == nil {
		s.fail(w, r, id, fmt.Errorf("client %q %w", id, tokens.ErrNotFound))
		return
	}
	writeJSON(w, http.StatusOK, view(c, s.Now()))
}

type keyRequest struct {
	PublicKey string `json:"public_key"`
	Note      string `json:"note"`
	Expires   string `json:"expires"` // 90d, 2027-01-31, RFC3339, never
}

type createRequest struct {
	ID            string       `json:"id"`
	Models        []string     `json:"models"`
	RPM           int          `json:"rpm"`
	Burst         int          `json:"burst"`
	MaxConcurrent int          `json:"max_concurrent"`
	Expires       string       `json:"expires"`
	Note          string       `json:"note"`
	PublicKeys    []keyRequest `json:"public_keys"` // optional: require signing from the start
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if !s.decode(w, r, &req) {
		return
	}
	now := s.Now()
	var tok string
	var cv clientView
	err := s.update(true, func(f *tokens.File) error {
		exp, err := tokens.ParseExpiry(req.Expires, now)
		if err != nil {
			return badRequest(err)
		}
		c := tokens.Client{ID: req.ID, Note: req.Note, Models: normModels(req.Models), RPM: req.RPM, Burst: req.Burst, MaxConcurrent: req.MaxConcurrent, ExpiresAt: exp}
		if tok, err = f.Add(c, now); err != nil {
			return err
		}
		for _, k := range req.PublicKeys {
			kexp, err := tokens.ParseExpiry(k.Expires, now)
			if err != nil {
				return badRequest(err)
			}
			if _, err := f.AddKey(req.ID, k.PublicKey, k.Note, kexp, now); err != nil {
				return err
			}
		}
		cv = view(f.Find(req.ID), now)
		return nil
	})
	if err != nil {
		s.fail(w, r, req.ID, err)
		return
	}
	s.applied(r, req.ID, "create")
	writeJSON(w, http.StatusCreated, map[string]any{"client": cv, "token": tok})
}

type patchRequest struct {
	Models        *[]string `json:"models"`
	RPM           *int      `json:"rpm"`
	Burst         *int      `json:"burst"`
	MaxConcurrent *int      `json:"max_concurrent"`
	Expires       *string   `json:"expires"`
	Note          *string   `json:"note"`
}

func (s *Server) patch(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req patchRequest
	if !s.decode(w, r, &req) {
		return
	}
	s.mutate(w, r, id, "update", func(f *tokens.File, c *tokens.Client, now time.Time) error {
		if req.Models != nil {
			c.Models = normModels(*req.Models)
		}
		if req.RPM != nil {
			c.RPM = *req.RPM
		}
		if req.Burst != nil {
			c.Burst = *req.Burst
		}
		if req.MaxConcurrent != nil {
			c.MaxConcurrent = *req.MaxConcurrent
		}
		if req.Note != nil {
			c.Note = *req.Note
		}
		if req.Expires != nil {
			exp, err := tokens.ParseExpiry(*req.Expires, now)
			if err != nil {
				return badRequest(err)
			}
			c.ExpiresAt = exp
		}
		return f.Validate()
	})
}

func (s *Server) setDisabled(disabled bool) http.HandlerFunc {
	action := "enable"
	if disabled {
		action = "revoke"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		s.mutate(w, r, r.PathValue("id"), action, func(_ *tokens.File, c *tokens.Client, _ time.Time) error {
			c.Disabled = disabled
			return nil
		})
	}
}

func (s *Server) remove(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.update(false, func(f *tokens.File) error { return f.Remove(id) }); err != nil {
		s.fail(w, r, id, err)
		return
	}
	s.applied(r, id, "remove")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) rotate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Grace string `json:"grace"` // how long old tokens stay valid; "" or 0 = revoke now
	}
	if !s.decode(w, r, &req) {
		return
	}
	var tok string
	var cv clientView
	now := s.Now()
	err := s.update(false, func(f *tokens.File) error {
		grace := time.Duration(0)
		if req.Grace != "" {
			var err error
			if grace, err = tokens.ParseDuration(req.Grace); err != nil {
				return badRequest(err)
			}
		}
		var err error
		if tok, err = f.Rotate(id, grace, now); err != nil {
			return err
		}
		cv = view(f.Find(id), now)
		return nil
	})
	if err != nil {
		s.fail(w, r, id, err)
		return
	}
	s.applied(r, id, "rotate")
	writeJSON(w, http.StatusOK, map[string]any{"client": cv, "token": tok})
}

func (s *Server) addKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req keyRequest
	if !s.decode(w, r, &req) {
		return
	}
	var k tokens.PublicKey
	var cv clientView
	now := s.Now()
	err := s.update(false, func(f *tokens.File) error {
		exp, err := tokens.ParseExpiry(req.Expires, now)
		if err != nil {
			return badRequest(err)
		}
		if k, err = f.AddKey(id, req.PublicKey, req.Note, exp, now); err != nil {
			return err
		}
		cv = view(f.Find(id), now)
		return nil
	})
	if err != nil {
		s.fail(w, r, id, err)
		return
	}
	s.applied(r, id, "add_key", "key_id", k.ID)
	writeJSON(w, http.StatusCreated, map[string]any{"client": cv, "key": k})
}

func (s *Server) removeKey(w http.ResponseWriter, r *http.Request) {
	id, keyID := r.PathValue("id"), r.PathValue("key")
	allowUnsigned := r.URL.Query().Get("allow_unsigned") == "true"
	err := s.update(false, func(f *tokens.File) error { return f.RemoveKey(id, keyID, allowUnsigned) })
	if err != nil {
		s.fail(w, r, id, err)
		return
	}
	s.applied(r, id, "remove_key", "key_id", keyID)
	w.WriteHeader(http.StatusNoContent)
}

// mutate runs fn on client id under the tokens-file lock and responds with
// the updated client.
func (s *Server) mutate(w http.ResponseWriter, r *http.Request, id, action string, fn func(*tokens.File, *tokens.Client, time.Time) error) {
	now := s.Now()
	var cv clientView
	err := s.update(false, func(f *tokens.File) error {
		c := f.Find(id)
		if c == nil {
			return fmt.Errorf("client %q %w", id, tokens.ErrNotFound)
		}
		if err := fn(f, c, now); err != nil {
			return err
		}
		cv = view(c, now)
		return nil
	})
	if err != nil {
		s.fail(w, r, id, err)
		return
	}
	s.applied(r, id, action)
	writeJSON(w, http.StatusOK, cv)
}

// --- helpers ---------------------------------------------------------------

func (s *Server) applied(r *http.Request, id, action string, extra ...any) {
	if s.Reload != nil {
		s.Reload()
	}
	s.Log.Info("admin change", append([]any{"action", action, "client", id, "remote", remote(r)}, extra...)...)
}

// userError marks failures caused by the request (bad input, unknown or
// duplicate ids) as opposed to I/O problems with the tokens file.
type userError struct{ error }

func (e userError) Unwrap() error { return e.error }

func badRequest(err error) error { return userError{err} }

// update is tokens.Update with every error from fn, and any validation
// failure of its result, attributed to the request.
func (s *Server) update(create bool, fn func(*tokens.File) error) error {
	return tokens.Update(s.TokensFile, create, func(f *tokens.File) error {
		if err := fn(f); err != nil {
			return userError{err}
		}
		if err := f.Validate(); err != nil {
			return userError{err}
		}
		return nil
	})
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, id string, err error) {
	var ue userError
	switch {
	case errors.Is(err, fs.ErrNotExist): // no tokens file yet
		writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("client %q not found", id))
	case errors.Is(err, tokens.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, tokens.ErrExists):
		writeError(w, http.StatusConflict, "already_exists", err.Error())
	case errors.Is(err, tokens.ErrLastKey):
		writeError(w, http.StatusConflict, "last_signing_key", err.Error())
	case errors.As(err, &ue):
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
	default:
		s.Log.Error("admin request failed", "method", r.Method, "path", truncate(r.URL.Path, 128), "client", id, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "internal_error", "Could not update the tokens file; see the proxy log.")
	}
}

func (s *Server) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "Request body too large.")
		return false
	}
	if len(bytes.TrimSpace(b)) == 0 {
		b = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func normModels(m []string) []string {
	return tokens.ParseModels(strings.Join(m, ","))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

// remote is the client address for the audit log; behind Caddy that is
// the X-Forwarded-For Caddy sets (it replaces any client-supplied value).
func remote(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return truncate(xff, 128)
	}
	return r.RemoteAddr
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
