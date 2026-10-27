package proxy

import (
	"fmt"
	"net/url"
	"strings"
)

// Route is one explicitly allowed upstream endpoint, e.g. "POST /v1/chat/completions".
// A `*` segment matches exactly one non-empty, safe path segment.
type Route struct {
	Method  string
	Pattern string
	segs    []string
}

var allowedMethods = map[string]bool{"GET": true, "POST": true, "DELETE": true, "PUT": true, "PATCH": true}

// ParseRoutes compiles route specs of the form "METHOD /v1/path/*".
func ParseRoutes(specs []string) ([]Route, error) {
	var out []Route
	for _, spec := range specs {
		method, p, ok := strings.Cut(strings.TrimSpace(spec), " ")
		method = strings.ToUpper(method)
		p = strings.TrimSpace(p)
		if !ok || !allowedMethods[method] {
			return nil, fmt.Errorf("route %q: want \"METHOD /v1/path\"", spec)
		}
		if !strings.HasPrefix(p, "/v1/") || strings.HasSuffix(p, "/") {
			return nil, fmt.Errorf("route %q: path must start with /v1/ and not end with /", spec)
		}
		segs := strings.Split(p[1:], "/")
		for _, s := range segs {
			if s != "*" && !safeSegment(s) {
				return nil, fmt.Errorf("route %q: invalid segment %q", spec, s)
			}
		}
		out = append(out, Route{Method: method, Pattern: method + " " + p, segs: segs})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no routes configured")
	}
	return out, nil
}

// matchRoute returns the route for method+path, or nil. Paths with unusual
// encodings (%2F etc.), empty segments, or dot segments never match, so a
// request can only ever reach an explicitly configured upstream endpoint.
func matchRoute(routes []Route, method string, u *url.URL) *Route {
	if u.RawPath != "" || !strings.HasPrefix(u.Path, "/v1/") {
		return nil
	}
	segs := strings.Split(u.Path[1:], "/")
	for _, s := range segs {
		if !safeSegment(s) {
			return nil
		}
	}
	for i := range routes {
		r := &routes[i]
		if r.Method != method || len(r.segs) != len(segs) {
			continue
		}
		ok := true
		for j, s := range r.segs {
			if s != "*" && s != segs[j] {
				ok = false
				break
			}
		}
		if ok {
			return r
		}
	}
	return nil
}

func safeSegment(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == ':':
		default:
			return false
		}
	}
	return true
}
