package proxy

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"

	"oaiproxy/internal/tokens"
)

var codexClientVersion = regexp.MustCompile(`^[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}$`)

func openAICatalogUpstream(u *url.URL) bool {
	return u.Scheme == "https" && u.Host == "api.openai.com" && u.Path == "/v1" && u.RawPath == "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

// Preserve provider-owned instructions and capability metadata verbatim. Native
// catalogs use slugs rather than public API IDs; both share the token policy.
func filterCodexCatalog(b []byte, pr *tokens.Principal) ([]byte, error) {
	var doc map[string]json.RawMessage
	var models []json.RawMessage
	if json.Unmarshal(b, &doc) != nil || json.Unmarshal(doc["models"], &models) != nil || models == nil {
		return nil, errors.New("invalid native model catalog")
	}
	kept := make([]json.RawMessage, 0, len(models))
	seen := make(map[string]bool, len(models))
	for _, raw := range models {
		var model struct {
			Slug           string `json:"slug"`
			SupportedInAPI bool   `json:"supported_in_api"`
		}
		if json.Unmarshal(raw, &model) != nil || strings.TrimSpace(model.Slug) == "" || seen[model.Slug] {
			return nil, errors.New("invalid native model catalog entry")
		}
		seen[model.Slug] = true
		if model.SupportedInAPI && pr.AllowsModel(model.Slug) {
			kept = append(kept, raw)
		}
	}
	doc["models"], _ = json.Marshal(kept)
	return json.Marshal(doc)
}
