package proxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

func searchObject(b []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errors.New("search fields must be objects")
	}
	out := make(map[string]json.RawMessage)
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return nil, errors.New("invalid search object")
		}
		name, ok := key.(string)
		if !ok || out[name] != nil {
			return nil, errors.New("duplicate search field")
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, errors.New("invalid search field")
		}
		out[name] = value
	}
	if _, err := d.Token(); err != nil {
		return nil, errors.New("invalid search object")
	}
	return out, nil
}

// Alpha search references belong to a provider session. Derive its namespace
// from the authenticated caller and fixed upstream owner, never caller identity
// headers. Rotation deliberately starts a fresh namespace; no session sidecar.
func scopedSearch(body []byte, caller, upstream, org, project, key string) ([]byte, error) {
	doc, err := searchObject(body)
	if err != nil {
		return nil, err
	}
	var id string
	if json.Unmarshal(doc["id"], &id) != nil || strings.TrimSpace(id) == "" || len(id) > 256 {
		return nil, errors.New("search requires a session id of 1 to 256 bytes")
	}
	if doc["stream"] != nil || doc["background"] != nil {
		return nil, errors.New("standalone search is a unary operation")
	}
	commands, err := searchObject(doc["commands"])
	if err != nil {
		return nil, err
	}
	count := 0
	for name, raw := range commands {
		if name == "response_length" {
			var value string
			if json.Unmarshal(raw, &value) != nil || (value != "short" && value != "medium" && value != "long") {
				return nil, errors.New("invalid search response_length")
			}
			continue
		}
		if name != "search_query" && name != "open" && name != "click" && name != "find" {
			return nil, errors.New("only text search, open, click and find are supported")
		}
		var ops []json.RawMessage
		if json.Unmarshal(raw, &ops) != nil || len(ops) == 0 || len(ops) > 8 {
			return nil, errors.New("search requires 1 to 8 operations per command")
		}
		for _, op := range ops {
			fields, err := searchObject(op)
			if err != nil {
				return nil, err
			}
			field := "ref_id"
			if name == "search_query" {
				field = "q"
			}
			var value string
			if json.Unmarshal(fields[field], &value) != nil || strings.TrimSpace(value) == "" || len(value) > 8192 {
				return nil, errors.New("search text/reference must contain 1 to 8192 bytes")
			}
			if name == "click" {
				var id int64
				if json.Unmarshal(fields["id"], &id) != nil || id < 0 {
					return nil, errors.New("click requires a nonnegative link id")
				}
			}
			if name == "find" && (json.Unmarshal(fields["pattern"], &value) != nil || value == "" || len(value) > 8192) {
				return nil, errors.New("find requires a bounded pattern")
			}
			count++
		}
	}
	if count == 0 {
		return nil, errors.New("search requires at least one text command")
	}
	identity, _ := json.Marshal([]string{"shellbench-search-v1", caller, upstream, org, project, id})
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(identity)
	sum := mac.Sum(nil)
	namespace := fmt.Sprintf("%x-%x-%x-%x-%x", sum[:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
	doc["id"], _ = json.Marshal(namespace)
	return json.Marshal(doc)
}
