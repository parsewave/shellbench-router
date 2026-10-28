package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
)

type bodyInfo struct {
	model    string
	hasModel bool
	stream   bool
}

// Inspect without rebuilding the upload: file bytes and repeated SDK fields
// must reach the provider unchanged. Never materialize files or spill to disk.
func inspectMultipart(b []byte, boundary string) (bodyInfo, error) {
	var info bodyInfo
	r := multipart.NewReader(bytes.NewReader(b), boundary)
	for {
		part, err := r.NextRawPart()
		if err == io.EOF {
			return info, nil
		}
		if err != nil {
			return info, errors.New("malformed multipart request body")
		}
		// Disposition ambiguity must not let proxy and provider pick different
		// field names from the same part and disagree about the model.
		if len(part.Header.Values("Content-Disposition")) != 1 || part.FormName() == "" {
			return info, errors.New("multipart part requires one named Content-Disposition")
		}
		if part.FormName() != "model" {
			continue
		}
		if info.hasModel || part.FileName() != "" || len(part.Header.Values("Content-Transfer-Encoding")) != 0 {
			return info, errors.New("multipart body requires one non-file model field")
		}
		value, err := io.ReadAll(io.LimitReader(part, 1025))
		if err != nil || len(value) == 0 || len(value) > 1024 {
			return info, errors.New("multipart model must contain 1 to 1024 bytes")
		}
		info.model, info.hasModel = string(value), true
	}
}

// inspectJSON extracts the top-level "model" and "stream" fields from a JSON
// request body without decoding the rest of it.
//
// It deliberately differs from encoding/json's struct decoding, which matches
// keys case-insensitively: {"model":"o3","MODEL":"gpt-4o"} would decode as
// gpt-4o in Go while the upstream sees o3. Here keys must equal "model"
// exactly (after JSON unescaping), and a duplicate "model" key is rejected,
// so the proxy and upstream cannot disagree about which model is requested.
func inspectJSON(b []byte) (bodyInfo, error) {
	var info bodyInfo
	if !json.Valid(b) {
		return info, errors.New("request body is not valid JSON")
	}
	i := skipWS(b, 0)
	if b[i] != '{' {
		return info, errors.New("request body must be a JSON object")
	}
	i++
	for {
		i = skipWS(b, i)
		if b[i] == '}' {
			return info, nil
		}
		ks := i
		i = skipString(b, i)
		key := b[ks:i]
		i = skipWS(b, skipWS(b, i)+1) // past ':'
		vs := i
		i = skipValue(b, i)
		val := b[vs:i]

		name, err := decodeKey(key)
		if err != nil {
			return info, err
		}
		switch name {
		case "model":
			if info.hasModel {
				return info, errors.New(`request body contains more than one "model" field`)
			}
			if val[0] != '"' {
				return info, errors.New(`"model" must be a string`)
			}
			if err := json.Unmarshal(val, &info.model); err != nil {
				return info, errors.New(`"model" must be a string`)
			}
			info.hasModel = true
		case "stream":
			var s bool
			if json.Unmarshal(val, &s) == nil {
				info.stream = s
			}
		}
		i = skipWS(b, i)
		if b[i] != ',' {
			return info, nil // '}' — guaranteed by json.Valid
		}
		i++
	}
}

func decodeKey(raw []byte) (string, error) {
	inner := raw[1 : len(raw)-1]
	if bytes.IndexByte(inner, '\\') < 0 {
		return string(inner), nil
	}
	var s string
	err := json.Unmarshal(raw, &s)
	return s, err
}

// The scanners below assume syntactically valid JSON (checked by json.Valid).

func skipWS(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return i
}

// skipString returns the index just past the string starting at b[i] == '"'.
func skipString(b []byte, i int) int {
	for i++; i < len(b); i++ {
		switch b[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return i
}

// skipValue returns the index just past the value starting at b[i].
func skipValue(b []byte, i int) int {
	switch b[i] {
	case '"':
		return skipString(b, i)
	case '{', '[':
		depth := 0
		for i < len(b) {
			switch b[i] {
			case '"':
				i = skipString(b, i)
				continue
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return i + 1
				}
			}
			i++
		}
		return i
	default:
		for i < len(b) {
			switch b[i] {
			case ',', '}', ']', ' ', '\t', '\n', '\r':
				return i
			}
			i++
		}
		return i
	}
}
