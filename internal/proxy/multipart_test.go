package proxy

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"sync/atomic"
	"testing"
)

func upload(t *testing.T, models []string, modelFile, encoded bool) (string, string) {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	for _, model := range models {
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", `form-data; name="model"`)
		if modelFile {
			h.Set("Content-Disposition", `form-data; name="model"; filename="model.txt"`)
		}
		if encoded {
			h.Set("Content-Transfer-Encoding", "quoted-printable")
		}
		part, err := w.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(part, model)
	}
	f, err := w.CreateFormFile("file", "fixture.wav")
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte{0, 255, 128, 42})
	w.WriteField("timestamp_granularities[]", "word")
	w.WriteField("timestamp_granularities[]", "segment")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String(), w.FormDataContentType()
}

func TestMultipartModelPolicy(t *testing.T) {
	for _, path := range []string{"images/edits", "audio/transcriptions", "audio/translations"} {
		t.Run(path, func(t *testing.T) {
			good, ct := upload(t, []string{"gpt-4o"}, false, false)
			var calls atomic.Int64
			e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body, _ := io.ReadAll(r.Body)
				if string(body) != good || r.Header.Get("Content-Type") != ct {
					t.Error("multipart upload changed")
				}
				fmt.Fprint(w, `{"text":"fixture"}`)
			}), func(o *Options) { o.Routes = append(o.Routes, "POST /v1/"+path) })
			resp, _ := e.do("POST", "/v1/"+path, e.tok["alice"], good, "Content-Type", ct)
			if resp.StatusCode != 200 {
				t.Fatalf("valid upload: %d", resp.StatusCode)
			}
			for _, tc := range []struct {
				models        []string
				file, encoded bool
				status        int
			}{
				{nil, false, false, 400},
				{[]string{"o3"}, false, false, 403},
				{[]string{"gpt-4o", "o3"}, false, false, 400},
				{[]string{"gpt-4o"}, true, false, 400},
				{[]string{"gpt-4o"}, false, true, 400},
				{[]string{strings.Repeat("x", 1025)}, false, false, 400},
			} {
				body, typ := upload(t, tc.models, tc.file, tc.encoded)
				resp, _ = e.do("POST", "/v1/"+path, e.tok["alice"], body, "Content-Type", typ)
				if resp.StatusCode != tc.status {
					t.Errorf("invalid upload: got %d want %d", resp.StatusCode, tc.status)
				}
			}
			for _, typ := range []string{"multipart/form-data", "multipart/form-data; boundary=wrong"} {
				resp, _ = e.do("POST", "/v1/"+path, e.tok["alice"], good, "Content-Type", typ)
				if resp.StatusCode != 400 {
					t.Errorf("malformed multipart: %d", resp.StatusCode)
				}
			}
			ambiguous := strings.Replace(good, `name="file"; filename="fixture.wav"`, "name=\"file\"; filename=\"fixture.wav\"\r\nContent-Disposition: form-data; name=\"model\"", 1)
			resp, _ = e.do("POST", "/v1/"+path, e.tok["alice"], ambiguous, "Content-Type", ct)
			if resp.StatusCode != 400 {
				t.Errorf("ambiguous part disposition: %d", resp.StatusCode)
			}
			if calls.Load() != 1 {
				t.Fatal("invalid multipart reached upstream")
			}
		})
	}
}
