package proxy

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"oaiproxy/internal/mockupstream"
)

// BenchmarkProxyChat measures the full proxy path (auth, inspection, header
// rewrite, upstream round trip, response copy) against an in-process mock.
// Compare with BenchmarkDirectChat for the proxy's own overhead.
func BenchmarkProxyChat(b *testing.B)  { benchChat(b, true, false) }
func BenchmarkDirectChat(b *testing.B) { benchChat(b, false, false) }
func BenchmarkProxySSE(b *testing.B)   { benchChat(b, true, true) }
func BenchmarkDirectSSE(b *testing.B)  { benchChat(b, false, true) }

func benchChat(b *testing.B, viaProxy, stream bool) {
	t := &testing.T{}
	e := newEnv(t, &mockupstream.Server{Key: upstreamKey}, func(o *Options) { o.AccessLog = nil; o.Logger = discardLogger() })
	base, tok := e.srv.URL, e.tok["carol"]
	if !viaProxy {
		base, tok = e.opt.Upstream.Scheme+"://"+e.opt.Upstream.Host, upstreamKey
	}
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}],"stream":` + map[bool]string{true: "true", false: "false"}[stream] + `}`
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 256, DisableCompression: true}}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+tok)
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				b.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 {
				b.Fatalf("status %d", resp.StatusCode)
			}
		}
	})
	b.StopTimer()
	e.srv.Close()
}

func BenchmarkInspectJSON(b *testing.B) {
	body := []byte(`{"messages":[{"role":"user","content":"` + strings.Repeat("lorem ipsum ", 4000) + `"}],"model":"gpt-4o","stream":true}`)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := inspectJSON(body); err != nil {
			b.Fatal(err)
		}
	}
}
