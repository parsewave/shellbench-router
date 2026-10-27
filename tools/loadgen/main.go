// Command loadgen drives concurrent chat-completion requests at a base URL
// and reports throughput, latency percentiles and a status breakdown. Run one
// instance per load-generator container; -csv writes every request so
// percentiles can be computed across all instances afterwards.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type result struct {
	start      time.Time
	lat, ttfb  time.Duration
	status     int
	errKind    string
	worker     int
	streamDone bool
}

func main() {
	base := flag.String("url", "http://127.0.0.1:8080/v1", "base URL")
	token := flag.String("token", os.Getenv("LOADGEN_TOKEN"), "bearer token (or LOADGEN_TOKEN)")
	conc := flag.Int("c", 50, "concurrent workers")
	dur := flag.Duration("d", 10*time.Second, "test duration")
	stream := flag.Bool("stream", false, "use SSE streaming")
	model := flag.String("model", "gpt-4o-mini", "model")
	maxTokens := flag.Int("max-tokens", 0, "max_tokens (0 = omit)")
	prompt := flag.String("prompt", "benchmark prompt", "user message")
	label := flag.String("label", "", "label for output")
	cacert := flag.String("cacert", "", "PEM CA bundle to trust (e.g. Caddy's local CA)")
	insecure := flag.Bool("insecure", false, "skip TLS verification")
	reqTimeout := flag.Duration("timeout", 5*time.Minute, "per-request timeout")
	csvPath := flag.String("csv", "", "write one CSV row per request")
	asJSON := flag.Bool("json", false, "print the summary as JSON")
	api := flag.String("api", "chat", "chat (/chat/completions) or responses (/responses)")
	errBackoff := flag.Duration("error-backoff", 0, "pause a worker this long after a failed request (avoid hammering a real upstream)")
	flag.Parse()

	path := "/chat/completions"
	req := map[string]any{"model": *model, "stream": *stream, "messages": []any{map[string]any{"role": "user", "content": *prompt}}}
	if *stream {
		req["stream_options"] = map[string]any{"include_usage": true}
	}
	if *maxTokens > 0 {
		req["max_tokens"] = *maxTokens
	}
	switch *api {
	case "chat":
	case "responses":
		path = "/responses"
		// List form: some relays (e.g. PackyAPI channels) reject string input.
		req = map[string]any{"model": *model, "stream": *stream, "input": []any{map[string]any{"role": "user", "content": *prompt}}}
		if *maxTokens > 0 {
			req["max_output_tokens"] = *maxTokens
		}
	default:
		fatal(fmt.Errorf("-api must be chat or responses"))
	}
	body, _ := json.Marshal(req)

	tlsCfg := &tls.Config{InsecureSkipVerify: *insecure}
	if *cacert != "" {
		pem, err := os.ReadFile(*cacert)
		if err != nil {
			fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		tlsCfg.RootCAs = pool
	}
	tr := &http.Transport{MaxIdleConns: 8192, MaxIdleConnsPerHost: 8192, DisableCompression: true, TLSClientConfig: tlsCfg, ForceAttemptHTTP2: false}
	client := &http.Client{Transport: tr, Timeout: *reqTimeout}

	ctx, cancel := context.WithTimeout(context.Background(), *dur)
	defer cancel()
	var (
		mu      sync.Mutex
		results []result
		wg      sync.WaitGroup
		active  atomic.Int64
	)
	start := time.Now()
	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			var mine []result
			for ctx.Err() == nil {
				active.Add(1)
				r := one(ctx, client, *base+path, *token, body, *stream)
				active.Add(-1)
				if r.errKind == "aborted_by_test_end" {
					break
				}
				r.worker = worker
				mine = append(mine, r)
				if *errBackoff > 0 && (r.status != 200 || r.errKind != "") {
					select {
					case <-time.After(*errBackoff):
					case <-ctx.Done():
					}
				}
			}
			mu.Lock()
			results = append(results, mine...)
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	if *csvPath != "" {
		f, err := os.Create(*csvPath)
		if err != nil {
			fatal(err)
		}
		w := bufio.NewWriter(f)
		fmt.Fprintln(w, "label,worker,start_unix_ms,latency_ms,ttfb_ms,status,error")
		for _, r := range results {
			fmt.Fprintf(w, "%s,%d,%d,%.3f,%.3f,%d,%s\n", *label, r.worker, r.start.UnixMilli(), ms(r.lat), ms(r.ttfb), r.status, r.errKind)
		}
		w.Flush()
		f.Close()
	}

	var lat, ttfb []time.Duration
	statuses := map[string]int{}
	ok := 0
	for _, r := range results {
		key := fmt.Sprint(r.status)
		if r.errKind != "" {
			key = r.errKind
		}
		statuses[key]++
		if r.status == 200 && r.errKind == "" {
			ok++
			lat = append(lat, r.lat)
			ttfb = append(ttfb, r.ttfb)
		}
	}
	slices.Sort(lat)
	slices.Sort(ttfb)
	sum := map[string]any{
		"label": *label, "concurrency": *conc, "stream": *stream, "duration_s": elapsed.Seconds(),
		"requests": len(results), "ok": ok, "rps_ok": float64(ok) / elapsed.Seconds(), "statuses": statuses,
		"p50_ms": pct(lat, .50), "p90_ms": pct(lat, .90), "p95_ms": pct(lat, .95), "p99_ms": pct(lat, .99), "max_ms": pct(lat, 1),
		"ttfb_p50_ms": pct(ttfb, .50), "ttfb_p95_ms": pct(ttfb, .95), "ttfb_p99_ms": pct(ttfb, .99),
	}
	if *asJSON {
		json.NewEncoder(os.Stdout).Encode(sum)
		return
	}
	fmt.Printf("%-22s c=%-4d stream=%-5v reqs=%-7d ok=%-7d rps=%-8.1f p50=%-8.1f p95=%-8.1f p99=%-8.1f max=%-8.1f ttfb_p50=%-8.1f ttfb_p99=%-8.1f statuses=%v\n",
		*label, *conc, *stream, len(results), ok, sum["rps_ok"], sum["p50_ms"], sum["p95_ms"], sum["p99_ms"], sum["max_ms"], sum["ttfb_p50_ms"], sum["ttfb_p99_ms"], statuses)
}

func one(ctx context.Context, client *http.Client, url, token string, body []byte, stream bool) result {
	r := result{start: time.Now()}
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		r.lat = time.Since(r.start)
		if ctx.Err() != nil {
			r.errKind = "aborted_by_test_end"
		} else {
			r.errKind = classify(err)
		}
		return r
	}
	defer resp.Body.Close()
	r.status = resp.StatusCode
	if stream && resp.StatusCode == 200 {
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		for sc.Scan() {
			line := sc.Text()
			if r.ttfb == 0 && strings.HasPrefix(line, "data: ") {
				r.ttfb = time.Since(r.start)
			}
			// Chat Completions ends with [DONE]; the Responses API with a
			// response.completed event.
			if line == "data: [DONE]" || line == "event: response.completed" {
				r.streamDone = true
			}
		}
		if err := sc.Err(); err != nil || !r.streamDone {
			if ctx.Err() != nil {
				r.errKind = "aborted_by_test_end"
			} else {
				r.errKind = "stream_truncated"
			}
		}
	} else {
		io.Copy(io.Discard, resp.Body)
		r.ttfb = time.Since(r.start)
	}
	r.lat = time.Since(r.start)
	return r
}

func classify(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "Client.Timeout"), strings.Contains(s, "deadline exceeded"):
		return "client_timeout"
	case strings.Contains(s, "connection refused"):
		return "conn_refused"
	case strings.Contains(s, "connection reset"):
		return "conn_reset"
	case strings.Contains(s, "EOF"):
		return "eof"
	case strings.Contains(s, "tls"), strings.Contains(s, "x509"):
		return "tls_error"
	}
	return "net_error"
}

func pct(s []time.Duration, p float64) float64 {
	if len(s) == 0 {
		return 0
	}
	return ms(s[min(len(s)-1, int(float64(len(s))*p))])
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
