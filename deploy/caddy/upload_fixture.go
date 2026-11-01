// Secretless scaled HTTP/1 lifecycle diagnosis, not a router integration test.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const idle = 200 * time.Millisecond
const hold = 4 * time.Second
const fakeKey = "fixture-only-not-a-credential"

var variants = []struct {
	name               string
	duplex             bool
	readIdle, readHard time.Duration
}{
	{"no_duplex_outer_first", false, 100 * time.Millisecond, 0},
	{"no_duplex_router_first", false, 400 * time.Millisecond, 0},
	{"duplex_outer_first", true, 100 * time.Millisecond, 0},
	{"duplex_router_first", true, 400 * time.Millisecond, 0},
	{"no_duplex_bounded_outer", false, 400 * time.Millisecond, 2400 * time.Millisecond},
}

var outputMu sync.Mutex

func emit(v any)             { outputMu.Lock(); defer outputMu.Unlock(); _ = json.NewEncoder(os.Stdout).Encode(v) }
func ms(t time.Time) float64 { return float64(time.Since(t).Microseconds()) / 1000 }
func errKind(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, io.EOF) {
		return "eof"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	return "other_io_error"
}

type observation struct {
	mu            sync.Mutex
	start         time.Time
	data          map[string]any
	backendClosed chan struct{}
}

func (o *observation) set(k string, v any) { o.mu.Lock(); defer o.mu.Unlock(); o.data[k] = v }
func (o *observation) mark(k string)       { o.set(k, ms(o.start)) }
func (o *observation) snapshot() map[string]any {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := map[string]any{}
	for k, v := range o.data {
		out[k] = v
	}
	return out
}

type fixture struct {
	observations       sync.Map
	connections        sync.Map
	active             atomic.Int32
	candidateQualified atomic.Int32
}

// Mirrors the admitted router's positive-read renewal and 10x total bound.
type uploadReader struct {
	io.Reader
	rc    *http.ResponseController
	total time.Time
}

func (r *uploadReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 && err == nil {
		deadline := time.Now().Add(idle)
		if r.total.Before(deadline) {
			deadline = r.total
		}
		_ = r.rc.SetReadDeadline(deadline)
	}
	return n, err
}
func readUpload(w http.ResponseWriter, r *http.Request) (body []byte, err error) {
	rc := http.NewResponseController(w)
	defer func() {
		if err != nil {
			w.Header().Set("Connection", "close")
			_ = rc.SetReadDeadline(time.Now())
		} else {
			_ = rc.SetReadDeadline(time.Time{})
		}
	}()
	now := time.Now()
	_ = rc.SetReadDeadline(now.Add(idle))
	return io.ReadAll(&uploadReader{Reader: http.MaxBytesReader(w, r.Body, 1<<20), rc: rc, total: now.Add(10 * idle)})
}
func (f *fixture) handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/ready" {
		w.WriteHeader(204)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+fakeKey {
		w.WriteHeader(401)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/reuse" {
		_, _ = io.WriteString(w, "ok")
		return
	}
	value, ok := f.observations.Load(strings.TrimPrefix(r.URL.Path, "/"))
	if !ok {
		w.WriteHeader(404)
		return
	}
	o := value.(*observation)
	f.connections.Store(r.RemoteAddr, o)
	f.active.Add(1)
	o.mark("handler_started_ms")
	defer func() { o.mark("handler_returned_ms"); f.active.Add(-1) }()
	status := 0
	for _, early := range []int{401, 413, 503} {
		if strings.HasSuffix(r.URL.Path, fmt.Sprintf("-early%d", early)) {
			status = early
		}
	}
	if status != 0 {
		// Guarantee a finite early backend response; Caddy owns the unfinished outer body.
		w.Header().Set("Connection", "close")
		_ = http.NewResponseController(w).SetReadDeadline(time.Now())
	} else {
		body, err := readUpload(w, r)
		o.mark("body_read_done_ms")
		o.set("read_error", errKind(err))
		o.set("bytes_read", len(body))
		switch {
		case err != nil:
			status = 400
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				status = 408
			}
		case !json.Valid(body):
			status = 400
		default:
			status = 200
		}
	}
	o.set("status", status)
	if status != 200 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		err := json.NewEncoder(w).Encode(map[string]any{"error": status})
		o.mark("error_write_returned_ms")
		o.set("write_error", errKind(err))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	_, _ = io.WriteString(w, "data: {\"type\":\"response.created\"}\n\n")
	w.(http.Flusher).Flush()
	select {
	case <-time.After(2500 * time.Millisecond):
		_, err := io.WriteString(w, "data: {\"type\":\"response.completed\"}\n\n")
		o.set("write_error", errKind(err))
	case <-r.Context().Done():
		o.set("sse_cancelled", true)
	}
}

func caddyConfig() []byte {
	servers := map[string]any{}
	for i, variant := range variants {
		server := map[string]any{"listen": []string{fmt.Sprintf("127.0.0.1:%d", 18080+i)},
			"automatic_https": map[string]any{"disable": true},
			"routes": []any{map[string]any{"handle": []any{map[string]any{"handler": "reverse_proxy",
				"upstreams": []any{map[string]any{"dial": "127.0.0.1:18090"}}}}}}}
		if variant.duplex {
			server["enable_full_duplex"] = true
		}
		server["read_idle_timeout"] = int64(variant.readIdle)
		if variant.readHard != 0 {
			server["read_timeout"] = int64(variant.readHard)
		}
		servers[variant.name] = server
	}
	data, _ := json.Marshal(map[string]any{"admin": map[string]any{"disabled": true},
		"apps": map[string]any{"http": map[string]any{"servers": servers}}})
	return data
}

func writeBody(conn net.Conn, chunked bool, kind string, stop <-chan struct{}) error {
	part := func(s string) error {
		if chunked {
			s = fmt.Sprintf("%x\r\n%s\r\n", len(s), s)
		}
		_, err := io.WriteString(conn, s)
		return err
	}
	if kind == "sse" {
		if err := part(`{"input":"ok"}`); err != nil {
			return err
		}
	} else {
		if err := part("{"); err != nil {
			return err
		}
		if kind != "progress" && kind != "drip" {
			return nil
		}
		ticker := time.NewTicker(40 * time.Millisecond)
		defer ticker.Stop()
		for n := 0; ; n++ {
			select {
			case <-stop:
				return nil
			case <-ticker.C:
			}
			if err := part(" "); err != nil {
				return err
			}
			if kind == "progress" && n == 12 {
				break
			}
		}
		if err := part("!"); err != nil {
			return err
		}
	}
	if chunked {
		_, err := io.WriteString(conn, "0\r\n\r\n")
		return err
	}
	return nil
}

func (f *fixture) probe(variant int, framing, kind string) {
	name := variants[variant].name
	id := name + "-" + framing + "-" + kind
	start := time.Now()
	o := &observation{start: start, data: map[string]any{}, backendClosed: make(chan struct{})}
	f.observations.Store(id, o)
	result := map[string]any{"event": "case", "variant": name, "framing": framing, "kind": kind,
		"headers_received": false, "body_complete": false, "server_eof_before_client_close": false}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", 18080+variant), time.Second)
	if err != nil {
		result["dial_error"] = errKind(err)
		emit(result)
		return
	}
	stop, written := make(chan struct{}), make(chan error, 1)
	var once sync.Once
	stopWriter := func() { once.Do(func() { close(stop) }) }
	defer func() {
		stopWriter()
		result["writer_error"] = errKind(<-written)
		// This snapshot precedes client Close. Only a server EOF proves finite teardown.
		backend := o.snapshot()
		result["backend_before_client_close"] = backend
		_, returned := backend["handler_returned_ms"]
		_, closed := backend["connection_closed_ms"]
		result["backend_handler_returned"], result["backend_connection_closed"] = returned, closed
		expected := map[string]int{"stalled": 408, "drip": 408, "early401": 401, "early413": 413, "early503": 503, "progress": 400, "sse": 200}[kind]
		result["expected_status"] = expected
		qualified := result["headers_received"] == true && result["body_complete"] == true && result["status"] == expected && returned
		if kind == "progress" || kind == "sse" {
			qualified = qualified && result["reuse_200"] == true && (kind != "sse" || result["sse_completed"] == true)
		} else {
			qualified = qualified && result["server_eof_before_client_close"] == true && closed
		}
		result["fixture_contract_met"] = qualified
		if variant == len(variants)-1 && qualified {
			f.candidateQualified.Add(1)
		}
		result["observation_cutoff_ms"] = ms(start)
		_ = conn.Close()
		emit(result)
	}()
	_ = conn.SetDeadline(start.Add(hold))
	length := 100
	if kind == "progress" {
		length = 15
	}
	if kind == "sse" {
		length = len(`{"input":"ok"}`)
	}
	if kind == "drip" {
		length = 1000
	}
	headers := fmt.Sprintf("Content-Length: %d\r\n", length)
	if framing == "chunked" {
		headers = "Transfer-Encoding: chunked\r\n"
	}
	_, err = fmt.Fprintf(conn, "POST /%s HTTP/1.1\r\nHost: fixture.invalid\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\n%s\r\n", id, fakeKey, headers)
	if err != nil {
		written <- err
		result["send_headers_error"] = errKind(err)
		return
	}
	go func() { written <- writeBody(conn, framing == "chunked", kind, stop) }()
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	result["headers_observed_ms"], result["headers_error"] = ms(start), errKind(err)
	if err != nil {
		return
	}
	stopWriter()
	result["headers_received"], result["status"], result["response_close"] = true, response.StatusCode, response.Close
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	result["body_observed_ms"], result["body_error"] = ms(start), errKind(err)
	result["body_complete"] = err == nil && len(body) < 4096
	if err != nil {
		return
	}
	if kind == "progress" || kind == "sse" {
		result["sse_completed"] = bytes.Contains(body, []byte("response.completed"))
		_, err = fmt.Fprintf(conn, "GET /reuse HTTP/1.1\r\nHost: fixture.invalid\r\nAuthorization: Bearer %s\r\n\r\n", fakeKey)
		if err != nil {
			result["reuse_error"] = errKind(err)
			return
		}
		reused, err := http.ReadResponse(reader, nil)
		result["reuse_error"] = errKind(err)
		if err == nil {
			_, err = io.Copy(io.Discard, io.LimitReader(reused.Body, 4096))
			result["reuse_200"] = reused.StatusCode == 200 && err == nil
		}
		return
	}
	// The client leaves the unfinished request and TCP socket open after any error response.
	_, err = reader.ReadByte()
	result["tcp_observed_ms"], result["tcp_error"] = ms(start), errKind(err)
	result["server_eof_before_client_close"] = errors.Is(err, io.EOF)
	if errors.Is(err, io.EOF) {
		// Go may send FIN before its 500ms reset-avoidance delay ends.
		// Await actual backend teardown while the client remains open.
		timer := time.NewTimer(min(time.Second, time.Until(start.Add(hold))))
		defer timer.Stop()
		select {
		case <-o.backendClosed:
		case <-timer.C:
		}
	}
}

func run() error {
	version, err := exec.Command("/usr/bin/caddy", "version").Output()
	if err != nil || !strings.HasPrefix(string(version), "v2.11.7 ") {
		return errors.New("unexpected_caddy_binary")
	}
	f := &fixture{}
	ln, err := net.Listen("tcp", "127.0.0.1:18090")
	if err != nil {
		return errors.New("backend_listen_failed")
	}
	backend := &http.Server{Handler: http.HandlerFunc(f.handler), ReadHeaderTimeout: time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	backend.ConnState = func(c net.Conn, s http.ConnState) {
		if s == http.StateClosed {
			if value, ok := f.connections.LoadAndDelete(c.RemoteAddr().String()); ok {
				o := value.(*observation)
				o.mark("connection_closed_ms")
				close(o.backendClosed)
			}
		}
	}
	go func() { _ = backend.Serve(ln) }()
	defer backend.Close()
	if err := os.WriteFile("/tmp/caddy-fixture.json", caddyConfig(), 0600); err != nil {
		return errors.New("config_write_failed")
	}
	command := exec.Command("/usr/bin/caddy", "run", "--config", "/tmp/caddy-fixture.json")
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Start(); err != nil {
		return errors.New("caddy_start_failed")
	}
	ended := make(chan struct{})
	go func() { _ = command.Wait(); close(ended) }()
	defer func() {
		_ = command.Process.Signal(syscall.SIGTERM)
		select {
		case <-ended:
		case <-time.After(time.Second):
			_ = command.Process.Kill()
			<-ended
		}
	}()
	client := &http.Client{Timeout: 100 * time.Millisecond, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	deadline := time.Now().Add(3 * time.Second)
	for {
		ready := true
		for port := 18080; port < 18080+len(variants); port++ {
			r, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/ready", port))
			if err != nil {
				ready = false
			} else {
				_ = r.Body.Close()
				ready = ready && r.StatusCode == 204
			}
		}
		if ready {
			break
		}
		select {
		case <-ended:
			return errors.New("caddy_exited_before_ready")
		default:
		}
		if time.Now().After(deadline) {
			return errors.New("caddy_readiness_timeout")
		}
		time.Sleep(20 * time.Millisecond)
	}
	emit(map[string]any{"event": "started", "caddy_version": strings.TrimSpace(string(version)), "backend_idle_ms": 200,
		"backend_total_ms": 2000, "client_hold_ms": hold.Milliseconds(), "sse_ms": 2500, "mock_backend": true, "tls": false, "cases": len(variants) * 8})
	var wg sync.WaitGroup
	for variant := range variants {
		for _, test := range [][2]string{{"fixed", "stalled"}, {"chunked", "stalled"}, {"fixed", "early401"}, {"fixed", "early413"}, {"fixed", "early503"}, {"fixed", "progress"}, {"fixed", "drip"}, {"fixed", "sse"}} {
			wg.Add(1)
			go func() { defer wg.Done(); f.probe(variant, test[0], test[1]) }()
		}
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	select {
	case <-done:
	case <-ctx.Done():
		return errors.New("fixture_bound_exceeded")
	case <-ended:
		return errors.New("caddy_exited_during_fixture")
	}
	emit(map[string]any{"event": "complete", "active_backend_handlers_after_clients_closed": f.active.Load(),
		"candidate_fixture_contracts_met": f.candidateQualified.Load() == 8, "candidate_cases_qualified": f.candidateQualified.Load(),
		"meaning": "candidate must satisfy every response, cleanup, streaming and reuse contract"})
	if f.candidateQualified.Load() != 8 {
		return errors.New("candidate_contract_failed")
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		emit(map[string]any{"event": "failed", "code": err.Error()})
		os.Exit(1)
	}
}
