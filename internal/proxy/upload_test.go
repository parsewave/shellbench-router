package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestUploadTimeoutResponse(t *testing.T) {
	for _, framing := range []string{"fixed", "chunked", "expect"} {
		t.Run(framing, func(t *testing.T) {
			var calls atomic.Int32
			e := newEnv(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }), func(o *Options) { o.BodyReadTimeout = 100 * time.Millisecond })
			conn, err := net.Dial("tcp", strings.TrimPrefix(e.srv.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(time.Second))
			br := bufio.NewReader(conn)
			headers := "Content-Length: 65536\r\n"
			if framing == "chunked" {
				headers = "Transfer-Encoding: chunked\r\n"
			}
			if framing == "expect" {
				headers += "Expect: 100-continue\r\n"
			}
			fmt.Fprintf(conn, "POST /v1/responses HTTP/1.1\r\nHost: fixture.invalid\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\n%s\r\n", e.tok["carol"], headers)
			if framing == "expect" {
				resp, err := http.ReadResponse(br, nil)
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != 100 {
					t.Fatalf("continue status %d", resp.StatusCode)
				}
			}
			prefix := "{"
			if framing == "chunked" {
				prefix = "1\r\n{\r\n"
			}
			if _, err := io.WriteString(conn, prefix); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("timeout response did not reach client: %v", err)
			}
			body := readBody(resp)
			if resp.StatusCode != 408 || errCode(t, body) != "invalid_request_body" || !resp.Close {
				t.Fatalf("status %d close %t", resp.StatusCode, resp.Close)
			}
			if _, err := br.ReadByte(); err != io.EOF {
				t.Fatalf("connection not closed after timeout: %v", err)
			}
			waitFor(t, "upload reservations released", func() bool { return e.p.buffered.Load() == 0 && e.p.inflight.Load() == 0 })
			if calls.Load() != 0 {
				t.Fatal("incomplete upload reached upstream")
			}
		})
	}
}

func TestUploadRejectedBodyCloses(t *testing.T) {
	for _, status := range []int{413, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			e := newEnv(t, http.NotFoundHandler(), func(o *Options) {
				o.BodyReadTimeout = 0
				o.MaxRequestBytes = 32768
				if status == 503 {
					o.MaxRequestBytes, o.MaxBufferedBytes = 65536, 1
				}
			})
			conn, err := net.Dial("tcp", strings.TrimPrefix(e.srv.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(time.Second))
			fmt.Fprintf(conn, "POST /v1/responses HTTP/1.1\r\nHost: fixture.invalid\r\nAuthorization: Bearer %s\r\nContent-Length: 65536\r\n\r\n{", e.tok["carol"])
			br := bufio.NewReader(conn)
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("rejection did not reach client: %v", err)
			}
			readBody(resp)
			if resp.StatusCode != status || !resp.Close {
				t.Fatalf("status %d close %t", resp.StatusCode, resp.Close)
			}
			if _, err := br.ReadByte(); err != io.EOF {
				t.Fatalf("rejected connection not closed: %v", err)
			}
			waitFor(t, "rejected upload released", func() bool { return e.p.buffered.Load() == 0 && e.p.inflight.Load() == 0 })
		})
	}
}

func TestUploadProgressAndReuse(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprintf("chunked=%t", chunked), func(t *testing.T) {
			idle := 100 * time.Millisecond
			body := `{"model":"gpt-4o","input":"hi","stream":true}`
			e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					w.Write([]byte(`{"data":[]}`))
					return
				}
				got, _ := io.ReadAll(r.Body)
				if string(got) != body {
					t.Errorf("upstream body changed")
					w.WriteHeader(500)
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, "data: {\"type\":\"response.created\"}\n\n")
				w.(http.Flusher).Flush()
				time.Sleep(3 * idle)
				fmt.Fprint(w, "data: {\"type\":\"response.completed\"}\n\n")
			}), func(o *Options) { o.BodyReadTimeout = idle })
			conn, err := net.Dial("tcp", strings.TrimPrefix(e.srv.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			framing := fmt.Sprintf("Content-Length: %d\r\n", len(body))
			if chunked {
				framing = "Transfer-Encoding: chunked\r\n"
			}
			fmt.Fprintf(conn, "POST /v1/responses HTTP/1.1\r\nHost: fixture.invalid\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\n%s\r\n", e.tok["carol"], framing)
			for i := 0; i < len(body); i += 8 {
				part := body[i:min(i+8, len(body))]
				if chunked {
					part = fmt.Sprintf("%x\r\n%s\r\n", len(part), part)
				}
				if _, err := io.WriteString(conn, part); err != nil {
					t.Fatal(err)
				}
				time.Sleep(40 * time.Millisecond)
			}
			if chunked {
				io.WriteString(conn, "0\r\n\r\n")
			}
			br := bufio.NewReader(conn)
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatal(err)
			}
			answer := readBody(resp)
			if resp.StatusCode != 200 || !strings.Contains(string(answer), "response.completed") {
				t.Fatalf("progressing upload/SSE failed: status %d", resp.StatusCode)
			}
			time.Sleep(2 * idle)
			fmt.Fprintf(conn, "GET /v1/models HTTP/1.1\r\nHost: fixture.invalid\r\nAuthorization: Bearer %s\r\n\r\n", e.tok["carol"])
			resp, err = http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("completed upload left a connection deadline: %v", err)
			}
			readBody(resp)
			if resp.StatusCode != 200 {
				t.Fatalf("reused connection status %d", resp.StatusCode)
			}
		})
	}
}

func TestUploadTotalDeadline(t *testing.T) {
	e := newEnv(t, http.NotFoundHandler(), func(o *Options) { o.BodyReadTimeout = 80 * time.Millisecond })
	conn, err := net.Dial("tcp", strings.TrimPrefix(e.srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(conn, "POST /v1/responses HTTP/1.1\r\nHost: fixture.invalid\r\nAuthorization: Bearer %s\r\nContent-Length: 65536\r\n\r\n{", e.tok["carol"])
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if _, err := io.WriteString(conn, " "); err != nil {
					return
				}
			}
		}
	}()
	defer func() { close(stop); <-done }()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("drip upload escaped total deadline: %v", err)
	}
	readBody(resp)
	if resp.StatusCode != 408 || !resp.Close {
		t.Fatalf("drip upload status %d close %t", resp.StatusCode, resp.Close)
	}
}
