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
