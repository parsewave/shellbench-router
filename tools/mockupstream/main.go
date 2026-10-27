// Command mockupstream serves a fake OpenAI API for local smoke tests and
// benchmarks. Not for production use.
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"oaiproxy/internal/mockupstream"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9999", "listen address")
	key := flag.String("key", "sk-mock-upstream-key", "expected upstream API key")
	latency := flag.Duration("latency", 0, "delay before each response")
	chunk := flag.Duration("chunk-delay", 0, "delay between SSE events")
	words := flag.Int("words", 8, "words per completion")
	flag.Parse()
	s := &mockupstream.Server{Key: *key, Latency: *latency, ChunkDelay: *chunk, Words: *words}
	log.Printf("mock upstream on http://%s/v1", *addr)
	srv := &http.Server{Addr: *addr, Handler: s, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
