package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"sync"
	"time"
)

// tapBody wraps an upstream response body as it streams to the client. It
// never buffers the response: it keeps only the last tailSize bytes, from
// which token usage is parsed at the end (usage is the last object in both
// regular responses and the final SSE event), and it enforces an idle
// timeout between upstream reads.
type tapBody struct {
	rc     io.ReadCloser
	st     *reqState
	t      *tail
	idle   time.Duration
	timer  *time.Timer
	closed bool
}

func newTap(rc io.ReadCloser, st *reqState, idle time.Duration) *tapBody {
	b := &tapBody{rc: rc, st: st, t: tailPool.Get().(*tail), idle: idle}
	b.t.w, b.t.full = 0, false
	if idle > 0 && st.cancel != nil {
		b.timer = time.AfterFunc(idle, func() { st.cancel(errStreamIdle) })
	}
	return b
}

func (b *tapBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 {
		b.t.write(p[:n])
		if b.timer != nil {
			b.timer.Reset(b.idle)
		}
	}
	if err != nil && err != io.EOF {
		b.st.upstreamReadErr = true
	}
	return n, err
}

func (b *tapBody) Close() error {
	if b.closed {
		return nil
	}
	b.closed = true
	if b.timer != nil {
		b.timer.Stop()
	}
	if u, ok := parseUsage(b.t.bytes()); ok {
		b.st.usage = u
	}
	tailPool.Put(b.t)
	b.t = nil
	return b.rc.Close()
}

const tailSize = 16 << 10

var tailPool = sync.Pool{New: func() any { return new(tail) }}

// tail is a fixed-size ring buffer holding the most recent bytes written.
type tail struct {
	b    [tailSize]byte
	w    int
	full bool
}

func (t *tail) write(p []byte) {
	if len(p) >= tailSize {
		copy(t.b[:], p[len(p)-tailSize:])
		t.w, t.full = 0, true
		return
	}
	n := copy(t.b[t.w:], p)
	copy(t.b[:], p[n:])
	if t.w+len(p) >= tailSize {
		t.full = true
	}
	t.w = (t.w + len(p)) % tailSize
}

func (t *tail) bytes() []byte {
	if !t.full {
		return t.b[:t.w]
	}
	out := make([]byte, 0, tailSize)
	return append(append(out, t.b[t.w:]...), t.b[:t.w]...)
}

type usage struct {
	Input, Output, Total, Reasoning, Cached int64
}

type rawUsage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	InputTokens      int64 `json:"input_tokens"`
	OutputTokens     int64 `json:"output_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
	PromptDetails    *struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
	InputDetails *struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"input_tokens_details"`
	CompletionDetails *struct {
		ReasoningTokens int64 `json:"reasoning_tokens"`
	} `json:"completion_tokens_details"`
	OutputDetails *struct {
		ReasoningTokens int64 `json:"reasoning_tokens"`
	} `json:"output_tokens_details"`
}

var usageKey = []byte(`"usage"`)

// parseUsage finds the last non-null "usage" object in b. Chat Completions
// (prompt/completion) and Responses (input/output) shapes are normalised.
func parseUsage(b []byte) (usage, bool) {
	end := len(b)
	for tries := 0; tries < 8; tries++ {
		i := bytes.LastIndex(b[:end], usageKey)
		if i < 0 {
			return usage{}, false
		}
		end = i
		rest := b[i+len(usageKey):]
		j := skipWS(rest, 0)
		if j >= len(rest) || rest[j] != ':' {
			continue
		}
		rest = rest[skipWS(rest, j+1):]
		if len(rest) == 0 || rest[0] != '{' {
			continue
		}
		var r rawUsage
		if json.NewDecoder(bytes.NewReader(rest)).Decode(&r) != nil {
			continue
		}
		u := usage{Input: r.PromptTokens + r.InputTokens, Output: r.CompletionTokens + r.OutputTokens, Total: r.TotalTokens}
		if r.PromptDetails != nil {
			u.Cached += r.PromptDetails.CachedTokens
		}
		if r.InputDetails != nil {
			u.Cached += r.InputDetails.CachedTokens
		}
		if r.CompletionDetails != nil {
			u.Reasoning += r.CompletionDetails.ReasoningTokens
		}
		if r.OutputDetails != nil {
			u.Reasoning += r.OutputDetails.ReasoningTokens
		}
		if u.Total == 0 {
			u.Total = u.Input + u.Output
		}
		if u.Total > 0 {
			return u, true
		}
	}
	return usage{}, false
}
