package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"oaiproxy/internal/tokens"
)

// Exercise the app's native engine in a disposable home. Only the proxy token
// reaches the child; the provider key belongs exclusively to the Go server.
func TestCodexAppServerOpenAILive(t *testing.T) {
	if os.Getenv("SHELLBENCH_OPENAI_LIVE") != "1" || os.Getenv("SHELLBENCH_CODEX_BIN") == "" {
		t.Skip("opt-in app-server proof requires SHELLBENCH_CODEX_BIN")
	}
	key := os.Getenv("OPENAI_API_KEY")
	if key == "" {
		t.Fatal("OPENAI_API_KEY required")
	}
	e := newEnv(t, http.NotFoundHandler(), func(o *Options) {
		o.Upstream, _ = url.Parse("https://api.openai.com/v1")
		o.Key, o.MaxRetries, o.UpstreamTimeout = staticKey(key), 0, 2*time.Minute
	})
	home := t.TempDir()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	args := []string{}
	for _, setting := range []string{
		`features.plugins=false`, `model_provider="gateway"`, `model="gpt-6.1-sol"`,
		`model_providers.gateway.name="Gateway"`,
		`model_providers.gateway.base_url=` + strconv.Quote(e.srv.URL+"/v1"),
		`model_providers.gateway.auth.command="/usr/bin/printenv"`,
		`model_providers.gateway.auth.args=["SHELLBENCH_PROXY_TOKEN"]`,
		`model_providers.gateway.wire_api="responses"`,
		`model_providers.gateway.requires_openai_auth=false`,
		`model_providers.gateway.supports_websockets=false`,
		`web_search="disabled"`, `model_reasoning_effort="low"`,
		`shell_environment_policy.inherit="none"`,
	} {
		args = append(args, "-c", setting)
	}
	args = append(args, "app-server")
	cmd := exec.CommandContext(ctx, os.Getenv("SHELLBENCH_CODEX_BIN"), args...)
	cmd.Dir = home
	cmd.Env = []string{"HOME=" + home, "CODEX_HOME=" + home, "PATH=" + os.Getenv("PATH"), "SHELLBENCH_PROXY_TOKEN=" + e.tok["carol"]}
	stderr := &liveOutput{}
	cmd.Stderr = stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal("cannot open app-server input")
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil || cmd.Start() != nil {
		t.Fatal("cannot start isolated app-server")
	}
	defer func() {
		stdin.Close()
		cancel()
		cmd.Wait()
		if bytes.Contains(stderr.data, []byte(key)) || strings.Contains(e.logs.String(), key) || strings.Contains(e.access.String(), key) {
			t.Error("provider credential appeared in app-server output or logs")
		}
	}()
	type message struct {
		ID     int             `json:"id"`
		Method string          `json:"method"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
		Params json.RawMessage `json:"params"`
	}
	messages := make(chan message)
	go func() {
		defer close(messages)
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			var m message
			if bytes.Contains(scanner.Bytes(), []byte(key)) || json.Unmarshal(scanner.Bytes(), &m) != nil {
				return
			}
			select {
			case messages <- m:
			case <-ctx.Done():
				return
			}
		}
	}()
	completed := false
	var completedThread, completedTurn, agentText string
	next := func() message {
		select {
		case m, ok := <-messages:
			if !ok {
				t.Fatal("app-server output ended before proof completed")
			}
			if m.Method == "turn/completed" {
				var p struct {
					ThreadID string `json:"threadId"`
					Turn     struct {
						ID     string `json:"id"`
						Status string `json:"status"`
					} `json:"turn"`
				}
				if json.Unmarshal(m.Params, &p) != nil || p.Turn.Status != "completed" {
					t.Fatal("app-server turn failed")
				}
				completed = true
				completedThread, completedTurn = p.ThreadID, p.Turn.ID
			}
			if m.Method == "item/completed" {
				var p struct{ Item struct{ Type, Text string } }
				if json.Unmarshal(m.Params, &p) == nil && p.Item.Type == "agentMessage" {
					agentText = p.Item.Text
				}
			}
			return m
		case <-ctx.Done():
			t.Fatal("app-server proof timed out")
			return message{}
		}
	}
	encoder := json.NewEncoder(stdin)
	id := 0
	request := func(method string, params any) json.RawMessage {
		id++
		if encoder.Encode(map[string]any{"id": id, "method": method, "params": params}) != nil {
			t.Fatal("app-server input failed")
		}
		for {
			m := next()
			if m.ID == id {
				if len(m.Error) > 0 && string(m.Error) != "null" {
					t.Fatalf("app-server %s failed (error body withheld)", method)
				}
				return m.Result
			}
		}
	}
	request("initialize", map[string]any{"clientInfo": map[string]any{"name": "gateway-proof", "version": "1"}})
	if encoder.Encode(map[string]any{"method": "initialized"}) != nil {
		t.Fatal("app-server initialization failed")
	}
	request("account/read", map[string]any{"refreshToken": false})
	catalog := request("model/list", map[string]any{})
	var models struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if json.Unmarshal(catalog, &models) != nil || len(models.Data) == 0 {
		t.Fatal("app-server returned no models")
	}
	found := false
	for _, m := range models.Data {
		if !tokens.ModelEligible(m.ID) {
			t.Fatal("app-server advertised an excluded model")
		}
		if m.ID == "gpt-6.1-sol" {
			found = true
		}
	}
	if !found {
		t.Fatal("app-server did not discover the configured model")
	}
	thread := request("thread/start", map[string]any{"model": "gpt-6.1-sol", "cwd": home, "ephemeral": true, "approvalPolicy": "never", "sandbox": "read-only"})
	var started struct {
		Thread struct {
			ID string `json:"id"`
		} `json:"thread"`
	}
	if json.Unmarshal(thread, &started) != nil || started.Thread.ID == "" {
		t.Fatal("app-server did not start a thread")
	}
	turn := request("turn/start", map[string]any{"threadId": started.Thread.ID, "input": []any{map[string]any{"type": "text", "text": "Reply exactly gateway-ok. Do not use tools."}}})
	var turnStarted struct{ Turn struct{ ID string } }
	if json.Unmarshal(turn, &turnStarted) != nil || turnStarted.Turn.ID == "" {
		t.Fatal("app-server did not start a turn")
	}
	for !completed {
		next()
	}
	if completedThread != started.Thread.ID || completedTurn != turnStarted.Turn.ID || strings.TrimSpace(agentText) != "gateway-ok" {
		t.Fatal("app-server did not complete the requested turn and answer")
	}
	// turn/completed can arrive before the proxy records the SSE close. Join
	// the fixture's handlers before inspecting their final access records.
	e.srv.CloseClientConnections()
	e.srv.Close()
	paths := map[string]int{}
	for _, line := range strings.Split(e.access.String(), "\n") {
		var rec struct {
			Path   string
			Status int
			Error  string
		}
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		// The native client closes SSE after its completion event, before EOF.
		if rec.Status != 200 || (rec.Error != "" && !(rec.Path == "/v1/responses" && rec.Error == "client_disconnected")) {
			t.Fatalf("app-server request %s status %d code %s", rec.Path, rec.Status, rec.Error)
		}
		paths[rec.Path]++
	}
	if paths["/v1/models"] == 0 || paths["/v1/responses"] == 0 {
		t.Fatal("app-server did not discover models and complete Responses through the gateway")
	}
	t.Logf("native catalog: %d models; app-server turn completed; provider key confined to server", len(models.Data))
}
