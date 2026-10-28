package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"oaiproxy/internal/admin"
	"oaiproxy/internal/config"
	"oaiproxy/internal/proxy"
)

func TestAdminOnlyOnPrivateListener(t *testing.T) {
	key, err := config.NewUpstreamKey("fixture-admin-key-at-least-32-characters", "")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("https://example.com/v1")
	p, err := proxy.New(proxy.Options{Upstream: u, Key: key, Routes: config.DefaultRoutes})
	if err != nil {
		t.Fatal(err)
	}
	public := httptest.NewServer(p.Handler())
	defer public.Close()
	adm := &admin.Server{Key: key, TokensFile: filepath.Join(t.TempDir(), "tokens.json")}
	privateServer := adminServer(&config.Config{AdminAddr: "127.0.0.1:8081"}, adm)
	if privateServer.Addr != "127.0.0.1:8081" || privateServer.ReadTimeout == 0 {
		t.Fatal("admin listener lacks private address/timeouts")
	}
	private := httptest.NewServer(privateServer.Handler)
	defer private.Close()
	for _, tc := range []struct {
		base, token string
		status      int
	}{
		{public.URL, key.Get(), 404}, {private.URL, "", 401}, {private.URL, key.Get(), 200},
	} {
		r, _ := http.NewRequest("GET", tc.base+"/admin/clients", nil)
		r.Header.Set("Authorization", "Bearer "+tc.token)
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Errorf("admin response: got %d want %d", resp.StatusCode, tc.status)
		}
	}
}

func TestAdminEnablementOrdersHostOverrideLast(t *testing.T) {
	for _, suffix := range []string{":deploy/docker-compose.host.yml", ":deploy/docker-compose.host.yml:deploy/docker-compose.admin.yml"} {
		t.Run(suffix, func(t *testing.T) {
			root := t.TempDir()
			for _, dir := range []string{"scripts", "secrets", "bin"} {
				if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			script, err := os.ReadFile("../../scripts/keys.sh")
			if err != nil {
				t.Fatal(err)
			}
			files := map[string]string{
				"scripts/keys.sh":       string(script),
				".env":                  "PROXY_DOMAIN=router.example\nCOMPOSE_FILE=docker-compose.yml:deploy/docker-compose.keyfile.yml" + suffix + "\n",
				"secrets/admin_api_key": "fixture-admin-key",
				"bin/docker":            "#!/bin/sh\nexit 0\n",
				"bin/sudo":              "#!/bin/sh\nexit 1\n",
			}
			for name, value := range files {
				if err := os.WriteFile(filepath.Join(root, name), []byte(value), 0700); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("/bin/bash", filepath.Join(root, "scripts/keys.sh"), "admin-key")
			cmd.Env = []string{"PATH=" + filepath.Join(root, "bin") + ":" + os.Getenv("PATH"), "HOME=" + root}
			if err := cmd.Run(); err != nil {
				t.Fatal("isolated admin enablement failed")
			}
			body, err := os.ReadFile(filepath.Join(root, ".env"))
			if err != nil {
				t.Fatal(err)
			}
			want := "COMPOSE_FILE=docker-compose.yml:deploy/docker-compose.keyfile.yml:deploy/docker-compose.admin.yml:deploy/docker-compose.host.yml\n"
			if !strings.Contains(string(body), want) {
				t.Fatal("host override is not last")
			}
		})
	}
}
