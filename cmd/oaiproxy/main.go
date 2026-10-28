// Command oaiproxy is an authenticated, streaming OpenAI API proxy.
//
//	oaiproxy serve                  run the proxy (configured via env)
//	oaiproxy token add|list|...     manage client tokens in TOKENS_FILE
//	oaiproxy healthcheck            probe /healthz (for container health checks)
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"oaiproxy/internal/admin"
	"oaiproxy/internal/config"
	"oaiproxy/internal/proxy"
	"oaiproxy/internal/tokens"
)

var version = "dev"

const usageText = `usage: oaiproxy <command> [flags]

commands:
  serve                     run the proxy (configuration via environment)
  token add -id ID [...]    create a client and print its token once
  token list                list clients (never prints tokens)
  token rotate -id ID       issue a new token (-grace keeps the old one valid)
  token revoke -id ID       disable a client immediately
  token enable -id ID       re-enable a revoked client
  token set -id ID [...]    change models / limits / expiry
  token remove -id ID       delete a client
  healthcheck               exit 0 if the local server is healthy
  version                   print version

Run "oaiproxy token <subcommand> -h" for flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve()
	case "token":
		err = tokenCmd(os.Args[2:], os.Stdout, os.Stderr, time.Now())
	case "healthcheck":
		err = healthcheck()
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usageText)
	default:
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func serve() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logger := newLogger(cfg)
	slog.SetDefault(logger)

	var access io.Writer
	if cfg.AccessLogFile != "" {
		f, err := os.OpenFile(cfg.AccessLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("access log: %w", err)
		}
		defer f.Close()
		access = f
	}

	metrics := proxy.NewMetrics()
	p, err := proxy.New(proxy.Options{
		Upstream:          cfg.Upstream,
		Key:               cfg.Key,
		Organization:      cfg.UpstreamOrg,
		Project:           cfg.UpstreamProject,
		ExtraHeaders:      cfg.UpstreamHeaders,
		Routes:            cfg.Routes,
		MaxRequestBytes:   cfg.MaxRequestBytes,
		MaxRetries:        cfg.MaxRetries,
		MaxRetryWait:      cfg.MaxRetryWait,
		UpstreamTimeout:   cfg.UpstreamTimeout,
		StreamIdleTimeout: cfg.StreamIdleTimeout,
		BodyReadTimeout:   cfg.BodyReadTimeout,
		MaxInflight:       cfg.MaxInflight,
		MaxBufferedBytes:  cfg.MaxBufferedBytes,
		Logger:            logger,
		AccessLog:         access,
		Metrics:           metrics,
		TrustedProxies:    cfg.TrustedProxies,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	w := &watcher{cfg: cfg, p: p, log: logger}
	w.check(true)
	go w.loop(ctx)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           p.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelDebug),
	}
	servers := []*http.Server{srv}
	if cfg.AdminKey != nil {
		servers = append(servers, adminServer(cfg, &admin.Server{TokensFile: cfg.TokensFile, Key: cfg.AdminKey, Reload: func() { w.check(true) }, Log: logger}))
	}
	if cfg.MetricsAddr != "" {
		msrv := &http.Server{Addr: cfg.MetricsAddr, Handler: metricsMux(metrics), ReadHeaderTimeout: 5 * time.Second}
		servers = append(servers, msrv)
	}
	errc := make(chan error, len(servers))
	for _, server := range servers {
		// Bind every listener before announcing readiness; a private-listener
		// failure must not leave a partially started public gateway running.
		ln, err := net.Listen("tcp", server.Addr)
		if err != nil {
			return err
		}
		defer server.Close()
		go func() { errc <- server.Serve(ln) }()
	}
	logger.Info("oaiproxy started", "version", version, "listen", cfg.ListenAddr, "metrics", cfg.MetricsAddr,
		"upstream", cfg.Upstream.Scheme+"://"+cfg.Upstream.Host+cfg.Upstream.Path,
		"routes", len(cfg.Routes), "upstream_key_fingerprint", cfg.Key.Fingerprint(), "admin_api", cfg.AdminKey != nil)

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	logger.Info("shutting down", "grace", cfg.ShutdownTimeout.String())
	sctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	for _, server := range servers {
		if err := server.Shutdown(sctx); err != nil {
			server.Close()
		}
	}
	return nil
}

// Admin never shares the public handler, even when the caller has a valid key.
func adminServer(cfg *config.Config, adm http.Handler) *http.Server {
	return &http.Server{Addr: cfg.AdminAddr, Handler: adm, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
}

func metricsMux(m *proxy.Metrics) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", m)
	return mux
}

func newLogger(cfg *config.Config) *slog.Logger {
	var lvl slog.Level
	if lvl.UnmarshalText([]byte(cfg.LogLevel)) != nil {
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if cfg.LogFormat == "text" {
		return slog.New(slog.NewTextHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}

// watcher hot-reloads the token file (and upstream key file) when they
// change on disk or on SIGHUP. Invalid files are rejected and the previous
// configuration stays active; a missing token file fails closed.
type watcher struct {
	mu      sync.Mutex // check runs from the poll loop and from admin API calls
	cfg     *config.Config
	p       *proxy.Proxy
	log     *slog.Logger
	last    os.FileInfo
	missing bool
}

func (w *watcher) loop(ctx context.Context) {
	t := time.NewTicker(w.cfg.ReloadInterval)
	defer t.Stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.check(false)
		case <-hup:
			w.check(true)
		}
	}
}

func (w *watcher) check(force bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	fi, err := os.Stat(w.cfg.TokensFile)
	switch {
	case err != nil:
		if !w.missing || force {
			w.log.Warn("tokens file unavailable; rejecting all requests", "file", w.cfg.TokensFile, "error", err.Error())
			w.p.SetStore(tokens.NewStore(&tokens.File{Version: 1}))
		}
		w.missing, w.last = true, nil
	case force || w.last == nil || !os.SameFile(fi, w.last) || !fi.ModTime().Equal(w.last.ModTime()) || fi.Size() != w.last.Size():
		w.missing, w.last = false, fi
		f, err := tokens.Read(w.cfg.TokensFile)
		if err != nil {
			w.log.Error("tokens file invalid; keeping previous configuration", "error", err.Error())
			break
		}
		w.p.SetStore(tokens.NewStore(f))
		w.log.Info("tokens loaded", "file", w.cfg.TokensFile, "clients", len(f.Clients))
	}
	if changed, err := w.cfg.Key.Reload(); err != nil {
		w.log.Error("upstream key reload failed; keeping previous key", "error", err.Error())
	} else if changed {
		w.log.Info("upstream key reloaded", "upstream_key_fingerprint", w.cfg.Key.Fingerprint())
	}
	if w.cfg.AdminKey != nil {
		if changed, err := w.cfg.AdminKey.Reload(); err != nil {
			w.log.Error("admin key reload failed; keeping previous key", "error", err.Error())
		} else if changed {
			w.log.Info("admin key reloaded")
		}
	}
}

func healthcheck() error {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz returned %d", resp.StatusCode)
	}
	return nil
}
