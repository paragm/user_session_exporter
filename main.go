package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/paragm/user_session_exporter/collector"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
)

func main() {
	listenAddr := flag.String("web.listen-address", ":10041", "Address to listen on for metrics")
	logLevel := flag.String("log.level", "info", "Log level: debug, info, warn, error")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.Print("user_sessions_exporter"))
		os.Exit(0)
	}

	// Environment variables override flags
	if port := os.Getenv("PORT"); port != "" {
		addr := ":" + port
		listenAddr = &addr
	}
	if lvl := os.Getenv("LOG_LEVEL"); lvl != "" {
		logLevel = &lvl
	}

	// Configure structured logger
	var slogLevel slog.Level
	switch strings.ToLower(*logLevel) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn", "warning":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slogLevel}))

	// Parse excluded users from environment
	excludeUsers := make(map[string]struct{})
	if excl := os.Getenv("EXCLUDE_USERS"); excl != "" {
		for _, u := range strings.Split(excl, ",") {
			u = strings.TrimSpace(u)
			if u != "" {
				excludeUsers[u] = struct{}{}
			}
		}
	}

	// Parse SSH ports from environment (default: 22)
	sshPorts := []int{22}
	if sp := os.Getenv("SSH_PORTS"); sp != "" {
		sshPorts = nil
		for _, s := range strings.Split(sp, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			p, err := strconv.Atoi(s)
			if err != nil {
				logger.Error("invalid SSH_PORTS value, must be comma-separated integers", "value", s)
				os.Exit(1)
			}
			sshPorts = append(sshPorts, p)
		}
		if len(sshPorts) == 0 {
			sshPorts = []int{22}
		}
	}

	// Resolve hostname once at startup
	hostname, err := os.Hostname()
	if err != nil {
		logger.Error("failed to get hostname", "err", err)
		hostname = "unknown"
	}

	cfg := collector.Config{
		ExcludeUsers: excludeUsers,
		Logger:       logger,
		Hostname:     hostname,
		SSHPorts:     sshPorts,
	}

	// Fresh registry — no default Go runtime metrics
	registry := prometheus.NewRegistry()

	mc := collector.NewMasterCollector(cfg)
	registry.MustRegister(mc)

	logger.Info("starting user_sessions_exporter",
		"version", version.Version,
		"revision", version.Revision,
		"branch", version.Branch,
		"listen", *listenAddr,
		"hostname", hostname,
		"excluded_users", len(excludeUsers),
	)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}))
	mux.HandleFunc("/-/healthy", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	})
	mux.HandleFunc("/-/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<html><head><title>User Sessions Exporter</title></head>
<body><h1>User Sessions Exporter</h1>
<p>Version: %s (branch: %s, revision: %s)</p>
<p><a href="/metrics">Metrics</a></p></body></html>`,
			version.Version, version.Branch, version.Revision)
	})

	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		logger.Error("server failed", "err", err)
		os.Exit(1)
	}
}
