package collector

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/prometheus/client_golang/prometheus"
)

// ResourceCollector collects per-user CPU, memory, and process count metrics.
type ResourceCollector struct {
	cfg      Config
	descCPU  *prometheus.Desc
	descMem  *prometheus.Desc
	descProc *prometheus.Desc
}

// NewResourceCollector creates a new ResourceCollector.
func NewResourceCollector(cfg Config) *ResourceCollector {
	return &ResourceCollector{
		cfg: cfg,
		descCPU: prometheus.NewDesc(
			"user_sessions_cpu_ratio",
			"Aggregate CPU usage ratio per user (0.0–1.0, from ps snapshot).",
			[]string{"username"}, nil,
		),
		descMem: prometheus.NewDesc(
			"user_sessions_memory_bytes",
			"Aggregate resident set size (RSS) in bytes per user.",
			[]string{"username"}, nil,
		),
		descProc: prometheus.NewDesc(
			"user_sessions_process_count",
			"Number of running processes per user.",
			[]string{"username"}, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *ResourceCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.descCPU
	ch <- c.descMem
	ch <- c.descProc
}

// Collect implements prometheus.Collector.
func (c *ResourceCollector) Collect(ch chan<- prometheus.Metric) {
	resources, err := collectUserResources(context.Background())
	if err != nil {
		c.cfg.Logger.Error("failed to collect user resources", "err", err)
		return
	}

	// Resolve numeric UIDs to usernames and merge into existing entries.
	resolved := make(map[string]*userResources, len(resources))
	for username, res := range resources {
		name := username
		if isNumericUID(username) && c.cfg.UserCache != nil {
			entry := c.cfg.UserCache.LookupByUID(username)
			if entry.Err == nil && entry.Username != "" {
				name = entry.Username
				c.cfg.Logger.Debug("resolved numeric UID to username", "uid", username, "username", name)
			}
		}
		if existing, ok := resolved[name]; ok {
			existing.cpuPercent += res.cpuPercent
			existing.memBytes += res.memBytes
			existing.procCount += res.procCount
		} else {
			resolved[name] = res
		}
	}

	for username, res := range resolved {
		if IsExcluded(username, c.cfg) {
			continue
		}

		ch <- prometheus.MustNewConstMetric(c.descCPU, prometheus.GaugeValue, res.cpuPercent/100.0, username)
		ch <- prometheus.MustNewConstMetric(c.descMem, prometheus.GaugeValue, res.memBytes, username)
		ch <- prometheus.MustNewConstMetric(c.descProc, prometheus.GaugeValue, float64(res.procCount), username)
	}
}

// isNumericUID returns true if the string looks like a numeric UID (all digits).
func isNumericUID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

type userResources struct {
	cpuPercent float64
	memBytes   float64
	procCount  int
}

// collectUserResources runs `ps` and aggregates CPU%, RSS, and process count per user.
func collectUserResources(ctx context.Context) (map[string]*userResources, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Use ruser:32 to avoid the default 8-char column width truncation.
	out, err := exec.CommandContext(ctx, "ps", "-eo", "ruser:32,pcpu=,rss=").Output()
	if err != nil {
		return nil, fmt.Errorf("ps: %w", err)
	}

	resources := make(map[string]*userResources)

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		username := fields[0]

		cpu, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			continue
		}

		rssKB, err := strconv.ParseFloat(fields[2], 64)
		if err != nil {
			continue
		}

		res, ok := resources[username]
		if !ok {
			res = &userResources{}
			resources[username] = res
		}

		res.cpuPercent += cpu
		res.memBytes += rssKB * 1024 // KB → bytes
		res.procCount++
	}

	return resources, scanner.Err()
}
