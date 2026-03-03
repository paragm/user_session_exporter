package collector

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// VNCCollector collects user_sessions_vnc_connections.
type VNCCollector struct {
	cfg     Config
	descVNC *prometheus.Desc

	mu    sync.Mutex
	count int // cached count from last Collect or CountVNC call
}

// NewVNCCollector creates a new VNCCollector.
func NewVNCCollector(cfg Config) *VNCCollector {
	return &VNCCollector{
		cfg: cfg,
		descVNC: prometheus.NewDesc(
			"user_sessions_vnc_connections",
			"Number of established VNC connections (ports 5901-64999).",
			nil, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *VNCCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.descVNC
}

// Collect implements prometheus.Collector.
func (c *VNCCollector) Collect(ch chan<- prometheus.Metric) {
	count, err := c.countVNCConnections(context.Background())
	if err != nil {
		c.cfg.Logger.Error("failed to count VNC connections", "err", err)
		count = 0
	}

	c.mu.Lock()
	c.count = count
	c.mu.Unlock()

	ch <- prometheus.MustNewConstMetric(c.descVNC, prometheus.GaugeValue, float64(count))
}

// CountVNC returns the last cached VNC connection count.
// Called by SSHCollector to compute user_sessions_remote_connections without running ss twice.
func (c *VNCCollector) CountVNC() (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count, nil
}

// countVNCConnections counts ESTABLISHED connections on ports 5901-64999.
func (c *VNCCollector) countVNCConnections(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ss", "-tn", "state", "established",
		"(", "sport", ">=", ":5901", "sport", "<=", ":64999", ")").Output()
	if err != nil {
		return 0, fmt.Errorf("ss vnc: %w", err)
	}

	count := 0
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Recv-Q") || strings.HasPrefix(line, "State") || line == "" {
			continue
		}
		count++
	}

	return count, nil
}
