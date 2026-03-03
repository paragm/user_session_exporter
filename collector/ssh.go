package collector

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// SSHCollector collects user_sessions_ssh_connections and user_sessions_remote_connections.
type SSHCollector struct {
	cfg        Config
	descSSH    *prometheus.Desc
	descRemote *prometheus.Desc
	vncCountFn func() (int, error)
}

// NewSSHCollector creates a new SSHCollector.
func NewSSHCollector(cfg Config, vncCountFn func() (int, error)) *SSHCollector {
	return &SSHCollector{
		cfg: cfg,
		descSSH: prometheus.NewDesc(
			"user_sessions_ssh_connections",
			"Number of established SSH connections (port 22).",
			nil, nil,
		),
		descRemote: prometheus.NewDesc(
			"user_sessions_remote_connections",
			"Total remote connections (SSH + VNC).",
			nil, nil,
		),
		vncCountFn: vncCountFn,
	}
}

// Describe implements prometheus.Collector.
func (c *SSHCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.descSSH
	ch <- c.descRemote
}

// Collect implements prometheus.Collector.
func (c *SSHCollector) Collect(ch chan<- prometheus.Metric) {
	sshCount, err := countSSHConnections(context.Background())
	if err != nil {
		c.cfg.Logger.Error("failed to count SSH connections", "err", err)
		sshCount = 0
	}

	ch <- prometheus.MustNewConstMetric(c.descSSH, prometheus.GaugeValue, float64(sshCount))

	// Compute remote total = SSH + VNC
	vncCount := 0
	if c.vncCountFn != nil {
		if v, err := c.vncCountFn(); err == nil {
			vncCount = v
		}
	}

	ch <- prometheus.MustNewConstMetric(
		c.descRemote, prometheus.GaugeValue, float64(sshCount+vncCount),
	)
}

// countSSHConnections counts ESTABLISHED TCP connections on port 22.
func countSSHConnections(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ss", "-tn", "state", "established", "sport", "=", ":22").Output()
	if err != nil {
		return 0, fmt.Errorf("ss ssh: %w", err)
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
