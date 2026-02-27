package collector

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// AuthCollector collects user_sessions_failed_logins_1h and user_sessions_root_logins_total.
type AuthCollector struct {
	cfg        Config
	descFailed *prometheus.Desc
	descRoot   *prometheus.Desc

	mu             sync.Mutex
	rootLoginCount float64
	lastRootCheck  time.Time
}

func NewAuthCollector(cfg Config) *AuthCollector {
	return &AuthCollector{
		cfg: cfg,
		descFailed: prometheus.NewDesc(
			"user_sessions_failed_logins_1h",
			"Number of failed SSH login attempts in the last 60 minutes.",
			nil, nil,
		),
		descRoot: prometheus.NewDesc(
			"user_sessions_root_logins_total",
			"Cumulative root login count since exporter start.",
			nil, nil,
		),
		lastRootCheck: time.Now(),
	}
}

func (c *AuthCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.descFailed
	ch <- c.descRoot
}

func (c *AuthCollector) Collect(ch chan<- prometheus.Metric) {
	ctx := context.Background()

	// Failed logins in the last hour
	failedCount, err := countFailedLogins(ctx, c.cfg.Logger)
	if err != nil {
		c.cfg.Logger.Error("failed to count failed logins", "err", err)
		failedCount = 0
	}
	ch <- prometheus.MustNewConstMetric(c.descFailed, prometheus.GaugeValue, float64(failedCount))

	// Root logins — accumulate since last check
	c.mu.Lock()
	since := c.lastRootCheck
	newRootLogins, err := countRootLogins(ctx, since, c.cfg.Logger)
	if err != nil {
		c.cfg.Logger.Error("failed to count root logins", "err", err)
		newRootLogins = 0
	}
	c.rootLoginCount += float64(newRootLogins)
	c.lastRootCheck = time.Now()
	rootTotal := c.rootLoginCount
	c.mu.Unlock()

	ch <- prometheus.MustNewConstMetric(c.descRoot, prometheus.CounterValue, rootTotal)
}

// countFailedLogins counts "Failed password" entries in the last 60 minutes.
// Tries journalctl first, falls back to /var/log/auth.log.
func countFailedLogins(ctx context.Context, logger *slog.Logger) (int, error) {
	// Try journalctl first
	count, err := countFailedLoginsJournalctl(ctx)
	if err == nil {
		return count, nil
	}
	logger.Debug("journalctl fallback to auth.log", "err", err)

	// Fallback to auth.log
	return countFailedLoginsAuthLog()
}

// countFailedLoginsJournalctl uses journalctl to count failed SSH login attempts.
func countFailedLoginsJournalctl(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "journalctl",
		"-u", "ssh.service", "-u", "sshd.service",
		"--since", "60 minutes ago",
		"--no-pager", "-q",
		"--lines", "50000",
	).Output()
	if err != nil {
		return 0, fmt.Errorf("journalctl: %w", err)
	}

	count := 0
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "Failed password") {
			count++
		}
	}
	return count, nil
}

// countFailedLoginsAuthLog reads /var/log/auth.log for failed login attempts
// in the last 60 minutes.
func countFailedLoginsAuthLog() (int, error) {
	f, err := os.Open("/var/log/auth.log")
	if err != nil {
		return 0, fmt.Errorf("open auth.log: %w", err)
	}
	defer f.Close()

	cutoff := time.Now().Add(-60 * time.Minute)
	currentYear := time.Now().Year()
	count := 0

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "Failed password") {
			continue
		}

		// Parse timestamp from auth.log line (format: "Jan  2 15:04:05")
		ts, err := parseAuthLogTimestamp(line, currentYear)
		if err != nil {
			continue
		}

		if ts.After(cutoff) {
			count++
		}
	}

	return count, scanner.Err()
}

// countRootLogins counts root login entries since the given time.
func countRootLogins(ctx context.Context, since time.Time, logger *slog.Logger) (int, error) {
	// Try journalctl first
	count, err := countRootLoginsJournalctl(ctx, since)
	if err == nil {
		return count, nil
	}
	logger.Debug("root login journalctl fallback to auth.log", "err", err)

	return countRootLoginsAuthLog(since)
}

func countRootLoginsJournalctl(ctx context.Context, since time.Time) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	sinceStr := since.Format("2006-01-02 15:04:05")
	out, err := exec.CommandContext(ctx, "journalctl",
		"-u", "ssh.service", "-u", "sshd.service",
		"--since", sinceStr,
		"--no-pager", "-q",
		"--lines", "50000",
	).Output()
	if err != nil {
		return 0, fmt.Errorf("journalctl: %w", err)
	}

	count := 0
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		// Match: "Accepted password for root" or "Accepted publickey for root"
		if strings.Contains(line, "Accepted") && strings.Contains(line, "for root") {
			count++
		}
	}
	return count, nil
}

func countRootLoginsAuthLog(since time.Time) (int, error) {
	f, err := os.Open("/var/log/auth.log")
	if err != nil {
		return 0, fmt.Errorf("open auth.log: %w", err)
	}
	defer f.Close()

	currentYear := time.Now().Year()
	count := 0

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "Accepted") || !strings.Contains(line, "for root") {
			continue
		}

		ts, err := parseAuthLogTimestamp(line, currentYear)
		if err != nil {
			continue
		}

		if ts.After(since) {
			count++
		}
	}

	return count, scanner.Err()
}

// parseAuthLogTimestamp parses the syslog-style timestamp from an auth.log line.
// Format: "Jan  2 15:04:05 hostname ..."
func parseAuthLogTimestamp(line string, year int) (time.Time, error) {
	// Need at least 15 characters for "Jan  2 15:04:05"
	if len(line) < 15 {
		return time.Time{}, fmt.Errorf("line too short")
	}

	// Extract the timestamp portion (first 15 characters)
	tsPart := line[:15]
	ts, err := time.Parse("Jan  2 15:04:05", tsPart)
	if err != nil {
		// Try single-space format for double-digit days: "Jan 12 15:04:05"
		ts, err = time.Parse("Jan 2 15:04:05", tsPart)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse timestamp %q: %w", tsPart, err)
		}
	}

	// time.Parse without a year defaults to year 0; set current year
	ts = ts.AddDate(year, 0, 0)

	// Handle December→January rollover: if parsed time is in the future, subtract a year
	if ts.After(time.Now().Add(24 * time.Hour)) {
		ts = ts.AddDate(-1, 0, 0)
	}

	return ts, nil
}
