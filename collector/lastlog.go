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

// LastlogCollector collects user_sessions_last_login_timestamp_seconds with a 5-minute cache.
type LastlogCollector struct {
	cfg         Config
	descLastlog *prometheus.Desc

	mu        sync.RWMutex
	cache     map[string]float64 // username → unix timestamp
	cacheTime time.Time
	cacheTTL  time.Duration
}

func NewLastlogCollector(cfg Config) *LastlogCollector {
	return &LastlogCollector{
		cfg: cfg,
		descLastlog: prometheus.NewDesc(
			"user_sessions_last_login_timestamp_seconds",
			"Unix timestamp of the user's last login (cached, refreshed every 5 minutes).",
			[]string{"username"}, nil,
		),
		cache:    make(map[string]float64),
		cacheTTL: 5 * time.Minute,
	}
}

func (c *LastlogCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.descLastlog
}

func (c *LastlogCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	needsRefresh := time.Since(c.cacheTime) >= c.cacheTTL
	c.mu.RUnlock()

	if needsRefresh {
		newCache, err := runLastlog(context.Background())
		if err != nil {
			c.cfg.Logger.Error("lastlog refresh failed", "err", err)
		} else {
			c.mu.Lock()
			c.cache = newCache
			c.cacheTime = time.Now()
			c.mu.Unlock()
		}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	for username, ts := range c.cache {
		if IsExcluded(username, c.cfg) {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.descLastlog, prometheus.GaugeValue, ts, username)
	}
}

// runLastlog runs the `lastlog` command and returns the parsed cache.
func runLastlog(ctx context.Context) (map[string]float64, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "lastlog").Output()
	if err != nil {
		return nil, fmt.Errorf("lastlog: %w", err)
	}

	return parseLastlogOutput(string(out))
}

// parseLastlogOutput parses the output of the `lastlog` command.
// Format:
//
//	Username         Port     From             Latest
//	root             pts/0    192.168.1.1      Wed Feb 26 10:30:01 +0000 2026
//	nobody                                     **Never logged in**
func parseLastlogOutput(output string) (map[string]float64, error) {
	cache := make(map[string]float64)

	scanner := bufio.NewScanner(strings.NewReader(output))

	// Skip header line
	if scanner.Scan() {
		// first line is the header
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Skip users who never logged in
		if strings.Contains(line, "**Never logged in**") {
			continue
		}

		// Username is the first field (up to first whitespace)
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		username := fields[0]

		// The timestamp starts after the "From" column.
		// lastlog format varies: "Port From Latest" columns have variable width.
		// Find the timestamp by looking for a day-of-week pattern.
		tsIdx := -1
		daysOfWeek := []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}
		for i, f := range fields {
			for _, d := range daysOfWeek {
				if f == d {
					tsIdx = i
					break
				}
			}
			if tsIdx >= 0 {
				break
			}
		}

		if tsIdx < 0 || tsIdx+4 >= len(fields) {
			continue
		}

		// Reconstruct the timestamp string from fields
		// Format: "Wed Feb 26 10:30:01 +0000 2026"
		var tsStr string
		if tsIdx+5 < len(fields) {
			// With timezone: "Wed Feb 26 10:30:01 +0000 2026"
			tsStr = strings.Join(fields[tsIdx:tsIdx+6], " ")
		} else {
			// Without timezone: "Wed Feb 26 10:30:01 2026"
			tsStr = strings.Join(fields[tsIdx:], " ")
		}

		ts, err := parseLastlogTimestamp(tsStr)
		if err != nil {
			continue
		}

		cache[username] = float64(ts.Unix())
	}

	return cache, scanner.Err()
}

// parseLastlogTimestamp attempts to parse various lastlog timestamp formats.
func parseLastlogTimestamp(s string) (time.Time, error) {
	// Try common formats
	formats := []string{
		"Mon Jan 2 15:04:05 -0700 2006", // with timezone offset
		"Mon Jan 2 15:04:05 MST 2006",   // with timezone name
		"Mon Jan 2 15:04:05 2006",       // no timezone
	}

	for _, layout := range formats {
		if ts, err := time.Parse(layout, s); err == nil {
			return ts, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse timestamp: %q", s)
}
