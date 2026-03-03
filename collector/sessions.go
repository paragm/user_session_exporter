package collector

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Session represents a single active user session.
type Session struct {
	Username    string
	TTY         string
	FromIP      string
	SessionType string // "terminal", "ssh-npty", "vnc"
}

// SessionCollector collects user_sessions_logged_in_users and user_sessions_session_active.
type SessionCollector struct {
	cfg         Config
	descLogged  *prometheus.Desc
	descSession *prometheus.Desc

	mu        sync.Mutex
	lastUsers []string // cached active usernames from last Collect
}

// NewSessionCollector creates a new SessionCollector.
func NewSessionCollector(cfg Config) *SessionCollector {
	return &SessionCollector{
		cfg: cfg,
		descLogged: prometheus.NewDesc(
			"user_sessions_logged_in_users",
			"Number of unique users with at least one active session.",
			nil, nil,
		),
		descSession: prometheus.NewDesc(
			"user_sessions_session_active",
			"Active user session (value=1 per session).",
			[]string{"username", "tty", "from_ip", "session_type"}, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *SessionCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.descLogged
	ch <- c.descSession
}

// Collect implements prometheus.Collector.
func (c *SessionCollector) Collect(ch chan<- prometheus.Metric) {
	var allSessions []Session

	// Collect from all sources, tolerating individual failures
	if ptySessions, err := collectWhoSessions(context.Background()); err == nil {
		allSessions = append(allSessions, ptySessions...)
	} else {
		c.cfg.Logger.Error("failed to collect PTY sessions", "err", err)
	}

	if sshSessions, err := collectNonPTYSSH(context.Background(), c.cfg.Logger, c.cfg.UserCache, c.cfg.SSHPorts); err == nil {
		allSessions = append(allSessions, sshSessions...)
	} else {
		c.cfg.Logger.Error("failed to collect non-PTY SSH sessions", "err", err)
	}

	if vncSessions, err := collectVNCSessions(context.Background(), c.cfg.Logger, c.cfg.UserCache); err == nil {
		allSessions = append(allSessions, vncSessions...)
	} else {
		c.cfg.Logger.Error("failed to collect VNC sessions", "err", err)
	}

	// Deduplicate and filter
	uniqueUsers := make(map[string]struct{})
	seen := make(map[string]struct{})

	for _, s := range allSessions {
		if IsExcluded(s.Username, c.cfg) {
			continue
		}

		// Dedup key: username+tty+session_type (same user on same tty = one session)
		key := fmt.Sprintf("%s|%s|%s", s.Username, s.TTY, s.SessionType)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		uniqueUsers[s.Username] = struct{}{}

		ch <- prometheus.MustNewConstMetric(
			c.descSession, prometheus.GaugeValue, 1,
			s.Username, s.TTY, s.FromIP, s.SessionType,
		)
	}

	ch <- prometheus.MustNewConstMetric(
		c.descLogged, prometheus.GaugeValue, float64(len(uniqueUsers)),
	)

	// Cache active users for UserInfoCollector
	users := make([]string, 0, len(uniqueUsers))
	for u := range uniqueUsers {
		users = append(users, u)
	}
	c.mu.Lock()
	c.lastUsers = users
	c.mu.Unlock()
}

// ActiveUsers returns the list of unique usernames from the last Collect cycle.
// Called by UserInfoCollector.
func (c *SessionCollector) ActiveUsers() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.lastUsers))
	copy(out, c.lastUsers)
	return out
}

// collectWhoSessions parses the output of the `who` command.
// Output format: "username  pts/0  2024-01-15 09:32 (192.168.1.10)"
func collectWhoSessions(ctx context.Context) ([]Session, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "who").Output()
	if err != nil {
		return nil, fmt.Errorf("who: %w", err)
	}

	var sessions []Session
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		s := Session{
			Username:    fields[0],
			TTY:         fields[1],
			SessionType: "terminal",
		}

		// Extract IP from parenthesized field at end, e.g. "(192.168.1.10)"
		for _, f := range fields {
			if strings.HasPrefix(f, "(") && strings.HasSuffix(f, ")") {
				s.FromIP = strings.Trim(f, "()")
				break
			}
		}

		sessions = append(sessions, s)
	}

	return sessions, nil
}

// ssPIDRegex extracts PID from ss output like: users:(("sshd",pid=12345,fd=3))
var ssPIDRegex = regexp.MustCompile(`pid=(\d+)`)

// collectNonPTYSSH detects non-PTY SSH sessions (VS Code Remote, scp, sftp, tunnels)
// by parsing `ss` output for established connections on the configured SSH ports and resolving PID→UID.
func collectNonPTYSSH(ctx context.Context, logger *slog.Logger, cache *UserLookupCache, ports []int) ([]Session, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	args := []string{"-tnp", "state", "established"}
	filter := SSHPortFilter(ports)
	if len(filter) == 1 {
		args = append(args, "sport", "=", filter[0])
	} else {
		args = append(args, filter...)
	}
	out, err := exec.CommandContext(ctx, "ss", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("ss ssh ports: %w", err)
	}

	// Get list of PTY-session PIDs to exclude (these are already counted by `who`)
	ptyTTYs := getPTYTTYs(context.Background())

	var sessions []Session
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		// Skip header line
		if strings.HasPrefix(line, "Recv-Q") || strings.HasPrefix(line, "State") {
			continue
		}

		fields := strings.Fields(line)
		// Expected: Recv-Q Send-Q Local:Port Peer:Port Process
		// After state filter: Local:Port Peer:Port Process
		if len(fields) < 3 {
			continue
		}

		_, peerAddr, processField := parseSSFields(fields)
		if processField == "" {
			continue
		}

		remoteIP := extractIP(peerAddr)

		// Extract PID
		matches := ssPIDRegex.FindStringSubmatch(processField)
		if len(matches) < 2 {
			continue
		}
		pid := matches[1]

		// Resolve PID → username
		username, err := resolveProcessUser(pid, cache)
		if err != nil {
			logger.Debug("failed to resolve PID user", "pid", pid, "err", err)
			continue
		}

		// Check if this sshd process has a PTY (already counted by `who`)
		if hasAssociatedPTY(pid, ptyTTYs) {
			continue
		}

		sessions = append(sessions, Session{
			Username:    username,
			TTY:         "",
			FromIP:      remoteIP,
			SessionType: "ssh-npty",
		})
	}

	return sessions, nil
}

// resolveVNCUser resolves the username for a VNC connection from the ss process field.
// Falls back to finding the Xvnc process listening on the given local port.
func resolveVNCUser(processField string, localPort int, cache *UserLookupCache) string {
	if processField != "" {
		matches := ssPIDRegex.FindStringSubmatch(processField)
		if len(matches) >= 2 {
			if u, err := resolveProcessUser(matches[1], cache); err == nil {
				return u
			}
		}
	}
	if localPort > 0 {
		return resolveVNCOwner(context.Background(), localPort, cache)
	}
	return ""
}

// collectVNCSessions detects VNC sessions on ports 5901-64999.
func collectVNCSessions(ctx context.Context, logger *slog.Logger, cache *UserLookupCache) ([]Session, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ss", "-tnp", "state", "established",
		"(", "sport", ">=", ":5901", "sport", "<=", ":64999", ")").Output()
	if err != nil {
		return nil, fmt.Errorf("ss vnc ports: %w", err)
	}

	var sessions []Session
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Recv-Q") || strings.HasPrefix(line, "State") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		localAddr, peerAddr, processField := parseSSFields(fields)
		localPort := extractPort(localAddr)

		username := resolveVNCUser(processField, localPort, cache)
		if username == "" {
			continue
		}

		displayNum := ""
		if localPort >= 5901 {
			displayNum = strconv.Itoa(localPort - 5900)
		}

		sessions = append(sessions, Session{
			Username:    username,
			TTY:         fmt.Sprintf("vnc:%s", displayNum),
			FromIP:      extractIP(peerAddr),
			SessionType: "vnc",
		})
	}

	return sessions, nil
}

// parseSSFields extracts localAddr, peerAddr, and process field from ss output fields.
func parseSSFields(fields []string) (localAddr, peerAddr, processField string) {
	for i, f := range fields {
		if strings.Contains(f, "pid=") {
			processField = f
			if i >= 2 {
				localAddr = fields[i-2]
				peerAddr = fields[i-1]
			}
			return
		}
	}
	return
}

// resolveProcessUser reads /proc/<pid>/status to find the UID, then resolves
// to username via the shared UserLookupCache (timeout-protected NSS lookup).
func resolveProcessUser(pid string, cache *UserLookupCache) (string, error) {
	statusPath := filepath.Join("/proc", pid, "status")
	data, err := os.ReadFile(statusPath) //nolint:gosec // path constructed from numeric PID, not user input
	if err != nil {
		return "", fmt.Errorf("read %s: %w", statusPath, err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uid := fields[1] // Real UID
				entry := cache.LookupByUID(uid)
				if entry.Err != nil {
					return "", fmt.Errorf("lookup uid %s: %w", uid, entry.Err)
				}
				return entry.Username, nil
			}
		}
	}

	return "", fmt.Errorf("no Uid line in /proc/%s/status", pid)
}

// resolveVNCOwner finds the Xvnc/Xtigervnc process listening on the given port
// and returns its owner username.
func resolveVNCOwner(ctx context.Context, port int, cache *UserLookupCache) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Find the listening process on this specific port
	out, err := exec.CommandContext(ctx, "ss", "-tlnp", "sport", "=", fmt.Sprintf(":%d", port)).Output() //nolint:gosec // port is an integer, not user input
	if err != nil {
		return ""
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		matches := ssPIDRegex.FindStringSubmatch(line)
		if len(matches) >= 2 {
			if username, err := resolveProcessUser(matches[1], cache); err == nil {
				return username
			}
		}
	}

	return ""
}

// extractIP extracts the IP address from an address:port string.
// Handles both IPv4 "1.2.3.4:22" and IPv6 "[::1]:22" formats.
func extractIP(addrPort string) string {
	if addrPort == "" {
		return ""
	}
	// IPv6 bracket notation
	if strings.HasPrefix(addrPort, "[") {
		idx := strings.LastIndex(addrPort, "]:")
		if idx >= 0 {
			return strings.Trim(addrPort[:idx+1], "[]")
		}
		return strings.Trim(addrPort, "[]")
	}
	// IPv4 or hostname:port
	idx := strings.LastIndex(addrPort, ":")
	if idx >= 0 {
		return addrPort[:idx]
	}
	return addrPort
}

// extractPort extracts the port number from an address:port string.
func extractPort(addrPort string) int {
	if addrPort == "" {
		return 0
	}
	idx := strings.LastIndex(addrPort, ":")
	if idx < 0 {
		return 0
	}
	port, err := strconv.Atoi(addrPort[idx+1:])
	if err != nil {
		return 0
	}
	return port
}

// getPTYTTYs returns a set of TTY device names from current `who` output
// so that SSH connections with an associated PTY can be excluded from non-PTY count.
func getPTYTTYs(ctx context.Context) map[string]struct{} {
	ttys := make(map[string]struct{})
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "who").Output()
	if err != nil {
		return ttys
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 {
			ttys[fields[1]] = struct{}{}
		}
	}
	return ttys
}

// hasAssociatedPTY checks whether an sshd process (by PID) has a child process
// with a PTY that appears in the `who` output.
func hasAssociatedPTY(sshdPID string, ptyTTYs map[string]struct{}) bool {
	// Read the children of this sshd process
	childrenPath := filepath.Join("/proc", sshdPID, "task", sshdPID, "children")
	data, err := os.ReadFile(childrenPath) //nolint:gosec // path constructed from numeric PID, not user input
	if err != nil {
		// If we can't read children, check if the sshd process itself has a TTY
		return checkProcessTTY(sshdPID, ptyTTYs)
	}

	// Check each child PID for TTY association
	for _, childPID := range strings.Fields(string(data)) {
		if checkProcessTTY(childPID, ptyTTYs) {
			return true
		}
	}

	return false
}

// checkProcessTTY checks if a process has a controlling TTY that matches `who` output.
func checkProcessTTY(pid string, ptyTTYs map[string]struct{}) bool {
	statPath := filepath.Join("/proc", pid, "stat")
	data, err := os.ReadFile(statPath) //nolint:gosec // path constructed from numeric PID, not user input
	if err != nil {
		return false
	}

	// /proc/<pid>/stat format: pid (comm) state ppid pgrp session tty_nr ...
	// tty_nr is field 7 (0-indexed: 6). A value of 0 means no TTY.
	// We need to skip past the (comm) field which may contain spaces.
	content := string(data)
	closeParen := strings.LastIndex(content, ")")
	if closeParen < 0 || closeParen+2 >= len(content) {
		return false
	}

	rest := strings.Fields(content[closeParen+2:])
	// rest[0]=state, rest[1]=ppid, rest[2]=pgrp, rest[3]=session, rest[4]=tty_nr
	if len(rest) < 5 {
		return false
	}

	ttyNr, err := strconv.Atoi(rest[4])
	if err != nil || ttyNr == 0 {
		return false
	}

	// tty_nr encodes major:minor. For pts devices, major=136.
	// The minor number corresponds to pts/N.
	major := (ttyNr >> 8) & 0xff
	minor := ttyNr & 0xff
	if major == 136 {
		ptsName := fmt.Sprintf("pts/%d", minor)
		if _, ok := ptyTTYs[ptsName]; ok {
			return true
		}
	}

	return false
}
