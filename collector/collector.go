package collector

import (
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// SSHPortFilter returns ss filter arguments for the configured SSH ports.
// Single port produces: ":22" (used as sport = :22).
// Multiple ports produce: "(" "sport" "=" ":22" "or" "sport" "=" ":2222" ")".
func SSHPortFilter(ports []int) []string {
	if len(ports) == 0 {
		return []string{":22"}
	}
	if len(ports) == 1 {
		return []string{fmt.Sprintf(":%d", ports[0])}
	}
	// Multiple ports: build ( sport = :P1 or sport = :P2 ... )
	args := []string{"("}
	for i, p := range ports {
		if i > 0 {
			args = append(args, "or")
		}
		args = append(args, "sport", "=", fmt.Sprintf(":%d", p))
	}
	args = append(args, ")")
	return args
}

// Config holds the shared configuration for all collectors.
type Config struct {
	ExcludeUsers map[string]struct{}
	Logger       *slog.Logger
	Hostname     string
	UserCache    *UserLookupCache
	SSHPorts     []int // SSH ports to monitor (default: [22])
}

// SubCollector is implemented by each metric-specific collector.
type SubCollector interface {
	Describe(ch chan<- *prometheus.Desc)
	Collect(ch chan<- prometheus.Metric)
}

// MasterCollector orchestrates all sub-collectors and implements prometheus.Collector.
type MasterCollector struct {
	cfg                Config
	subCollectors      []SubCollector
	sessions           *SessionCollector
	descUp             *prometheus.Desc
	descScrapeDuration *prometheus.Desc
}

// NewMasterCollector creates the master collector with all sub-collectors wired together.
func NewMasterCollector(cfg Config) *MasterCollector {
	// Initialize the shared user lookup cache if not provided
	if cfg.UserCache == nil {
		cfg.UserCache = NewUserLookupCache(2*time.Second, 5*time.Minute)
	}

	sessions := NewSessionCollector(cfg)
	vnc := NewVNCCollector(cfg)
	ssh := NewSSHCollector(cfg, vnc.CountVNC)

	mc := &MasterCollector{
		cfg:      cfg,
		sessions: sessions,
		subCollectors: []SubCollector{
			sessions,
			ssh,
			vnc,
			NewAuthCollector(cfg),
			NewResourceCollector(cfg),
			NewLastlogCollector(cfg),
			NewUserInfoCollector(cfg, sessions.ActiveUsers),
		},
		descUp: prometheus.NewDesc(
			"user_sessions_up",
			"Whether the user sessions exporter is up (1=healthy).",
			nil, nil,
		),
		descScrapeDuration: prometheus.NewDesc(
			"user_sessions_scrape_duration_seconds",
			"Duration of last metrics collection in seconds.",
			nil, nil,
		),
	}
	return mc
}

// Describe sends all metric descriptors from all sub-collectors.
func (mc *MasterCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, sc := range mc.subCollectors {
		sc.Describe(ch)
	}
	ch <- mc.descUp
	ch <- mc.descScrapeDuration
}

// Collect calls each sub-collector with panic recovery.
func (mc *MasterCollector) Collect(ch chan<- prometheus.Metric) {
	start := time.Now()

	for _, sc := range mc.subCollectors {
		safeCollect(sc, ch, mc.cfg.Logger)
	}

	ch <- prometheus.MustNewConstMetric(mc.descScrapeDuration, prometheus.GaugeValue, time.Since(start).Seconds())
	ch <- prometheus.MustNewConstMetric(mc.descUp, prometheus.GaugeValue, 1)
}

// safeCollect wraps a sub-collector's Collect in a defer/recover to prevent panics
// from crashing the exporter.
func safeCollect(sc SubCollector, ch chan<- prometheus.Metric, logger *slog.Logger) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("collector panicked",
				"collector", fmt.Sprintf("%T", sc),
				"panic", r,
			)
		}
	}()
	sc.Collect(ch)
}

// IsExcluded returns true if the username should be excluded from metrics.
// A user is excluded if their UID < 1000 or they are in the exclusion list.
// Uses the shared UserLookupCache for timeout-protected NSS lookups.
func IsExcluded(username string, cfg Config) bool {
	if _, ok := cfg.ExcludeUsers[username]; ok {
		return true
	}
	entry := cfg.UserCache.LookupByName(username)
	if entry.Err != nil {
		return false
	}
	uid, err := strconv.Atoi(entry.UID)
	if err != nil {
		return false
	}
	return uid < 1000
}
