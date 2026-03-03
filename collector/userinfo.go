package collector

import (
	"github.com/prometheus/client_golang/prometheus"
)

// UserInfoCollector collects user_sessions_user_info (info-pattern metric, value=1).
type UserInfoCollector struct {
	cfg           Config
	descInfo      *prometheus.Desc
	activeUsersFn func() []string
}

// NewUserInfoCollector creates a new UserInfoCollector.
func NewUserInfoCollector(cfg Config, activeUsersFn func() []string) *UserInfoCollector {
	return &UserInfoCollector{
		cfg: cfg,
		descInfo: prometheus.NewDesc(
			"user_sessions_user_info",
			"User identity information for active session users (value=1).",
			[]string{"username", "real_name", "uid", "primary_group"}, nil,
		),
		activeUsersFn: activeUsersFn,
	}
}

// Describe implements prometheus.Collector.
func (c *UserInfoCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.descInfo
}

// Collect implements prometheus.Collector.
func (c *UserInfoCollector) Collect(ch chan<- prometheus.Metric) {
	users := c.activeUsersFn()

	seen := make(map[string]struct{})
	for _, username := range users {
		if _, ok := seen[username]; ok {
			continue
		}
		seen[username] = struct{}{}

		entry := c.cfg.UserCache.LookupByName(username)
		if entry.Err != nil {
			c.cfg.Logger.Debug("failed to lookup user info", "username", username, "err", entry.Err)
			continue
		}

		// Resolve primary group via cache
		primaryGroup, _ := c.cfg.UserCache.LookupGroupByGID(entry.GID)

		ch <- prometheus.MustNewConstMetric(
			c.descInfo, prometheus.GaugeValue, 1,
			username, entry.Name, entry.UID, primaryGroup,
		)
	}
}
