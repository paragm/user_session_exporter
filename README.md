# User Session Exporter

[![CI](https://github.com/paragm/user_session_exporter/actions/workflows/ci.yml/badge.svg)](https://github.com/paragm/user_session_exporter/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/paragm/user_session_exporter)](https://goreportcard.com/report/github.com/paragm/user_session_exporter)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Prometheus exporter for active user sessions, authentication events, and per-user resource usage on Linux hosts.

## Overview

The User Session Exporter collects metrics about:

- **Active sessions** — PTY terminals, SSH (including non-PTY like VS Code Remote, scp, sftp), and VNC
- **Authentication** — Failed SSH login attempts, root logins
- **Resources** — Per-user CPU ratio, memory (RSS), and process count
- **Identity** — User info labels, last login timestamps

Sessions are detected from multiple sources (`who`, `ss`, `/proc`) and deduplicated. The exporter is designed to run on every monitored host.

## Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `user_sessions_logged_in_users` | Gauge | — | Number of unique users with active sessions |
| `user_sessions_session_active` | Gauge | `username`, `tty`, `from_ip`, `session_type` | Active session indicator (1 per session) |
| `user_sessions_failed_logins_1h` | Gauge | — | Failed SSH logins in the last 60 minutes |
| `user_sessions_root_logins_total` | Counter | — | Cumulative root login count |
| `user_sessions_ssh_connections` | Gauge | — | Established SSH connections (port 22) |
| `user_sessions_vnc_connections` | Gauge | — | Established VNC connections (ports 5901-64999) |
| `user_sessions_remote_connections` | Gauge | — | Total remote connections (SSH + VNC) |
| `user_sessions_cpu_ratio` | Gauge | `username` | Aggregate CPU usage ratio per user (0.0–1.0) |
| `user_sessions_memory_bytes` | Gauge | `username` | Aggregate RSS in bytes per user |
| `user_sessions_process_count` | Gauge | `username` | Number of processes per user |
| `user_sessions_last_login_timestamp_seconds` | Gauge | `username` | Unix timestamp of last login |
| `user_sessions_user_info` | Gauge | `username`, `real_name`, `uid`, `primary_group` | User identity (always 1) |
| `user_sessions_up` | Gauge | — | Exporter health (always 1 on success) |
| `user_sessions_scrape_duration_seconds` | Gauge | — | Duration of last collection |

## Installation

### From Source

```bash
git clone https://github.com/paragm/user_session_exporter.git
cd user_session_exporter
make build
sudo make install
```

### Systemd Service

```bash
sudo cp examples/systemd/user_sessions_exporter.service /etc/systemd/system/
sudo cp examples/systemd/user_sessions_exporter.env /etc/default/user-sessions-exporter
sudo systemctl daemon-reload
sudo systemctl enable --now user_sessions_exporter
```

## Configuration

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-web.listen-address` | `:10041` | Address to listen on for metrics |
| `-log.level` | `info` | Log level: debug, info, warn, error |
| `-version` | — | Print version and exit |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `PORT` | Override listen port |
| `LOG_LEVEL` | Override log level |
| `EXCLUDE_USERS` | Comma-separated usernames to exclude from metrics |

### Example Environment File

```bash
PORT=10041
LOG_LEVEL=info
EXCLUDE_USERS=nobody,daemon,www-data,zabbix,prometheus,grafana,postgres,mysql,redis,cadvisor
```

## Endpoints

| Path | Description |
|------|-------------|
| `/metrics` | Prometheus metrics |
| `/-/healthy` | Health check |
| `/-/ready` | Readiness check |
| `/` | Landing page |

## Building

```bash
make build          # Build for current platform
make build-linux    # Cross-compile for Linux amd64
make test           # Run tests with race detection
make lint           # Run golangci-lint
make coverage       # Generate HTML coverage report
```

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
