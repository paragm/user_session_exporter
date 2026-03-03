# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.1] - 2026-03-03

### Added
- Configurable SSH ports via `SSH_PORTS` env var (comma-separated, default: `22`)
- Expanded failed login detection: now matches `Invalid user`, `Connection closed by authenticating user`, and `Received disconnect from ... [preauth]` in addition to `Failed password`

### Fixed
- Resource metrics (`user_sessions_cpu_ratio`, `user_sessions_memory_bytes`, `user_sessions_process_count`) now use real UID (`ruser`) instead of effective UID (`user`), correctly attributing `sudo` processes to the original user

## [1.3.0] - 2026-02-28

### Changed
- Renamed all metrics to use `user_sessions_` prefix consistently
- Added exec timeouts on all external commands (5-15s context deadlines)

### Security
- Added HTTP server timeouts (read, write, idle)
- Hardened systemd service with syscall filtering

## [1.2.0] - 2026-02-15

### Changed
- Changed default port from 9101 to 10041 to avoid conflicts

## [1.1.0] - 2026-02-10

### Fixed
- Fixed build error: removed unavailable `version.NewCollector` call

## [1.0.0] - 2026-02-01

### Added
- Initial release
- Session detection via `who`, `ss`, `/proc` for PTY, SSH non-PTY, and VNC sessions
- Authentication metrics from journalctl/auth.log (failed logins, root logins)
- Resource metrics per user (CPU ratio, memory bytes, process count)
- Last login timestamp tracking
- User identity info metrics
- SSH and VNC connection counting
- NSS lookup cache with timeout protection
- Systemd service with security hardening
- Environment variable overrides (PORT, LOG_LEVEL, EXCLUDE_USERS)
