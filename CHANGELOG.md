# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha] - 2026-11-22

First public pre-release. Dry-run only. No blocking.

### Added

- Monitoring of SQL queries on every database connection, including ones
  established after boot and after a purge.
- Monitoring of outbound requests made with Laravel's HTTP client.
- Seven detection rules:
  - `UnionSelectRule`, `CommentInjectionRule`, `StackedQueryRule` and
    `TimeBasedRule` (SQL injection)
  - `PrivateIpRule` and `MetadataEndpointRule` (SSRF), which parse the host
    instead of matching one spelling: dotted, decimal, octal and hex IPv4,
    IPv6 literals, IPv4 inside IPv6, percent-encoding, `localhost`
  - `DangerousCommandRule` (process execution)
- `analysis_limit` and `oversized_input` findings, reported when a pattern
  fails on an input or an input is too large to inspect fully.
- A route and Artisan command whitelist, matched by name with `fnmatch()`
  patterns.
- `ThreatDetected` event, carrying the redacted context.
- Request context on every finding: client IP, HTTP method, route and user
  id when already known.
- Default log file `storage/logs/laronclad.log` with one JSON object per
  line, redaction of sensitive keys and per-source deduplication.
- `laronclad:status` and `laronclad:clear-logs` commands, available even
  when monitoring is disabled.
- `ProcessGuard` for inspecting commands by hand.
- `Laronclad` entry point and Facade.

### Security

- Fail-open by default: Laronclad never takes down the application. Hook
  installation, rule evaluation, request context, deduplication, whitelist
  checks and log writes each contain their own failures.
- Failures are reported to PHP's error log by exception class only, never
  by message, so connection strings and SQL do not leak.
- A failing whitelist check monitors instead of skipping. Whitelist patterns
  made only of stars are ignored.
- A failed pattern match is reported as a finding, not treated as "no
  match". Analysis is bounded per input, with the start and end of oversized
  input still inspected and flagged.
- Sensitive values are redacted before logging and before the event is
  fired. Only metadata is logged, never query text or bindings.
- No `unserialize()` on untrusted data.

### Known limitations

- Detection is heuristic and can be bypassed. See the README for what is
  known to be flagged by mistake or missed.
- Process execution is not hooked into Laravel. `ProcessGuard` must be
  called by hand, and the `process.enabled` option is reserved.
- Only Laravel's HTTP client is observed, and only the request host is
  checked. Names are not resolved.
- The default log file is not rotated, and internal failure lines are not
  rate limited.
- Not tested under Octane or other long-running servers.

[Unreleased]: https://github.com/FirasArafah/laronclad/compare/v0.1.0-alpha...HEAD
[0.1.0-alpha]: https://github.com/FirasArafah/laronclad/releases/tag/v0.1.0-alpha
