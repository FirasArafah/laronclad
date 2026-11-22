# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2-alpha] - 2026-11-22

The same code as 0.1.1-alpha, published again under a new version number.
The commit history was rewritten to replace the maintainer's personal email
address in commit metadata. Packagist does not allow an existing version to
point to a rewritten commit, so 0.1.1-alpha is withdrawn and replaced by
this version. Install this version.

No code, behavior or dependency changes.

## [0.1.1-alpha] - 2026-11-22 [YANKED]

Withdrawn and replaced by 0.1.2-alpha, which contains the same code (see
above). The changes below are part of 0.1.2-alpha.

First installable public pre-release. It contains everything listed under
0.1.0-alpha below, plus the changes here.

### Fixed

- Findings from Artisan commands, queue workers and scheduled tasks were
  logged as `"method":"GET"` from `"ip":"127.0.0.1"`, because Laravel binds
  a placeholder request for console runs. They now carry the running
  command instead (`"command":"queue:work"`), and are deduplicated per
  command.
- `ProcessGuard::inspect()` could throw into the application when an array
  command held a part that is not text: an object raised an `Error`, and a
  nested array raised a warning that Laravel turns into an exception. It
  now contains its own failures like the other hooks, and skips parts that
  cannot be read as text.

### Changed

- The whitelist is built once and rebuilt only when its config changes,
  instead of on every query and outbound request. On the benchmark machine
  this lowers the cost of a monitored query from about 20 µs to about 6 to
  10 µs. Whitelist changes made at runtime still apply.

### Added

- A benchmark script (`composer bench`) that measures every detector and
  the end-to-end cost per query and outbound request, with Laronclad off
  and on. Results and method are in `benchmarks/README.md`. The script is
  not part of the installed package.

## [0.1.0-alpha] - 2026-11-22 [YANKED]

Withdrawn. Packagist serves an older, incomplete commit under this version
number and does not allow it to be replaced. Use 0.1.2-alpha.

First public pre-release. Detection only. No blocking.

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
- `SCOPE.md`, which defines what Laronclad is, what it will not become, and
  what exists today versus what is planned.

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
- Findings carry a rule, type, confidence and request context, but no
  separate explanation text. The log format is not versioned yet.
- The default log file is not rotated, and internal failure lines are not
  rate limited.
- No benchmark suite yet. Not tested under Octane or other long-running
  servers.

[Unreleased]: https://github.com/FirasArafah/laronclad/compare/v0.1.2-alpha...HEAD
[0.1.2-alpha]: https://github.com/FirasArafah/laronclad/compare/v0.1.1-alpha...v0.1.2-alpha
[0.1.1-alpha]: https://github.com/FirasArafah/laronclad/compare/v0.1.0-alpha...v0.1.1-alpha
[0.1.0-alpha]: https://github.com/FirasArafah/laronclad/releases/tag/v0.1.0-alpha
