# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

First public pre-release. Dry-run only. No blocking.

### Added

- Package skeleton with Laravel package discovery.
- Configuration file with dry-run mode by default.
- `ThreatType` and `ConfidenceLevel` enums.
- `ThreatMatch` DTO and `RuleInterface`.
- Seven detection rules:
  - `UnionSelectRule` (SQL injection)
  - `CommentInjectionRule` (SQL injection)
  - `StackedQueryRule` (SQL injection)
  - `TimeBasedRule` (SQL injection)
  - `PrivateIpRule` (SSRF)
  - `MetadataEndpointRule` (SSRF)
  - `DangerousCommandRule` (process execution)
- `ThreatAnalyzer` engine with per-type rule filtering and per-rule
  failure isolation.
- `Redactor` for removing sensitive values from log context.
- `RequestContext` adding client IP, HTTP method, route and user id to
  findings.
- `SafeLogger` with JSON payloads and per-source deduplication.
- `DatabaseInterceptor` using `DB::beforeExecuting`, on the default
  connection.
- `HttpInterceptor` using `Http::globalRequestMiddleware`.
- `ThreatDetected` event, carrying the redacted context.
- `Laronclad` entry point and Facade.
- Artisan commands: `laronclad:status`, `laronclad:clear-logs`. They
  stay available when monitoring is disabled.

### Security

- Fail-open by default: Laronclad never takes down the application.
  Hook installation, rule evaluation, request context, deduplication
  and log writes each contain their own failures.
- Failures are reported to PHP's error log by exception class only,
  never by message, so connection strings and SQL do not leak.
- No `unserialize()` on untrusted data.
- Sensitive values are redacted before logging and before the event
  is fired. Only metadata is logged, never query text or bindings.
- The `UnionSelectRule` pattern has a long-input timing test.
  PCRE backtrack-limit handling is not implemented yet.

### Known limitations

- `ProcessGuard` exists but is not hooked into Laravel, so process
  execution is not monitored. The `process.enabled` option is reserved.
- The whitelist option is accepted but not applied.
- Only the default database connection is monitored, and only the
  first 8 KB of each query is analyzed.
- Detection rules are heuristic and can be bypassed; see the README.

[Unreleased]: https://github.com/FirasArafah/laronclad/commits/main
