# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha] - 2026-10-14

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
- `ThreatAnalyzer` engine with per-type rule filtering.
- `Redactor` for removing sensitive values from log context.
- `SafeLogger` with JSON lines format and deduplication.
- `DatabaseInterceptor` using `DB::beforeExecuting`.
- `HttpInterceptor` using `Http::globalRequestMiddleware`.
- `ProcessGuard` for command inspection.
- `Whitelist` support for routes and Artisan commands.
- `ThreatDetected` event.
- `Laronclad` entry point and Facade.
- Artisan commands: `laronclad:status`, `laronclad:clear-logs`.

### Security

- Fail-open by default: Laronclad never takes down the application.
- No `unserialize()` on untrusted data.
- Regex patterns tested against ReDoS.
- Sensitive values redacted before logging.

[Unreleased]: https://github.com/FirasArafah/laronclad/compare/v0.1.0-alpha...HEAD
[0.1.0-alpha]: https://github.com/FirasArafah/laronclad/releases/tag/v0.1.0-alpha
