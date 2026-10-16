# Laronclad

[![Latest Version on Packagist](https://img.shields.io/packagist/v/firasarafah/laronclad.svg?style=flat-square)](https://packagist.org/packages/firasarafah/laronclad)
[![Tests](https://img.shields.io/github/actions/workflow/status/FirasArafah/laronclad/tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/FirasArafah/laronclad/actions/workflows/tests.yml)
[![Static Analysis](https://img.shields.io/github/actions/workflow/status/FirasArafah/laronclad/static-analysis.yml?branch=main&label=static%20analysis&style=flat-square)](https://github.com/FirasArafah/laronclad/actions/workflows/static-analysis.yml)
[![Total Downloads](https://img.shields.io/packagist/dt/firasarafah/laronclad.svg?style=flat-square)](https://packagist.org/packages/firasarafah/laronclad)

Runtime monitoring layer for Laravel applications.

Laronclad watches what your Laravel app does while it runs: the SQL
queries it sends and the outbound requests it makes with Laravel's
HTTP client. It runs in dry-run mode and never blocks anything.

**Laronclad is not a WAF replacement.** It sees what your app does
after a request arrives, not what happens before. It does not protect
against an attacker with code execution. Use it as one layer among
several.

## Status

**Pre-alpha (0.1.0-alpha).** The API may change between minor versions
until 1.0. Detection is heuristic, so expect both missed attacks and
false positives. Please read [Known limitations](#known-limitations)
before you run it anywhere that matters.

## What this release does

- Inspects SQL queries on the default database connection for UNION
  SELECT, SQL comments, stacked queries and time-based functions.
- Inspects the host of outbound requests made with Laravel's HTTP
  client for private or reserved IP addresses and cloud metadata
  endpoints.
- Writes findings to a log, adds request context (client IP, HTTP
  method, route, user id when known) and redacts sensitive values.
- Fires a `ThreatDetected` event you can forward elsewhere.
- Never throws into your application: every failure path is contained.

## What this release does not do

- **Block anything.** Dry-run only.
- **Monitor process execution.** The `ProcessGuard` class exists, but
  nothing calls it automatically yet.
- **Apply the whitelist.** The `whitelist` config option is reserved
  and has no effect yet.
- Replace a WAF, SAST, DAST or dependency scanner.

## Installation

This is a pre-release, so pin the version explicitly:

    composer require firasarafah/laronclad:0.1.0-alpha

Optionally publish the config file:

    php artisan vendor:publish --tag="laronclad-config"

## Usage

Once installed, Laronclad starts monitoring automatically. No code
changes are needed.

### Check status

    php artisan laronclad:status

### Clear logs

    php artisan laronclad:clear-logs

This clears the default log file only. If you configured your own log
channel, clear it with that channel's tools.

### Listen for threats

    use Laronclad\Events\ThreatDetected;

    Event::listen(function (ThreatDetected $event) {
        // $event->match   the finding (type, confidence, rule)
        // $event->context redacted metadata, safe to forward
    });

The event is not fired for deduplicated findings.

## Configuration

Settings live in `config/laronclad.php`. Each one has an environment
variable:

| Variable | Default | Meaning |
|---|---|---|
| `LARONCLAD_ENABLED` | `true` | Turn all monitoring hooks on or off |
| `LARONCLAD_MODE` | `dry-run` | Only `dry-run` exists in this release |
| `LARONCLAD_LOG_CHANNEL` | none | Your own log channel; none means a dedicated file |
| `LARONCLAD_LOG_DEDUP_WINDOW` | `60` | Seconds; `0` turns deduplication off |
| `LARONCLAD_DATABASE_ENABLED` | `true` | Monitor database queries |
| `LARONCLAD_DATABASE_MAX_INPUT` | `8192` | Bytes of each query that are analyzed |
| `LARONCLAD_HTTP_ENABLED` | `true` | Monitor outbound HTTP requests |
| `LARONCLAD_PROCESS_ENABLED` | `true` | Reserved, no effect yet |

## What gets logged

By default findings go to `storage/logs/laronclad.log`. The file is
not rotated, so keep an eye on its size.

Each entry carries a JSON payload like this:

    {
      "time": "2026-10-16T10:22:01Z",
      "type": "sqli",
      "confidence": "medium",
      "rule": "union_select",
      "description": "UNION SELECT pattern found in query",
      "context": {"query_length": 74, "ip": "203.0.113.5", "method": "GET", "route": "users.index"}
    }

Only metadata is logged. Query text, query bindings, request bodies,
headers and cookies are not. The target host is logged for outbound
requests. Values under keys such as `password`, `token`, `secret`,
`api_key`, `authorization`, `cookie`, `session` and `csrf` are
redacted before they are written and before the event is fired.

If the cache store is unavailable, deduplication is skipped and
findings are still logged.

## Known limitations

- **Heuristic detection.** Novel techniques and variants will pass
  through, and legitimate traffic will sometimes be flagged (for
  example SQL comments or a semicolon inside a string).
- **Database coverage.** Only the default connection is monitored, and
  only the first 8 KB of each query is analyzed.
- **Outbound HTTP coverage.** Only Laravel's HTTP client is observed,
  and only the request host is checked. Hosts are matched as literal
  IP addresses or known metadata hostnames. Names are not resolved, so
  `localhost`, DNS tricks and numeric IP encodings are not detected.
- **Bypasses.** Raw PDO, raw curl and direct `exec()` calls do not go
  through Laravel's hooks. An attacker with code execution can disable
  Laronclad.
- **Overhead.** Every query and request goes through the checks.
  Measure it in your environment.
- **Log growth.** Deduplication helps, but a busy app under attack can
  still write many lines.

## Requirements

- PHP 8.2 or newer
- Laravel 12.x or 13.x

Laronclad supports only Laravel versions that still receive security
fixes from the Laravel team.

## Testing

    composer test

## Changelog

See CHANGELOG.md.

## Security

Report vulnerabilities through GitHub Security Advisories. See
SECURITY.md.

## License

Apache License 2.0. See LICENSE.
