# Laronclad

[![Latest Version on Packagist](https://img.shields.io/packagist/v/firasarafah/laronclad.svg?style=flat-square)](https://packagist.org/packages/firasarafah/laronclad)
[![Tests](https://img.shields.io/github/actions/workflow/status/FirasArafah/laronclad/tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/FirasArafah/laronclad/actions/workflows/tests.yml)
[![Static Analysis](https://img.shields.io/github/actions/workflow/status/FirasArafah/laronclad/static-analysis.yml?branch=main&label=static%20analysis&style=flat-square)](https://github.com/FirasArafah/laronclad/actions/workflows/static-analysis.yml)
[![Total Downloads](https://img.shields.io/packagist/dt/firasarafah/laronclad.svg?style=flat-square)](https://packagist.org/packages/firasarafah/laronclad)

A runtime security sensor for Laravel.

Laronclad watches what your app does while it runs and logs what looks like
an attack: SQL queries that resemble injection, and outbound HTTP requests
aimed at internal or cloud-metadata addresses. It observes, detects and
reports. It logs findings and fires an event, and it never blocks anything.

**Laronclad is not a WAF replacement.** It sees what your app does after a
request arrives, not what happens before. It does not protect against an
attacker with code execution. Use it as one layer among several. The full
intended scope, and what Laronclad will never become, is in
[SCOPE.md](SCOPE.md).

## Status

**Pre-release (0.1.1-alpha).** The API may change between minor versions
until 1.0. Detection is heuristic, so expect both missed attacks and false
positives. [SCOPE.md](SCOPE.md) describes where the project is going, and
its Status table shows what exists today. Please read
[Known limitations](#known-limitations) before you run it anywhere that
matters, and [send feedback](#feedback).

## What this release does

- Inspects SQL on every database connection for UNION SELECT, SQL comments,
  stacked queries and time-based functions.
- Inspects the host of outbound requests made with Laravel's HTTP client for
  private, loopback and reserved addresses (in any spelling an HTTP client
  accepts) and cloud metadata endpoints.
- Writes findings to a log with request context (client IP, HTTP method,
  route, user id when known) and redacts sensitive values.
- Fires a `ThreatDetected` event you can forward elsewhere.
- Lets you exclude routes and Artisan commands.
- Never throws into your application: every failure path is contained.

## What this release does not do

- **Block anything.** Laronclad detects and reports. It does not block, and
  no blocking is planned.
- **Monitor process execution automatically.** The `ProcessGuard` class
  exists, but nothing calls it for you. See [Inspect a command by hand](#inspect-a-command-by-hand).
- **Explain findings in detail yet.** A finding carries its rule, type,
  confidence and request context, but no separate "why" text.
- Replace a WAF, SAST, DAST or dependency scanner.

## Installation

This is a pre-release, so name the version explicitly:

    composer require firasarafah/laronclad:0.1.1-alpha

Optionally publish the config file:

    php artisan vendor:publish --tag="laronclad-config"

## Usage

Once installed, Laronclad starts monitoring automatically. No code changes
are needed.

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

The event is not fired for deduplicated findings. It is the integration
point for reacting to findings: forward them to your SIEM, alert on them or
store them. Laronclad itself takes no action.

### Exclude routes and commands

In `config/laronclad.php`:

    'whitelist' => [
        'routes' => ['admin.*', 'horizon.*'],
        'commands' => ['migrate', 'queue:work'],
    ],

Routes are matched by route name and commands by command name, with
`fnmatch()` patterns (`*` matches any characters, dots included). Database
queries and outbound requests made by a listed route or command are not
inspected.

A route is only known once routing has run, so queries and requests made
earlier (in global middleware, for example) are still monitored. A pattern
made only of stars is ignored, because it would switch monitoring off: use
`LARONCLAD_ENABLED=false` for that. If checking the whitelist ever fails,
the request is monitored, never skipped.

### Inspect a command by hand

Laravel has no public hook for observing process execution, so this is
manual for now:

    use Laronclad\Process\ProcessGuard;

    app(ProcessGuard::class)->inspect($command);

`$command` is a string or an array. The guard logs findings like everything
else, and honors the whitelist.

## What it detects

| Rule | Type | Confidence | What it finds |
|---|---|---|---|
| `union_select` | SQL | Medium | `UNION SELECT` with any whitespace, comments, `ALL`/`DISTINCT` or parentheses between the words, including MySQL versioned comments |
| `comment_injection` | SQL | Low | A SQL comment marker (`--`, `#`, `/*`) |
| `stacked_query` | SQL | Medium | A second statement after a semicolon |
| `time_based` | SQL | Medium | `SLEEP`, `BENCHMARK`, `pg_sleep` (also `_for`, `_until`), `WAITFOR DELAY` and `TIME`, Oracle `DBMS_LOCK.SLEEP` and `DBMS_PIPE.RECEIVE_MESSAGE` |
| `private_ip` | SSRF | High | A request to a private, loopback, link-local, carrier-grade NAT or reserved address, written as dotted, decimal, octal or hex IPv4, an IPv6 literal, IPv4 inside IPv6, or `localhost` |
| `metadata_endpoint` | SSRF | High | AWS, Azure, GCP and Alibaba Cloud metadata endpoints, in any of those spellings |
| `dangerous_command` | Process | Medium | Recursive `rm` of the root or home, a download piped into a shell or interpreter, reverse shell markers, world-writable `chmod` (only through `ProcessGuard`) |

Two more findings report that analysis itself was limited:

| Rule | Confidence | Meaning |
|---|---|---|
| `analysis_limit` | Medium | A pattern could not process the input (malformed data or a matcher limit). Input that defeats a matcher is suspicious in itself. |
| `oversized_input` | Low | The input was too large to inspect fully, so only its start and end were checked. |

## What gets logged

By default findings go to `storage/logs/laronclad.log`, one JSON object per
line, so the file works with `jq` and log shippers. The file is not rotated,
so keep an eye on its size. If you set your own log channel, that channel's
formatter decides how lines look.

Each line looks like this:

    {"time":"2026-11-22T10:22:01Z","type":"sqli","confidence":"medium","rule":"union_select","description":"UNION SELECT pattern found in query","context":{"query_length":74,"ip":"203.0.113.5","method":"GET","route":"users.index"}}

The format is consistent but not yet versioned, so fields may change before
1.0.

Only metadata is logged. Query text, query bindings, request bodies,
headers and cookies are not. The context carries the size of the query, the
target host of an outbound request, and request metadata: client IP, HTTP
method, route name (or URI pattern), and the user id when one is already
known. Findings from an Artisan command, queue worker or scheduled task
carry the command name (`"command":"queue:work"`) instead of the client IP,
method and route, because there is no real request behind them. Values under keys such as `password`, `token`, `secret`, `api_key`,
`authorization`, `cookie`, `session` and `csrf` are redacted before they
are written and before the event is fired.

The same finding from the same source (client IP, else user id, else
command) is logged once per window, 60 seconds by default. If the cache store is unavailable,
deduplication is skipped and findings are still logged.

Client IPs and user ids can be personal data. Set retention for the log file
according to your own obligations.

## Configuration

Settings live in `config/laronclad.php`. Each one has an environment
variable:

| Variable | Default | Meaning |
|---|---|---|
| `LARONCLAD_ENABLED` | `true` | Turn all monitoring hooks on or off |
| `LARONCLAD_MODE` | `dry-run` | Only `dry-run` exists, and no other mode is planned |
| `LARONCLAD_LOG_CHANNEL` | none | Your own log channel; none means a dedicated file |
| `LARONCLAD_LOG_DEDUP_WINDOW` | `60` | Seconds; `0` turns deduplication off |
| `LARONCLAD_DATABASE_ENABLED` | `true` | Monitor database queries |
| `LARONCLAD_DATABASE_MAX_INPUT` | `1048576` | Bytes of each query analyzed whole; longer queries get their start and end checked and an `oversized_input` finding |
| `LARONCLAD_HTTP_ENABLED` | `true` | Monitor outbound HTTP requests |
| `LARONCLAD_PROCESS_ENABLED` | `true` | Reserved, no effect yet |

The whitelist has no environment variable. Edit `whitelist.routes` and
`whitelist.commands` in the published config.

## How it is built

- **Fail-open.** Hook installation, rule evaluation, request context,
  deduplication, whitelist checks and log writes each contain their own
  failures. A failure never reaches your application, and the exception
  class (never its message) goes to PHP's error log.
- **No payloads in logs.** Only metadata, redacted by key before it is
  written.
- **Bounded cost.** Every pattern is possessive or bounded, and the work per
  input is capped: 1 MiB per query, 8 KiB per command, 255 characters per
  host. Normal input is analyzed in a few microseconds, and a monitored
  query costs about 6 to 10 µs end to end (about 15 µs for an outbound
  request). See
  [benchmarks](benchmarks/README.md), and run `composer bench` on your own
  machine.
- **Public extension points only.** Laronclad uses Laravel's documented
  hooks and nothing internal.

## Known limitations

- **Heuristic detection.** Novel techniques and variants will pass through,
  and legitimate traffic will sometimes be flagged: comment markers or a
  semicolon inside a string, a UNION written inside a comment, a table named
  `sleep` followed by an opening parenthesis, `chmod 777` anywhere.
- **Database.** Queries are seen as the SQL text with placeholders, not the
  bound values. Queries over 1 MiB are only partly inspected and flagged.
- **Outbound HTTP.** Only Laravel's HTTP client is observed, and only the
  request host is checked. Hosts are matched as address literals (in any
  spelling) or known names such as `localhost` and the metadata hosts. Names
  are not resolved, so a DNS name that points at a private address is not
  detected. Redirects are not specifically handled.
- **Internal services.** Calls from your own app to private addresses are
  flagged. There is no host allowlist yet.
- **Bypasses.** Raw PDO, raw curl and direct `exec()` calls do not go
  through Laravel's hooks. An attacker with code execution can disable
  Laronclad.
- **Process execution** is manual, as described above.
- **Whitelist.** A route is only known once routing has run. Queue jobs are
  not matched by job: whitelisting a `queue:work` command excludes
  everything that worker runs.
- **Deduplication.** Findings from console and queue runs are deduplicated
  per command, so all jobs handled by one `queue:work` worker share one key
  per rule and window.
- **Logging.** The default log file is not rotated. Internal failures write
  one line each to PHP's error log, without rate limiting.
- **Not tested yet** under Octane or other long-running servers.

## Roadmap

A rough plan, not a promise. Feedback decides the order. The boundaries
Laronclad keeps, including that it will not block, are in
[SCOPE.md](SCOPE.md).

- **0.2**: false-positive tuning from real-world feedback, a short "why" for
  every finding, a versioned log and event format, log rotation and
  retention, an allowlist for hosts, rate-limited internal error reporting.
- **0.3**: a documented way to observe process execution, queue job
  whitelisting, per-rule switches and a documented way to add your own rules.
- **0.4**: Octane support and benchmark regression checks in CI.
- **1.0**: a stable API and a stable event format.

## Feedback

Feedback on detection is the most useful thing you can send: false
positives, missed attacks, rules that are noisy in a real application.
[Open an issue](https://github.com/FirasArafah/laronclad/issues/new/choose)
with the detection feedback template, and describe the *shape* of an input
rather than real queries, hosts or tokens.

## Requirements

- PHP 8.2 or newer
- Laravel 12.x or 13.x

Laronclad supports only Laravel versions that still receive security fixes
from the Laravel team.

## Testing

    composer test

## Scope

See [SCOPE.md](SCOPE.md) for what Laronclad is, what it will become, and
what it will never be.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Report vulnerabilities through GitHub Security Advisories. See
[SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
