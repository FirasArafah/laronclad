# Laronclad

Runtime monitoring and protection layer for Laravel applications.

Laronclad is an application-level RASP package for Laravel. It
observes suspicious behavior inside your application while it
executes: database queries, outbound HTTP requests, and system
process calls. It runs in dry-run mode by default and never blocks.

## Status

Pre-alpha. No code yet. The repository currently contains the
project setup, composer.json, security policy, and the initial
README. The first package code will land in v0.1.0-alpha.

## What it is

- An internal monitoring layer for Laravel applications.
- A behavioral detection tool for suspicious patterns.
- A complement to WAFs, SAST, DAST, and other security tools.

## What it is not

- A replacement for a WAF or for dependency scanning.
- Protection against an attacker with code execution.
- A tool that catches every attack.

Laronclad runs in PHP, inside your application. It cannot see or
stop anything below the application layer.

## Planned for v0.1.0-alpha

- SQL query monitoring
- SSRF detection on outbound HTTP
- Process execution monitoring
- Dry-run only: log, never block
- Safe logging with redaction
- A demo app to test against

## Requirements

- PHP 8.2 or newer
- Laravel 12.x or 13.x

Laronclad supports only Laravel versions that still receive
security fixes from the Laravel team.

## Security

Report vulnerabilities through GitHub Security Advisories. See
SECURITY.md for details.

## Changelog

See CHANGELOG.md.

## License

Apache License 2.0. See LICENSE.
