# Laronclad

[![Latest Version on Packagist](https://img.shields.io/packagist/v/firasarafah/laronclad.svg?style=flat-square)](https://packagist.org/packages/firasarafah/laronclad)
[![Tests](https://img.shields.io/github/actions/workflow/status/FirasArafah/laronclad/tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/FirasArafah/laronclad/actions/workflows/tests.yml)
[![Static Analysis](https://img.shields.io/github/actions/workflow/status/FirasArafah/laronclad/static-analysis.yml?branch=main&label=static%20analysis&style=flat-square)](https://github.com/FirasArafah/laronclad/actions/workflows/static-analysis.yml)
[![Total Downloads](https://img.shields.io/packagist/dt/firasarafah/laronclad.svg?style=flat-square)](https://packagist.org/packages/firasarafah/laronclad)

Runtime monitoring and protection layer for Laravel applications.

Laronclad observes suspicious behavior inside your Laravel app while
it executes: database queries, outbound HTTP requests, and system
process calls. It runs in dry-run mode by default and never blocks.

**Laronclad is not a WAF replacement.** It sees what your app does
after a request arrives, not what happens before. It does not protect
against an attacker with code execution. Use it as one layer among
several.

## Status

**Pre-alpha.** API may change between minor versions until 1.0.

## Installation

Install via Composer:

    composer require firasarafah/laronclad

Publish the config file:

    php artisan vendor:publish --tag="laronclad-config"

## Usage

Once installed, Laronclad starts monitoring automatically. No code
changes are needed.

### Check status

    php artisan laronclad:status

### Clear logs

    php artisan laronclad:clear-logs

### Listen for threats

    use Laronclad\Events\ThreatDetected;

    Event::listen(function (ThreatDetected $event) {
        // Forward to Slack, Sentry, a SIEM, etc.
    });

### Whitelist routes or commands

In config/laronclad.php:

    'whitelist' => [
        'routes' => ['admin.*', 'horizon.*'],
        'commands' => ['migrate', 'queue:work'],
    ],

## What it detects

- SQL injection patterns (UNION SELECT, comments, stacked queries,
  time-based functions)
- SSRF attempts to private IPs and cloud metadata endpoints
- Dangerous shell commands

## What it does not do

- Block traffic (in this version)
- Protect against an attacker with code execution
- Replace a WAF, SAST, DAST, or dependency scanner

See docs/limitations.md for the full list.

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
