# Security Policy

## Reporting a vulnerability

Please do not open a public issue for security problems.

Use GitHub's private security advisories:

https://github.com/FirasArafah/laronclad/security/advisories/new

An email contact will be added before the first stable release. If
GitHub advisories are not an option for you, open a minimal issue
asking for a private channel. Do not include any details in that
issue.

## What to include

- A short description of the issue
- Steps to reproduce, or a small proof of concept
- Affected version(s)
- Impact, as you understand it

Please don't include real user data or production credentials.

## What to expect

- I'll acknowledge your report within a few days.
- I'll confirm the issue and give a rough timeline.

## Supported versions

Laronclad is pre-alpha. There is no stable release yet.

Once 1.0 ships, this section will list supported versions and their
support windows.

## Supported Laravel versions

Laronclad follows Laravel's own security support window. Versions
that no longer receive security fixes from the Laravel team are not
supported.

| Laravel         | Status                                      |
|-----------------|---------------------------------------------|
| 13.x            | Supported (security fixes until March 2028) |
| 12.x            | Supported (security fixes until February 2027) |
| 11.x and older  | Not supported (EOL)                         |

## Scope

In scope:

- The package code under src/
- The default configuration
- The published documentation, where it could lead to insecure use

Out of scope:

- Vulnerabilities in Laravel or PHP themselves
- Vulnerabilities in dependencies (report upstream)
- Issues caused by modifying the package in unsupported ways
- Denial of service on your own test environment
