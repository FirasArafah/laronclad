# Laronclad Scope

## Definition

**Laronclad is a lightweight, Laravel-native runtime security sensor that observes security-sensitive application behavior, detects suspicious execution patterns, and produces explainable security telemetry with minimal application overhead.**

It is designed to strengthen an existing Laravel application without becoming its firewall, security platform, or infrastructure dependency.

This document describes where Laronclad is going and what it will never become. For what the current release actually does, see [Status](#status).

## Status

**Version 0.1.1-alpha.** This is an early pre-release. The sections after this one describe the intended scope, not the current feature set.

| Area | Intended scope | Today |
|---|---|---|
| Database execution | Detect suspicious SQL structures and execution anomalies | Implemented for SQL structure (four rules). No anomaly or behavioral detection. |
| Outbound HTTP | Detect suspicious destinations | Implemented for Laravel's HTTP client, host only. DNS names are not resolved. |
| Process execution | Observe commands on supported execution paths | Manual only. `ProcessGuard` must be called by your code. Laravel has no public hook to observe it automatically. |
| Detection engine | Rules, normalization, behavioral features, optional small local ML | Rules and normalization only. Behavioral features and ML are not implemented. |
| Explainable findings | What, why, where, confidence, detector | Finding type, confidence, rule, description and request context (IP, method, route, user id when known). No separate "why" field and no call-site file or line yet. |
| Performance contract | Bounded, benchmarked, regression-tested | Work per input is bounded and tested. A benchmark script measures every detector and the end-to-end cost. No regression tracking in CI yet. |
| Telemetry | Stable, versioned event format | Consistent JSON lines and a `ThreatDetected` event. The format is not versioned and is not yet a stability promise. |
| Dashboard | Optional investigation interface | Not started. |
| Extension points | Stable API for custom rules | Rules implement an interface, but a documented, stable custom-rule API does not exist yet. |

Anything in this table marked as not implemented is a direction, not a promise.

## Core Scope

Laronclad focuses exclusively on security-sensitive behavior that occurs **inside the Laravel application runtime**.

Its supported monitoring surfaces are:

1. **Database Execution**
   - Observe database queries executed through Laravel.
   - Detect suspicious SQL structures, injection indicators, and execution anomalies.

2. **Outbound HTTP**
   - Observe destinations reached through Laravel's HTTP facilities.
   - Detect suspicious internal, reserved, metadata, obfuscated, and otherwise security-sensitive destinations.

3. **Process Execution**
   - Observe commands reaching supported Laravel/PHP process execution paths.
   - Detect dangerous command structures, shell execution patterns, and suspicious execution behavior.

These surfaces define the principal boundary of Laronclad. New surfaces should only be added when they represent a meaningful security-sensitive execution point within Laravel and can be monitored with low, bounded overhead.

## Detection Philosophy

Laronclad uses a **hybrid, explainable detection engine**.

Detection may combine:

- deterministic security rules;
- normalization and evasion-resistant parsing;
- lightweight behavioral features;
- small, optional statistical or machine-learning scoring models.

Machine learning must remain lightweight, local, optional, and explainable. Laronclad will not depend on large language models, deep-learning inference, external AI APIs, or cloud services for core detection.

Every finding should answer:

- **What happened?**
- **Why was it considered suspicious?**
- **Where did it occur?**
- **How confident is the detector?**
- **Which detector, rule, or signal contributed to the finding?**

## Performance Contract

Security monitoring must not become a significant application workload.

Laronclad therefore treats runtime overhead as a product constraint rather than an optimization added later.

Detection paths should:

- remain bounded;
- avoid external network calls;
- avoid mandatory synchronous persistence;
- avoid expensive inference;
- minimize allocations and repeated normalization;
- be independently benchmarkable.

Every major detector should have measurable performance characteristics and regression coverage.

## Operational Model

Laronclad is **detection-first and non-invasive**.

Its primary responsibility is to observe, detect, explain, and emit.

It fails open when its own monitoring encounters an internal failure rather than breaking the host application.

**Laronclad does not block requests, queries, or commands, and no blocking is planned.** Findings are emitted as log lines and events. Applications, security teams, or external systems decide how to react to them.

## Security Telemetry

Findings use a stable, structured, privacy-conscious security event format suitable for:

- application logs;
- queues;
- SIEM ingestion;
- custom listeners;
- the optional Laronclad Dashboard.

Sensitive application data should not be required for useful detection or investigation.

## Optional Dashboard

The Laronclad Dashboard is an observability and investigation interface for Laronclad findings, not a separate security platform.

Its scope is limited to:

- findings and their explanations;
- severity and confidence;
- affected Laravel routes or runtime surfaces;
- detection trends;
- detector and ruleset information;
- runtime performance statistics;
- false-positive review and detector feedback.

The core package must remain fully functional without the Dashboard.

## Explicitly Out of Scope

Laronclad will **not** attempt to become:

- a Web Application Firewall;
- a malware scanner;
- a vulnerability scanner;
- a SAST or DAST platform;
- a dependency scanner;
- an authentication or authorization system;
- an IP reputation or geolocation service;
- an anti-DDoS system;
- a bot-management platform;
- a CSP or security-header manager;
- an ACL system;
- a SIEM;
- an EDR;
- a general-purpose audit logging framework;
- a cloud security service;
- a general Laravel monitoring/APM product;
- a request blocker or automated response system.

Existing specialized tools should continue performing those jobs.

Laronclad should complement them rather than replace them.

## Definition of Done

Laronclad reaches its intended mature scope when it can reliably:

1. Observe its defined Laravel runtime surfaces.
2. Detect meaningful suspicious behavior across those surfaces.
3. Resist documented encoding and evasion techniques.
4. Produce structured and explainable findings.
5. Protect sensitive telemetry through safe collection and redaction.
6. Operate with predictable and measured overhead.
7. Fail without disrupting the host application.
8. Integrate cleanly with external logging and security systems.
9. Provide optional investigation and visualization through its Dashboard.
10. Maintain stable extension points for new detection rules without expanding the core product beyond its defined runtime-security role.

After this point, development should prioritize **security fixes, bypass resistance, false-positive reduction, performance, Laravel compatibility, detection quality, and small rule improvements** rather than continuous feature expansion.

## Product Principle

**Install it. Keep building Laravel. Laronclad quietly watches the security-sensitive parts of the runtime and tells you when something deserves attention.**

Laronclad should make a Laravel application more observable from a security perspective without making the application meaningfully heavier, more complex, or dependent on Laronclad itself.
