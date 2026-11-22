# Benchmarks

How much Laronclad costs an application, measured two ways.

    composer bench
    php benchmarks/run.php --json

- **Detectors**: the time to analyze one input with the default rules,
  with the same size limits the hooks use. No logging.
- **End to end**: real Laravel queries (SQLite in memory) and HTTP client
  calls (faked, nothing leaves the machine), each timed in a fresh PHP
  process with Laronclad off and then on. The difference is what your
  application pays per query or request.

Every number is the median of 7 rounds, in time per operation. The script
fails if the "on" run did not actually log the attack query, or if the
"off" run logged anything, so it cannot quietly measure nothing.

## Results

Laronclad 0.1.1-alpha, PHP 8.2.12 (Windows, ZTS, OPcache and JIT off),
Laravel 12.70, Intel Core i7-12700H. Your numbers will differ. Compare
runs on one machine, not across machines. Repeated runs here differed by
up to about 3 µs per row.

### End to end

| Operation | Off | On | Overhead |
|---|--:|--:|--:|
| Raw query: select by id | 10.2 µs | 16.1 µs | +5.9 µs |
| Query builder: where + first | 33.9 µs | 43.8 µs | +9.8 µs |
| Query builder: insert | 21.0 µs | 31.4 µs | +10.4 µs |
| HTTP client: GET (faked) | 89.5 µs | 104.9 µs | +15.4 µs |
| Attack query, logged every time | 13.2 µs | 53.5 µs | +40.3 µs |

**About 6 to 10 µs per query, and about 15 µs per outbound request.** The
queries here run against SQLite in memory, so they cost almost nothing on
their own. That makes the percentage look large (30% to 60%), but it is the
worst case. A query to a database server over the network usually takes
from a few hundred microseconds to milliseconds, so the same 10 µs is a
much smaller share there. Measure your own app if the share matters to you.

The attack row is a worst case on purpose. Deduplication is off, so every
query is analyzed, logged as JSON to a file and fires `ThreatDetected`. With
deduplication on (the default, 60 seconds), a repeated finding skips the
write.

Where the time goes inside the database hook, for a short query:

| Part | Time |
|---|--:|
| Rules (the detection itself) | ~2.4 µs |
| Whitelist check | ~2.2 µs |
| The rest of the hook | ~2 µs |

### Compared with 0.1.0-alpha

0.1.0-alpha rebuilt the whitelist from config on every query and outbound
request, even when it was empty. That check alone took about 8 µs. Since
0.1.1-alpha the whitelist is rebuilt only when its config changes.

| Operation | 0.1.0-alpha | 0.1.1-alpha |
|---|--:|--:|
| Raw query: select by id | +17.6 µs | +5.9 µs |
| Query builder: where + first | +21.5 µs | +9.8 µs |
| Query builder: insert | +21.8 µs | +10.4 µs |
| HTTP client: GET (faked) | +26.5 µs | +15.4 µs |

### Detectors

| Input | Size | Findings | Median |
|---|--:|--:|--:|
| SQL: primary key lookup | 44 B | 0 | 2.4 µs |
| SQL: ORM query with join, 50 bindings | 382 B | 0 | 3.1 µs |
| SQL: batch insert, 500 rows | 6.9 KB | 0 | 16.7 µs |
| SQL: UNION injection | 83 B | 2 | 3.5 µs |
| SQL: time-based injection | 45 B | 1 | 2.6 µs |
| SQL: 64 KB literal | 64 KB | 0 | 123 µs |
| SQL: 1 MB literal (at the limit) | 1 MB | 0 | 1.9 ms |
| SQL: 8 MB literal (over the limit) | 8 MB | 1 | 3.0 ms |
| SQL: 1 MB of quotes and comment markers | 1 MB | 1 | 2.9 ms |
| Host: public domain | 14 B | 0 | 3.8 µs |
| Host: public IPv4 | 13 B | 0 | 10.3 µs |
| Host: private IPv4 | 8 B | 1 | 8.6 µs |
| Host: metadata, decimal form | 10 B | 2 | 6.3 µs |
| Host: metadata, IPv4-in-IPv6 | 24 B | 2 | 8.1 µs |
| Host: 253-character name | 253 B | 0 | 2.9 µs |
| Command: git status | 22 B | 0 | 3.3 µs |
| Command: curl piped to sh | 46 B | 1 | 3.8 µs |
| Command: 8 KB of arguments (at the limit) | 8 KB | 0 | 154 µs |
| Command: 1 MB (over the limit) | 1 MB | 1 | 160 µs |

What this shows:

- **Normal input takes a few microseconds.** Cost grows linearly with size,
  at about 2 µs per KB of SQL.
- **Size cannot be used to slow it down.** Input over the limit (1 MB per
  query, 8 KB per command) costs the same as input at the limit, because
  only the first and last halves are analyzed. That input is always
  reported as `oversized_input`.
- **Input built to defeat the patterns stays bounded.** A full megabyte of
  quotes and comment markers takes 3 ms, close to a plain 1 MB literal.

## Not measured yet

- Boot time and memory added by the service provider.
- Octane or other long-running servers.
- Linux, OPcache and JIT. Numbers there are expected to be lower.
- Regression tracking in CI.
