<?php

declare(strict_types=1);

namespace Laronclad\Database;

use Illuminate\Database\Connection;
use Illuminate\Database\Events\ConnectionEstablished;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Laronclad\Analysis\InputLimit;
use Laronclad\Analysis\ThreatAnalyzer;
use Laronclad\Analysis\ThreatType;
use Laronclad\Logging\SafeLogger;
use Throwable;
use WeakMap;

/**
 * Observes SQL queries before they reach the database.
 *
 * Laravel runs the callbacks added with Connection::beforeExecuting
 * with the raw query string before any driver runs it. Callbacks
 * belong to one connection object, so the hook is attached to every
 * connection: the ones that exist at boot, and each one Laravel
 * establishes later (other named connections, a connection created
 * again after DB::purge()). We inspect the query against the SQLi
 * rules and hand matches to the logger.
 *
 * Queries up to the size limit are analyzed whole. Longer queries
 * have their first and last halves analyzed and always produce an
 * "oversized_input" finding, so padding cannot hide a payload.
 *
 * v0.1 does not block. It only logs.
 *
 * Fail-open: any failure inside inspection or hooking is swallowed.
 * A monitoring tool must never break the application's own queries.
 */
final readonly class DatabaseInterceptor
{
    public const DEFAULT_MAX_INPUT_LENGTH = 1_048_576;

    /**
     * Connections that already carry the hook. Weak keys, so a
     * discarded connection is not kept alive by this map.
     *
     * @var WeakMap<Connection, true>
     */
    private WeakMap $hooked;

    public function __construct(
        private ThreatAnalyzer $analyzer,
        private SafeLogger $logger,
        private int $maxInputLength = self::DEFAULT_MAX_INPUT_LENGTH,
    ) {
        $this->hooked = new WeakMap;
    }

    /**
     * Attach the interceptor to Laravel's database layer.
     *
     * Called once from the service provider. No connection is
     * resolved here: only connections that already exist are hooked
     * now, and the rest are hooked as Laravel establishes them.
     */
    public function register(): void
    {
        Event::listen(ConnectionEstablished::class, function (ConnectionEstablished $event): void {
            $this->attach($event->connection);
        });

        foreach (DB::getConnections() as $connection) {
            $this->attach($connection);
        }
    }

    /**
     * Hook one connection. Safe to call more than once for the same
     * connection: Laravel announces an existing connection again on
     * reconnect, and it must not be inspected twice.
     *
     * Never throws. Failures are reported to PHP's error log with
     * the exception class only.
     */
    public function attach(Connection $connection): void
    {
        try {
            if (isset($this->hooked[$connection])) {
                return;
            }

            $this->hooked->offsetSet($connection, true);

            $connection->beforeExecuting(function (string $query): void {
                $this->inspect($query);
            });
        } catch (Throwable $e) {
            error_log('[laronclad] database hook failed: '.$e::class);
        }
    }

    /**
     * Inspect a single query. Public so tests can call it directly.
     *
     * Never throws. Failures are reported to PHP's error log with
     * the exception class only, so no SQL or input leaks into logs.
     */
    public function inspect(string $query): void
    {
        try {
            // A zero or negative limit is a misconfiguration. Falling
            // back keeps SQL monitoring from being switched off by it.
            $limit = $this->maxInputLength > 0
                ? $this->maxInputLength
                : self::DEFAULT_MAX_INPUT_LENGTH;

            $matches = InputLimit::analyze(
                $this->analyzer,
                $query,
                $limit,
                ThreatType::SqlInjection,
            );

            foreach ($matches as $match) {
                $this->logger->log($match, [
                    'query_length' => strlen($query),
                ]);
            }
        } catch (Throwable $e) {
            error_log('[laronclad] database inspection failed: '.$e::class);
        }
    }
}
