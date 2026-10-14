<?php

declare(strict_types=1);

namespace Laronclad\Database;

use Illuminate\Support\Facades\DB;
use Laronclad\Analysis\ThreatAnalyzer;
use Laronclad\Analysis\ThreatType;
use Laronclad\Logging\SafeLogger;
use Throwable;

/**
 * Observes SQL queries before they reach the database.
 *
 * Laravel exposes DB::beforeExecuting, which fires with the raw
 * query string before any driver runs it. We inspect the query
 * against the SQLi rules and hand matches to the logger.
 *
 * v0.1 does not block. It only logs.
 *
 * Fail-open: any failure inside inspection is swallowed. A
 * monitoring tool must never break the application's own queries.
 */
final readonly class DatabaseInterceptor
{
    public function __construct(
        private ThreatAnalyzer $analyzer,
        private SafeLogger $logger,
        private int $maxInputLength = 8192,
    ) {}

    /**
     * Attach the interceptor to Laravel's database layer.
     *
     * Called once from the service provider.
     */
    public function register(): void
    {
        DB::beforeExecuting(function (string $query): void {
            $this->inspect($query);
        });
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
            $truncated = strlen($query) > $this->maxInputLength
                ? substr($query, 0, $this->maxInputLength)
                : $query;

            $matches = $this->analyzer->analyze($truncated, ThreatType::SqlInjection);

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
