<?php

declare(strict_types=1);

namespace Laronclad\Logging;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\Cache;
use Laronclad\Analysis\ThreatMatch;
use Laronclad\Events\ThreatDetected;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Writes threat matches as JSON lines and dispatches an event.
 *
 * All findings go through here, so this class is the only place
 * that knows the log format. Failures are swallowed: a monitoring
 * tool must never take down the application.
 *
 * Failure reports go to PHP's error log with the exception class
 * only. Exception messages can carry connection strings or SQL
 * bindings, so they are never copied into logs.
 */
final readonly class SafeLogger
{
    public function __construct(
        private LoggerInterface $logger,
        private Redactor $redactor,
        private ?Dispatcher $events = null,
        private int $deduplicationWindow = 60,
    ) {}

    /**
     * @param  array<array-key, mixed>  $context
     */
    public function log(ThreatMatch $match, array $context = []): void
    {
        try {
            if ($this->shouldSkip($match, $context)) {
                return;
            }

            $this->write($match, $context);
        } catch (Throwable $e) {
            error_log('[laronclad] log write failed: '.$e::class);
        }
    }

    /**
     * Whether this finding is a duplicate inside the window.
     *
     * Fail-open: if the cache store is unavailable, the finding is
     * treated as new and still gets logged. Losing deduplication is
     * better than losing detection or breaking the application.
     *
     * @param  array<array-key, mixed>  $context
     */
    private function shouldSkip(ThreatMatch $match, array $context): bool
    {
        if ($this->deduplicationWindow <= 0) {
            return false;
        }

        try {
            $key = $this->deduplicationKey($match, $context);

            if (Cache::has($key)) {
                return true;
            }

            Cache::put($key, true, $this->deduplicationWindow);
        } catch (Throwable $e) {
            error_log('[laronclad] dedup check failed: '.$e::class);
        }

        return false;
    }

    /**
     * @param  array<array-key, mixed>  $context
     */
    private function deduplicationKey(ThreatMatch $match, array $context): string
    {
        $source = $context['ip'] ?? $context['user_id'] ?? 'unknown';

        return 'laronclad:dedup:'.sha1($match->type->value.'|'.$match->rule.'|'.$source);
    }

    /**
     * @param  array<array-key, mixed>  $context
     */
    private function write(ThreatMatch $match, array $context): void
    {
        $payload = [
            'time' => gmdate('Y-m-d\TH:i:s\Z'),
            'type' => $match->type->value,
            'confidence' => $match->confidence->value,
            'rule' => $match->rule,
            'description' => $match->description,
            'context' => $this->redactor->redact($context),
        ];

        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        if ($json === false) {
            error_log('[laronclad] failed to encode log payload');

            return;
        }

        $this->logger->info($json);

        // Only dispatch after a successful write. Deduplicated
        // findings never reach this point.
        $this->events?->dispatch(new ThreatDetected($match, $context));
    }
}
