<?php

declare(strict_types=1);

use Illuminate\Events\Dispatcher;
use Illuminate\Support\Facades\Cache;
use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\ThreatMatch;
use Laronclad\Analysis\ThreatType;
use Laronclad\Events\ThreatDetected;
use Laronclad\Logging\Redactor;
use Laronclad\Logging\SafeLogger;
use Psr\Log\AbstractLogger;

/**
 * Collects every call to log() so tests can inspect them.
 */
final class SpyLogger extends AbstractLogger
{
    /** @var list<array{level: mixed, message: string, context: array<string, mixed>}> */
    public array $records = [];

    public function log($level, string|Stringable $message, array $context = []): void
    {
        $this->records[] = [
            'level' => $level,
            'message' => (string) $message,
            'context' => $context,
        ];
    }
}

function makeMatch(
    ThreatType $type = ThreatType::SqlInjection,
    ConfidenceLevel $confidence = ConfidenceLevel::Medium,
    string $rule = 'union_select',
): ThreatMatch {
    return new ThreatMatch(
        type: $type,
        confidence: $confidence,
        rule: $rule,
        description: 'test match',
    );
}

/**
 * Runs the callback and returns whatever it wrote to PHP's error log.
 */
function captureLoggerErrorLog(Closure $callback): string
{
    $file = (string) tempnam(sys_get_temp_dir(), 'laronclad');
    $previous = ini_set('error_log', $file);

    try {
        $callback();
    } finally {
        ini_set('error_log', (string) $previous);
    }

    $output = (string) file_get_contents($file);
    unlink($file);

    return $output;
}

it('writes a JSON line for a match', function () {
    $spy = new SpyLogger;
    $logger = new SafeLogger($spy, new Redactor, deduplicationWindow: 0);

    $logger->log(makeMatch(), ['ip' => '1.2.3.4']);

    expect($spy->records)->toHaveCount(1);

    $payload = json_decode($spy->records[0]['message'], true);

    expect($payload['type'])->toBe('sqli');
    expect($payload['rule'])->toBe('union_select');
    expect($payload['context']['ip'])->toBe('1.2.3.4');
});

it('redacts sensitive context keys', function () {
    $spy = new SpyLogger;
    $logger = new SafeLogger($spy, new Redactor, deduplicationWindow: 0);

    $logger->log(makeMatch(), ['password' => 'hunter2', 'route' => 'users.index']);

    $payload = json_decode($spy->records[0]['message'], true);

    expect($payload['context']['password'])->toBe('[REDACTED]');
    expect($payload['context']['route'])->toBe('users.index');
});

it('skips duplicate matches within the deduplication window', function () {
    $spy = new SpyLogger;
    $logger = new SafeLogger($spy, new Redactor, deduplicationWindow: 60);

    $logger->log(makeMatch(), ['ip' => '1.2.3.4']);
    $logger->log(makeMatch(), ['ip' => '1.2.3.4']);
    $logger->log(makeMatch(), ['ip' => '1.2.3.4']);

    expect($spy->records)->toHaveCount(1);
});

it('does not deduplicate when the source differs', function () {
    $spy = new SpyLogger;
    $logger = new SafeLogger($spy, new Redactor, deduplicationWindow: 60);

    $logger->log(makeMatch(), ['ip' => '1.2.3.4']);
    $logger->log(makeMatch(), ['ip' => '5.6.7.8']);

    expect($spy->records)->toHaveCount(2);
});

it('does not deduplicate when the window is zero', function () {
    $spy = new SpyLogger;
    $logger = new SafeLogger($spy, new Redactor, deduplicationWindow: 0);

    $logger->log(makeMatch(), ['ip' => '1.2.3.4']);
    $logger->log(makeMatch(), ['ip' => '1.2.3.4']);

    expect($spy->records)->toHaveCount(2);
});

it('never throws when the underlying logger throws', function () {
    $throwingLogger = new class extends AbstractLogger
    {
        public function log($level, string|Stringable $message, array $context = []): void
        {
            throw new RuntimeException('boom');
        }
    };

    $logger = new SafeLogger($throwingLogger, new Redactor, deduplicationWindow: 0);

    $output = captureLoggerErrorLog(function () use ($logger) {
        $logger->log(makeMatch());
    });

    // Only the exception class is reported, never its message.
    expect($output)->toContain('log write failed: RuntimeException');
    expect($output)->not->toContain('boom');
});

it('still logs when the cache store throws', function () {
    Cache::shouldReceive('has')->andThrow(new RuntimeException('redis-host-secret'));

    $spy = new SpyLogger;
    $logger = new SafeLogger($spy, new Redactor, deduplicationWindow: 60);

    $output = captureLoggerErrorLog(function () use ($logger) {
        $logger->log(makeMatch(), ['ip' => '1.2.3.4']);
    });

    expect($spy->records)->toHaveCount(1);
    expect($output)->toContain('dedup check failed: RuntimeException');
    expect($output)->not->toContain('redis-host-secret');
});

it('still dispatches the event when the cache store throws', function () {
    Cache::shouldReceive('has')->andThrow(new RuntimeException('cache down'));

    $events = new Dispatcher;

    $captured = [];
    $events->listen(
        ThreatDetected::class,
        function ($event) use (&$captured) {
            $captured[] = $event;
        },
    );

    $logger = new SafeLogger(
        logger: new SpyLogger,
        redactor: new Redactor,
        events: $events,
        deduplicationWindow: 60,
    );

    captureLoggerErrorLog(function () use ($logger) {
        $logger->log(makeMatch(), ['ip' => '1.2.3.4']);
    });

    expect($captured)->toHaveCount(1);
});

it('dispatches a ThreatDetected event after logging', function () {
    $spy = new SpyLogger;
    $events = new Dispatcher;

    $captured = [];
    $events->listen(
        ThreatDetected::class,
        function ($event) use (&$captured) {
            $captured[] = $event;
        },
    );

    $logger = new SafeLogger(
        logger: $spy,
        redactor: new Redactor,
        events: $events,
        deduplicationWindow: 0,
    );

    $logger->log(makeMatch(), ['ip' => '1.2.3.4']);

    expect($captured)->toHaveCount(1);
    expect($captured[0]->match->rule)->toBe('union_select');
    expect($captured[0]->context['ip'])->toBe('1.2.3.4');
});

it('does not dispatch an event for deduplicated findings', function () {
    $spy = new SpyLogger;
    $events = new Dispatcher;

    $captured = [];
    $events->listen(
        ThreatDetected::class,
        function ($event) use (&$captured) {
            $captured[] = $event;
        },
    );

    $logger = new SafeLogger(
        logger: $spy,
        redactor: new Redactor,
        events: $events,
        deduplicationWindow: 60,
    );

    $logger->log(makeMatch(), ['ip' => '1.2.3.4']);
    $logger->log(makeMatch(), ['ip' => '1.2.3.4']);

    expect($captured)->toHaveCount(1);
});
