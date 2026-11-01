<?php

declare(strict_types=1);

use Laronclad\Analysis\Rules\UnionSelectRule;
use Laronclad\Analysis\ThreatAnalyzer;
use Laronclad\Database\DatabaseInterceptor;
use Laronclad\Logging\Redactor;
use Laronclad\Logging\SafeLogger;
use Psr\Log\AbstractLogger;

final class DbSpyLogger extends AbstractLogger
{
    /** @var list<string> */
    public array $messages = [];

    public function log($level, string|Stringable $message, array $context = []): void
    {
        $this->messages[] = (string) $message;
    }
}

function dbInterceptor(
    DbSpyLogger $spy,
    int $maxInputLength = DatabaseInterceptor::DEFAULT_MAX_INPUT_LENGTH,
): DatabaseInterceptor {
    return new DatabaseInterceptor(
        analyzer: new ThreatAnalyzer([new UnionSelectRule]),
        logger: new SafeLogger($spy, new Redactor, deduplicationWindow: 0),
        maxInputLength: $maxInputLength,
    );
}

/**
 * @return list<string>
 */
function loggedDbRules(DbSpyLogger $spy): array
{
    return array_map(static function (string $message): string {
        $payload = json_decode($message, true);

        return is_array($payload) && is_string($payload['rule'] ?? null) ? $payload['rule'] : '';
    }, $spy->messages);
}

/**
 * Runs the callback and returns whatever it wrote to PHP's error log.
 */
function captureDbErrorLog(Closure $callback): string
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

it('does not log a safe query', function () {
    $spy = new DbSpyLogger;
    dbInterceptor($spy)->inspect('SELECT id FROM users WHERE id = ?');

    expect($spy->messages)->toBe([]);
});

it('logs a union select query', function () {
    $spy = new DbSpyLogger;
    dbInterceptor($spy)->inspect(
        "SELECT id FROM users WHERE name = 'x' UNION SELECT password FROM admins"
    );

    expect(loggedDbRules($spy))->toBe(['union_select']);
});

it('still finds a payload hidden behind padding', function () {
    $spy = new DbSpyLogger;

    dbInterceptor($spy, maxInputLength: 100)->inspect(
        str_repeat('a', 100).' UNION SELECT 1'
    );

    expect(loggedDbRules($spy))->toBe(['union_select', 'oversized_input']);
});

it('flags a payload hidden in the middle of oversized input', function () {
    $spy = new DbSpyLogger;

    dbInterceptor($spy, maxInputLength: 100)->inspect(
        str_repeat('a', 200).' UNION SELECT 1 '.str_repeat('b', 200)
    );

    expect(loggedDbRules($spy))->toBe(['oversized_input']);
});

it('analyzes a query of exactly the limit as a whole', function () {
    $spy = new DbSpyLogger;

    dbInterceptor($spy, maxInputLength: 100)->inspect(
        str_pad('SELECT 1 UNION SELECT 2', 100)
    );

    expect(loggedDbRules($spy))->toBe(['union_select']);
});

it('falls back to the default limit when the configured one is not positive', function () {
    $safe = new DbSpyLogger;
    dbInterceptor($safe, maxInputLength: 0)->inspect('SELECT id FROM users');

    expect($safe->messages)->toBe([]);

    $unsafe = new DbSpyLogger;
    dbInterceptor($unsafe, maxInputLength: 0)->inspect('SELECT 1 UNION SELECT 2');

    expect(loggedDbRules($unsafe))->toBe(['union_select']);
});

it('does not throw when the logger throws', function () {
    $throwing = new class extends AbstractLogger
    {
        public function log($level, string|Stringable $message, array $context = []): void
        {
            throw new RuntimeException('boom');
        }
    };

    $interceptor = new DatabaseInterceptor(
        analyzer: new ThreatAnalyzer([new UnionSelectRule]),
        logger: new SafeLogger($throwing, new Redactor, deduplicationWindow: 0),
    );

    $output = captureDbErrorLog(function () use ($interceptor) {
        $interceptor->inspect('SELECT 1 UNION SELECT 2');
    });

    expect($output)->toContain('log write failed: RuntimeException');
    expect($output)->not->toContain('boom');
});
