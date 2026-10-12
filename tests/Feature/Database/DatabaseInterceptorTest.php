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

function dbInterceptor(DbSpyLogger $spy): DatabaseInterceptor
{
    return new DatabaseInterceptor(
        analyzer: new ThreatAnalyzer([new UnionSelectRule]),
        logger: new SafeLogger($spy, new Redactor, deduplicationWindow: 0),
    );
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

    expect($spy->messages)->toHaveCount(1);
});

it('truncates very long queries before analysis', function () {
    $spy = new DbSpyLogger;

    $interceptor = new DatabaseInterceptor(
        analyzer: new ThreatAnalyzer([new UnionSelectRule]),
        logger: new SafeLogger($spy, new Redactor, deduplicationWindow: 0),
        maxInputLength: 100,
    );

    // The first 100 chars are safe, so the rule must not match
    // even though the full input contains a UNION SELECT later.
    $query = str_repeat('a', 100).' UNION SELECT 1';
    $interceptor->inspect($query);

    expect($spy->messages)->toBe([]);
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

    $interceptor->inspect('SELECT 1 UNION SELECT 2');

    expect(true)->toBeTrue();
});
