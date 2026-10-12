<?php

declare(strict_types=1);

use Laronclad\Analysis\Rules\DangerousCommandRule;
use Laronclad\Analysis\ThreatAnalyzer;
use Laronclad\Logging\Redactor;
use Laronclad\Logging\SafeLogger;
use Laronclad\Process\ProcessGuard;
use Psr\Log\AbstractLogger;

final class ProcessSpyLogger extends AbstractLogger
{
    /** @var list<string> */
    public array $messages = [];

    public function log($level, string|Stringable $message, array $context = []): void
    {
        $this->messages[] = (string) $message;
    }
}

function processGuard(ProcessSpyLogger $spy): ProcessGuard
{
    return new ProcessGuard(
        analyzer: new ThreatAnalyzer([new DangerousCommandRule]),
        logger: new SafeLogger($spy, new Redactor, deduplicationWindow: 0),
    );
}

it('does not log a safe command', function () {
    $spy = new ProcessSpyLogger;
    processGuard($spy)->inspect('ls -la');

    expect($spy->messages)->toBe([]);
});

it('logs a dangerous string command', function () {
    $spy = new ProcessSpyLogger;
    processGuard($spy)->inspect('rm -rf /');

    expect($spy->messages)->toHaveCount(1);
});

it('logs a dangerous array command', function () {
    $spy = new ProcessSpyLogger;
    processGuard($spy)->inspect(['rm', '-rf', '/']);

    expect($spy->messages)->toHaveCount(1);
});

it('handles null command', function () {
    $spy = new ProcessSpyLogger;
    processGuard($spy)->inspect(null);

    expect($spy->messages)->toBe([]);
});

it('handles an empty string', function () {
    $spy = new ProcessSpyLogger;
    processGuard($spy)->inspect('');

    expect($spy->messages)->toBe([]);
});
