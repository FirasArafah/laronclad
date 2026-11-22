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

function processGuard(
    ProcessSpyLogger $spy,
    int $maxInputLength = ProcessGuard::DEFAULT_MAX_INPUT_LENGTH,
): ProcessGuard {
    return new ProcessGuard(
        analyzer: new ThreatAnalyzer([new DangerousCommandRule]),
        logger: new SafeLogger($spy, new Redactor, deduplicationWindow: 0),
        maxInputLength: $maxInputLength,
    );
}

/**
 * @return list<string>
 */
function loggedProcessRules(ProcessSpyLogger $spy): array
{
    return array_map(static function (string $message): string {
        $payload = json_decode($message, true);

        return is_array($payload) && is_string($payload['rule'] ?? null) ? $payload['rule'] : '';
    }, $spy->messages);
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

it('skips array parts that cannot be read as text, without warnings', function () {
    $spy = new ProcessSpyLogger;
    $warnings = [];

    set_error_handler(function (int $level, string $message) use (&$warnings): bool {
        $warnings[] = $message;

        return true;
    });

    try {
        processGuard($spy)->inspect(['rm', ['nested'], new stdClass, '-rf', '/']);
    } finally {
        restore_error_handler();
    }

    expect($warnings)->toBe([]);
    expect(loggedProcessRules($spy))->toBe(['dangerous_command']);
});

it('reads numbers and stringable objects in array commands', function () {
    $spy = new ProcessSpyLogger;

    $target = new class implements Stringable
    {
        public function __toString(): string
        {
            return '/';
        }
    };

    processGuard($spy)->inspect(['chmod', 777, 'file']);
    processGuard($spy)->inspect(['rm', '-rf', $target]);

    expect(loggedProcessRules($spy))->toBe(['dangerous_command', 'dangerous_command']);
});

it('fails open and reports only the exception class', function () {
    $part = new class implements Stringable
    {
        public function __toString(): string
        {
            throw new RuntimeException('secret-detail');
        }
    };

    $file = (string) tempnam(sys_get_temp_dir(), 'laronclad');
    $previous = ini_set('error_log', $file);

    try {
        processGuard(new ProcessSpyLogger)->inspect(['rm', $part]);
    } finally {
        ini_set('error_log', (string) $previous);
    }

    $output = (string) file_get_contents($file);
    unlink($file);

    expect($output)->toContain('process inspection failed: RuntimeException');
    expect($output)->not->toContain('secret-detail');
});

it('inspects both ends of an oversized command and flags it', function () {
    $spy = new ProcessSpyLogger;

    processGuard($spy, maxInputLength: 100)->inspect(
        'rm -rf / '.str_repeat('a', 300)
    );

    expect(loggedProcessRules($spy))->toBe(['dangerous_command', 'oversized_input']);
});

it('flags an oversized command whose middle is not inspected', function () {
    $spy = new ProcessSpyLogger;

    processGuard($spy, maxInputLength: 100)->inspect(
        'ls '.str_repeat('a', 200).' rm -rf / '.str_repeat('b', 200)
    );

    expect(loggedProcessRules($spy))->toBe(['oversized_input']);
});
