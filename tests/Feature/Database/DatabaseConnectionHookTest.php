<?php

declare(strict_types=1);

use Illuminate\Database\Connection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Laronclad\Analysis\Rules\UnionSelectRule;
use Laronclad\Analysis\ThreatAnalyzer;
use Laronclad\Database\DatabaseInterceptor;
use Laronclad\Events\ThreatDetected;
use Laronclad\Logging\Redactor;
use Laronclad\Logging\SafeLogger;
use Psr\Log\AbstractLogger;

final class HookSpyLogger extends AbstractLogger
{
    /** @var list<string> */
    public array $messages = [];

    public function log($level, string|Stringable $message, array $context = []): void
    {
        $this->messages[] = (string) $message;
    }
}

/**
 * Runs the callback and returns whatever it wrote to PHP's error log.
 */
function captureHookErrorLog(Closure $callback): string
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

/**
 * Starts collecting the rule of every ThreatDetected event.
 *
 * @return ArrayObject<int, string>
 */
function collectDetectedRules(): ArrayObject
{
    // Deduplication state must not hide a finding from this test.
    Cache::flush();

    /** @var ArrayObject<int, string> $rules */
    $rules = new ArrayObject;

    Event::listen(ThreatDetected::class, function (ThreatDetected $event) use ($rules): void {
        $rules->append($event->match->rule);
    });

    return $rules;
}

function addSecondConnection(): void
{
    config()->set('database.connections.second', [
        'driver' => 'sqlite',
        'database' => ':memory:',
        'prefix' => '',
    ]);
}

it('inspects queries on the default connection', function () {
    $rules = collectDetectedRules();

    DB::select('select 1 union select 2');

    expect($rules->getArrayCopy())->toBe(['union_select']);
})->skip(! extension_loaded('pdo_sqlite'), 'pdo_sqlite is required');

it('inspects queries on a connection created after boot', function () {
    addSecondConnection();
    $rules = collectDetectedRules();

    DB::connection('second')->select('select 1 union select 2');

    expect($rules->getArrayCopy())->toBe(['union_select']);
})->skip(! extension_loaded('pdo_sqlite'), 'pdo_sqlite is required');

it('keeps inspecting after a connection is purged', function () {
    $rules = collectDetectedRules();

    DB::select('select 1');
    DB::purge();
    DB::select('select 1 union select 2');

    expect($rules->getArrayCopy())->toBe(['union_select']);
})->skip(! extension_loaded('pdo_sqlite'), 'pdo_sqlite is required');

it('hooks a connection only once', function () {
    $spy = new HookSpyLogger;

    $interceptor = new DatabaseInterceptor(
        analyzer: new ThreatAnalyzer([new UnionSelectRule]),
        logger: new SafeLogger($spy, new Redactor, deduplicationWindow: 0, requestContext: null),
    );

    $connection = DB::connection();

    $interceptor->attach($connection);
    $interceptor->attach($connection);

    $connection->select('select 1 union select 2');

    expect($spy->messages)->toHaveCount(1);
})->skip(! extension_loaded('pdo_sqlite'), 'pdo_sqlite is required');

it('does not throw when a connection refuses the hook', function () {
    $connection = new class extends Connection
    {
        public function __construct() {}

        public function beforeExecuting(Closure $callback)
        {
            throw new RuntimeException('secret-detail');
        }
    };

    $interceptor = new DatabaseInterceptor(
        analyzer: new ThreatAnalyzer([new UnionSelectRule]),
        logger: new SafeLogger(new HookSpyLogger, new Redactor, deduplicationWindow: 0),
    );

    $output = captureHookErrorLog(function () use ($interceptor, $connection) {
        $interceptor->attach($connection);
    });

    expect($output)->toContain('database hook failed: RuntimeException');
    expect($output)->not->toContain('secret-detail');
});
