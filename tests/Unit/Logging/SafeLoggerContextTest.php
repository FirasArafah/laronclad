<?php

declare(strict_types=1);

use Illuminate\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\ThreatMatch;
use Laronclad\Analysis\ThreatType;
use Laronclad\Events\ThreatDetected;
use Laronclad\Logging\Redactor;
use Laronclad\Logging\SafeLogger;
use Psr\Log\AbstractLogger;

final class ContextSpyLogger extends AbstractLogger
{
    /** @var list<string> */
    public array $messages = [];

    public function log($level, string|Stringable $message, array $context = []): void
    {
        $this->messages[] = (string) $message;
    }
}

function contextMatch(): ThreatMatch
{
    return new ThreatMatch(
        type: ThreatType::SqlInjection,
        confidence: ConfidenceLevel::Medium,
        rule: 'union_select',
        description: 'test match',
    );
}

function useRequestFrom(string $ip): void
{
    app()->instance('request', Request::create('/x', 'POST', [], [], [], [
        'REMOTE_ADDR' => $ip,
    ]));
}

it('adds request context to the log line', function () {
    useRequestFrom('203.0.113.5');

    $spy = new ContextSpyLogger;
    $logger = new SafeLogger($spy, new Redactor, deduplicationWindow: 0);

    $logger->log(contextMatch(), ['query_length' => 12]);

    $payload = json_decode($spy->messages[0], true);

    expect($payload['context']['ip'])->toBe('203.0.113.5');
    expect($payload['context']['method'])->toBe('POST');
    expect($payload['context']['query_length'])->toBe(12);
});

it('lets values from the caller win over collected ones', function () {
    useRequestFrom('203.0.113.5');

    $spy = new ContextSpyLogger;
    $logger = new SafeLogger($spy, new Redactor, deduplicationWindow: 0);

    $logger->log(contextMatch(), ['ip' => '1.2.3.4']);

    $payload = json_decode($spy->messages[0], true);

    expect($payload['context']['ip'])->toBe('1.2.3.4');
});

it('deduplicates per real source instead of collapsing all sources', function () {
    Cache::flush();

    $spy = new ContextSpyLogger;
    $logger = new SafeLogger($spy, new Redactor, deduplicationWindow: 60);

    useRequestFrom('203.0.113.5');
    $logger->log(contextMatch());
    $logger->log(contextMatch());

    expect($spy->messages)->toHaveCount(1);

    useRequestFrom('198.51.100.9');
    $logger->log(contextMatch());

    expect($spy->messages)->toHaveCount(2);
});

it('does not add request context when collection is turned off', function () {
    useRequestFrom('203.0.113.5');

    $spy = new ContextSpyLogger;
    $logger = new SafeLogger(
        $spy,
        new Redactor,
        deduplicationWindow: 0,
        requestContext: null,
    );

    $logger->log(contextMatch(), ['query_length' => 12]);

    $payload = json_decode($spy->messages[0], true);

    expect($payload['context'])->toBe(['query_length' => 12]);
});

it('dispatches the redacted context to listeners', function () {
    $events = new Dispatcher;

    $captured = [];
    $events->listen(
        ThreatDetected::class,
        function ($event) use (&$captured) {
            $captured[] = $event;
        },
    );

    $logger = new SafeLogger(
        logger: new ContextSpyLogger,
        redactor: new Redactor,
        events: $events,
        deduplicationWindow: 0,
        requestContext: null,
    );

    $logger->log(contextMatch(), [
        'password' => 'hunter2',
        'api_key' => 'k-123',
        'route' => 'users.index',
    ]);

    expect($captured)->toHaveCount(1);
    expect($captured[0]->context['password'])->toBe('[REDACTED]');
    expect($captured[0]->context['api_key'])->toBe('[REDACTED]');
    expect($captured[0]->context['route'])->toBe('users.index');
});

it('dispatches request context to listeners', function () {
    useRequestFrom('203.0.113.5');

    $events = new Dispatcher;

    $captured = [];
    $events->listen(
        ThreatDetected::class,
        function ($event) use (&$captured) {
            $captured[] = $event;
        },
    );

    $logger = new SafeLogger(
        logger: new ContextSpyLogger,
        redactor: new Redactor,
        events: $events,
        deduplicationWindow: 0,
    );

    $logger->log(contextMatch());

    expect($captured[0]->context['ip'])->toBe('203.0.113.5');
});
