<?php

declare(strict_types=1);

use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\RuleInterface;
use Laronclad\Analysis\Rules\MetadataEndpointRule;
use Laronclad\Analysis\Rules\PrivateIpRule;
use Laronclad\Analysis\ThreatAnalyzer;
use Laronclad\Analysis\ThreatMatch;
use Laronclad\Analysis\ThreatType;
use Laronclad\Events\ThreatDetected;
use Laronclad\Http\HttpInterceptor;
use Laronclad\Logging\Redactor;
use Laronclad\Logging\SafeLogger;
use Psr\Log\AbstractLogger;

final class HttpSpyLogger extends AbstractLogger
{
    /** @var list<string> */
    public array $messages = [];

    public function log($level, string|Stringable $message, array $context = []): void
    {
        $this->messages[] = (string) $message;
    }
}

function httpInterceptor(HttpSpyLogger $spy): HttpInterceptor
{
    return new HttpInterceptor(
        analyzer: new ThreatAnalyzer([
            new PrivateIpRule,
            new MetadataEndpointRule,
        ]),
        logger: new SafeLogger($spy, new Redactor, deduplicationWindow: 0),
    );
}

it('does not log a public URL', function () {
    $spy = new HttpSpyLogger;
    httpInterceptor($spy)->inspect('https://api.example.com/users');

    expect($spy->messages)->toBe([]);
});

it('logs a request to a private IP', function () {
    $spy = new HttpSpyLogger;
    httpInterceptor($spy)->inspect('http://192.168.1.1/admin');

    expect($spy->messages)->toHaveCount(1);
});

it('logs a request to the metadata endpoint', function () {
    $spy = new HttpSpyLogger;
    httpInterceptor($spy)->inspect('http://169.254.169.254/latest/meta-data/');

    // 169.254.169.254 matches both PrivateIpRule (link-local)
    // and MetadataEndpointRule (cloud metadata). Two matches is
    // the intended behavior: each rule reports independently.
    expect($spy->messages)->toHaveCount(2);
});

it('handles a URL without a host', function () {
    $spy = new HttpSpyLogger;
    httpInterceptor($spy)->inspect('not-a-url');

    expect($spy->messages)->toBe([]);
});

it('handles an empty string', function () {
    $spy = new HttpSpyLogger;
    httpInterceptor($spy)->inspect('');

    expect($spy->messages)->toBe([]);
});

it('inspects real outbound requests through the registered middleware', function () {
    // Dedup state must not leak between runs.
    Cache::flush();

    $captured = [];
    Event::listen(ThreatDetected::class, function ($event) use (&$captured) {
        $captured[] = $event;
    });

    Http::fake();

    $response = Http::get('http://192.168.1.1/admin');

    expect($response->successful())->toBeTrue();
    expect($captured)->toHaveCount(1);
    expect($captured[0]->match->rule)->toBe('private_ip');
});

it('passes requests through the middleware unchanged', function () {
    Cache::flush();

    $captured = [];
    Event::listen(ThreatDetected::class, function ($event) use (&$captured) {
        $captured[] = $event;
    });

    Http::fake();

    $response = Http::get('https://api.example.com/users');

    expect($response->successful())->toBeTrue();
    expect($captured)->toBe([]);

    Http::assertSent(fn (Request $request) => $request->url() === 'https://api.example.com/users');
});

it('keeps inspecting when a rule throws and leaks no details', function () {
    $logFile = (string) tempnam(sys_get_temp_dir(), 'laronclad');
    $previous = ini_set('error_log', $logFile);

    $throwingRule = new class implements RuleInterface
    {
        public function matches(string $input): ?ThreatMatch
        {
            throw new RuntimeException('sensitive-detail');
        }

        public function name(): string
        {
            return 'boom';
        }

        public function type(): ThreatType
        {
            return ThreatType::Ssrf;
        }

        public function confidence(): ConfidenceLevel
        {
            return ConfidenceLevel::High;
        }
    };

    $spy = new HttpSpyLogger;

    $interceptor = new HttpInterceptor(
        analyzer: new ThreatAnalyzer([$throwingRule, new PrivateIpRule]),
        logger: new SafeLogger($spy, new Redactor, deduplicationWindow: 0),
    );

    $interceptor->inspect('http://192.168.1.1/admin');

    ini_set('error_log', (string) $previous);
    $output = (string) file_get_contents($logFile);
    unlink($logFile);

    // The healthy rule after the failing one still ran.
    expect($spy->messages)->toHaveCount(1);
    // Only class names are reported, never the exception message.
    expect($output)->toContain('rule failed');
    expect($output)->toContain('threw RuntimeException');
    expect($output)->not->toContain('sensitive-detail');
});
