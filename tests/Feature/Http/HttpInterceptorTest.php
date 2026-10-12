<?php

declare(strict_types=1);

use Laronclad\Analysis\Rules\MetadataEndpointRule;
use Laronclad\Analysis\Rules\PrivateIpRule;
use Laronclad\Analysis\ThreatAnalyzer;
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
