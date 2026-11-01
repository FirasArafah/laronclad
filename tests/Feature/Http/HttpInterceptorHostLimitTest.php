<?php

declare(strict_types=1);

use Laronclad\Analysis\Rules\MetadataEndpointRule;
use Laronclad\Analysis\Rules\PrivateIpRule;
use Laronclad\Analysis\ThreatAnalyzer;
use Laronclad\Http\HttpInterceptor;
use Laronclad\Logging\Redactor;
use Laronclad\Logging\SafeLogger;
use Psr\Log\AbstractLogger;

final class HostLimitSpyLogger extends AbstractLogger
{
    /** @var list<string> */
    public array $messages = [];

    public function log($level, string|Stringable $message, array $context = []): void
    {
        $this->messages[] = (string) $message;
    }
}

function hostLimitInterceptor(HostLimitSpyLogger $spy): HttpInterceptor
{
    return new HttpInterceptor(
        analyzer: new ThreatAnalyzer([
            new PrivateIpRule,
            new MetadataEndpointRule,
        ]),
        logger: new SafeLogger($spy, new Redactor, deduplicationWindow: 0),
    );
}

it('flags an oversized host and logs only its length', function () {
    $spy = new HostLimitSpyLogger;
    $host = str_repeat('a', 300).'.example.com';

    hostLimitInterceptor($spy)->inspect('http://'.$host.'/');

    expect($spy->messages)->toHaveCount(1);

    $payload = json_decode($spy->messages[0], true);

    expect($payload['rule'])->toBe('oversized_input');
    expect($payload['type'])->toBe('ssrf');
    expect($payload['context']['host_length'])->toBe(strlen($host));
    expect($spy->messages[0])->not->toContain('aaaaaaaaaa');
});

it('does not flag a host at the length limit', function () {
    $spy = new HostLimitSpyLogger;

    hostLimitInterceptor($spy)->inspect('http://'.str_repeat('a', 255).'/');

    expect($spy->messages)->toBe([]);
});

it('still inspects the host of a normal URL', function () {
    $spy = new HostLimitSpyLogger;

    hostLimitInterceptor($spy)->inspect('http://192.168.1.1/admin');

    expect($spy->messages)->toHaveCount(1);
    expect(json_decode($spy->messages[0], true)['rule'])->toBe('private_ip');
});
