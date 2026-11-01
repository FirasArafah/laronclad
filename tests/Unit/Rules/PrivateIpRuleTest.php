<?php

declare(strict_types=1);

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\Rules\PrivateIpRule;
use Laronclad\Analysis\ThreatType;

function privateIpRule(): PrivateIpRule
{
    return new PrivateIpRule;
}

it('exposes its identity', function () {
    expect(privateIpRule()->name())->toBe('private_ip');
    expect(privateIpRule()->type())->toBe(ThreatType::Ssrf);
    expect(privateIpRule()->confidence())->toBe(ConfidenceLevel::High);
});

it('matches 10.x.x.x addresses', function () {
    expect(privateIpRule()->matches('10.0.0.1'))->not->toBeNull();
    expect(privateIpRule()->matches('10.255.255.255'))->not->toBeNull();
});

it('matches 172.16.x.x through 172.31.x.x addresses', function () {
    expect(privateIpRule()->matches('172.16.0.1'))->not->toBeNull();
    expect(privateIpRule()->matches('172.31.255.255'))->not->toBeNull();
});

it('matches 192.168.x.x addresses', function () {
    expect(privateIpRule()->matches('192.168.1.1'))->not->toBeNull();
});

it('matches loopback addresses', function () {
    expect(privateIpRule()->matches('127.0.0.1'))->not->toBeNull();
});

it('matches link-local addresses', function () {
    expect(privateIpRule()->matches('169.254.1.1'))->not->toBeNull();
});

it('matches IPv6 loopback', function () {
    expect(privateIpRule()->matches('::1'))->not->toBeNull();
});

it('does not match public IPv4 addresses', function () {
    expect(privateIpRule()->matches('8.8.8.8'))->toBeNull();
    expect(privateIpRule()->matches('1.1.1.1'))->toBeNull();
});

it('does not match 172.15 or 172.32', function () {
    expect(privateIpRule()->matches('172.15.0.1'))->toBeNull();
    expect(privateIpRule()->matches('172.32.0.1'))->toBeNull();
});

it('does not match a hostname', function () {
    expect(privateIpRule()->matches('example.com'))->toBeNull();
});

it('matches every spelling of IPv4 loopback', function (string $host) {
    expect(privateIpRule()->matches($host))->not->toBeNull();
})->with([
    '127.1',
    '127.0.1',
    '2130706433',
    '0x7f000001',
    '0x7f.0.0.1',
    '0177.0.0.1',
    '017700000001',
]);

it('matches the names that mean this machine', function (string $host) {
    expect(privateIpRule()->matches($host))->not->toBeNull();
})->with([
    'localhost',
    'LOCALHOST',
    'localhost.',
    'app.localhost',
    'ip6-localhost',
    'localhost.localdomain',
]);

it('does not match names that only contain localhost', function (string $host) {
    expect(privateIpRule()->matches($host))->toBeNull();
})->with(['notlocalhost', 'localhost.example.com', 'mylocalhost.com']);

it('matches the unspecified address', function (string $host) {
    expect(privateIpRule()->matches($host))->not->toBeNull();
})->with(['0.0.0.0', '0', '::', '[::]']);

it('matches the carrier-grade NAT range and nothing next to it', function () {
    expect(privateIpRule()->matches('100.64.0.1'))->not->toBeNull();
    expect(privateIpRule()->matches('100.127.255.255'))->not->toBeNull();
    expect(privateIpRule()->matches('100.63.255.255'))->toBeNull();
    expect(privateIpRule()->matches('100.128.0.1'))->toBeNull();
});

it('matches IPv6 unique-local and link-local addresses', function (string $host) {
    expect(privateIpRule()->matches($host))->not->toBeNull();
})->with([
    'fc00::1',
    'fd12:3456:789a::1',
    'fe80::1',
    '[fe80::1%25eth0]',
    'fe80::1%eth0',
]);

it('matches an IPv4 address hidden inside IPv6', function (string $host) {
    expect(privateIpRule()->matches($host))->not->toBeNull();
})->with([
    '::ffff:127.0.0.1',
    '::ffff:7f00:1',
    '[::ffff:10.0.0.1]',
    '64:ff9b::a00:1',
    '2002:c0a8:101::',
]);

it('ignores case, a trailing dot and percent encoding', function (string $host) {
    expect(privateIpRule()->matches($host))->not->toBeNull();
})->with(['127.0.0.1.', '%31%32%37.0.0.1', '127%2e0%2e0%2e1']);

it('does not match public or documentation addresses', function (string $host) {
    expect(privateIpRule()->matches($host))->toBeNull();
})->with([
    '203.0.113.5',
    '192.0.2.1',
    '2001:4860:4860::8888',
    '2606:4700:4700::1111',
    '2001:db8::1',
    '::ffff:8.8.8.8',
]);

it('does not match an empty host', function () {
    expect(privateIpRule()->matches(''))->toBeNull();
});
