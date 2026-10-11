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
