<?php

declare(strict_types=1);

use Laronclad\Support\HostAddress;

it('normalizes case, brackets, zone ids, trailing dots and percent encoding', function (string $input, string $expected) {
    expect(HostAddress::normalize($input))->toBe($expected);
})->with([
    ['EXAMPLE.com', 'example.com'],
    ['example.com.', 'example.com'],
    ['[::1]', '::1'],
    ['[FE80::1%25eth0]', 'fe80::1'],
    ['fe80::1%eth0', 'fe80::1'],
    ['%31%32%37.0.0.1', '127.0.0.1'],
    ['127%2e0.0.1', '127.0.0.1'],
]);

it('reads every spelling of an IPv4 address', function (string $host, int $expected) {
    expect(HostAddress::ipv4($host))->toBe($expected);
})->with([
    ['127.0.0.1', 2130706433],
    ['127.1', 2130706433],
    ['127.0.1', 2130706433],
    ['2130706433', 2130706433],
    ['0x7f000001', 2130706433],
    ['0x7f.0.0.1', 2130706433],
    ['0177.0.0.1', 2130706433],
    ['017700000001', 2130706433],
    ['8.8.8.8', 134744072],
    ['255.255.255.255', 4294967295],
    ['4294967295', 4294967295],
    ['0', 0],
]);

it('does not read something that is not an IPv4 address', function (string $host) {
    expect(HostAddress::ipv4($host))->toBeNull();
})->with([
    'example.com',
    '',
    '256.1.1.1',
    '1.2.3.256',
    '1.2.3.4.5',
    '08.0.0.1',
    '0x',
    '0xzz',
    '1..2',
    '4294967296',
    'a.b.c.d',
    '127.0.0.1.example.com',
    '2001:db8::1',
]);

it('finds an IPv4 address hidden inside an IPv6 literal', function (string $host) {
    expect(HostAddress::ipv4($host))->toBe(2130706433);
})->with([
    '::ffff:127.0.0.1',
    '::ffff:7f00:1',
    '::7f00:1',
    '64:ff9b::7f00:1',
    '2002:7f00:1::',
]);

it('knows which IPv4 addresses are private or reserved', function (string $host, bool $reserved) {
    $address = HostAddress::ipv4($host);

    expect($address)->not->toBeNull();
    expect(HostAddress::isReservedIpv4((int) $address))->toBe($reserved);
})->with([
    ['0.0.0.0', true],
    ['10.1.2.3', true],
    ['100.64.0.1', true],
    ['100.127.255.255', true],
    ['127.0.0.1', true],
    ['169.254.169.254', true],
    ['172.16.0.1', true],
    ['172.31.255.255', true],
    ['192.0.0.1', true],
    ['192.168.0.1', true],
    ['198.18.0.1', true],
    ['198.19.255.255', true],
    ['240.0.0.1', true],
    ['255.255.255.255', true],
    ['8.8.8.8', false],
    ['1.1.1.1', false],
    ['100.63.255.255', false],
    ['100.128.0.1', false],
    ['172.15.255.255', false],
    ['172.32.0.1', false],
    ['192.0.2.1', false],
    ['198.17.255.255', false],
    ['198.20.0.1', false],
    ['203.0.113.5', false],
    ['223.255.255.255', false],
]);

it('knows which IPv6 addresses are private or reserved', function (string $host, bool $reserved) {
    $bytes = HostAddress::ipv6($host);

    expect($bytes)->not->toBeNull();
    expect(HostAddress::isReservedIpv6((string) $bytes))->toBe($reserved);
})->with([
    ['::', true],
    ['::1', true],
    ['fc00::1', true],
    ['fd12:3456::1', true],
    ['fe80::1', true],
    ['febf::1', true],
    ['fec0::1', true],
    ['2001:db8::1', false],
    ['2606:4700::1111', false],
    ['2001:4860:4860::8888', false],
    ['fe00::1', false],
    ['fbff::1', false],
]);

it('does not read an IPv6 literal from something else', function (string $host) {
    expect(HostAddress::ipv6($host))->toBeNull();
})->with(['example.com', '127.0.0.1', '', 'a:b', ':::']);

it('recognizes names that always mean this machine', function (string $host, bool $expected) {
    expect(HostAddress::isLocalName($host))->toBe($expected);
})->with([
    ['localhost', true],
    ['app.localhost', true],
    ['ip6-localhost', true],
    ['ip6-loopback', true],
    ['localhost.localdomain', true],
    ['notlocalhost', false],
    ['localhost.example.com', false],
    ['example.com', false],
]);
