<?php

declare(strict_types=1);

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\Rules\MetadataEndpointRule;
use Laronclad\Analysis\ThreatType;

function metadataRule(): MetadataEndpointRule
{
    return new MetadataEndpointRule;
}

it('exposes its identity', function () {
    expect(metadataRule()->name())->toBe('metadata_endpoint');
    expect(metadataRule()->type())->toBe(ThreatType::Ssrf);
    expect(metadataRule()->confidence())->toBe(ConfidenceLevel::High);
});

it('matches the AWS and Azure metadata IP', function () {
    expect(metadataRule()->matches('169.254.169.254'))->not->toBeNull();
});

it('matches the GCP metadata hostname', function () {
    expect(metadataRule()->matches('metadata.google.internal'))->not->toBeNull();
});

it('matches the GCP short metadata hostname', function () {
    expect(metadataRule()->matches('metadata.goog'))->not->toBeNull();
});

it('matches the Alibaba Cloud metadata IP', function () {
    expect(metadataRule()->matches('100.100.100.200'))->not->toBeNull();
});

it('does not match a regular hostname', function () {
    expect(metadataRule()->matches('example.com'))->toBeNull();
});

it('does not match a public IP', function () {
    expect(metadataRule()->matches('8.8.8.8'))->toBeNull();
});

it('matches every spelling of the metadata IP', function (string $host) {
    expect(metadataRule()->matches($host))->not->toBeNull();
})->with([
    '2852039166',
    '0xa9fea9fe',
    '0251.0376.0251.0376',
    '169.254.43518',
    '::ffff:169.254.169.254',
    '::ffff:a9fe:a9fe',
    '%31%36%39.254.169.254',
]);

it('matches the Azure WireServer IP', function () {
    expect(metadataRule()->matches('168.63.129.16'))->not->toBeNull();
});

it('matches the AWS IPv6 metadata address', function (string $host) {
    expect(metadataRule()->matches($host))->not->toBeNull();
})->with(['fd00:ec2::254', '[fd00:ec2::254]', 'FD00:EC2:0:0:0:0:0:254']);

it('ignores case and a trailing dot on the hostnames', function (string $host) {
    expect(metadataRule()->matches($host))->not->toBeNull();
})->with(['METADATA.GOOGLE.INTERNAL', 'metadata.google.internal.', 'Metadata.Goog']);

it('does not match hosts that only contain a metadata name', function (string $host) {
    expect(metadataRule()->matches($host))->toBeNull();
})->with([
    'metadata.google.internal.evil.com',
    'evilmetadata.goog',
    'x169.254.169.254',
    '169.254.169.254.evil.com',
    '169.254.169.253',
    'fd00:ec2::255',
]);

it('does not match an empty host', function () {
    expect(metadataRule()->matches(''))->toBeNull();
});
