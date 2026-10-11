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
