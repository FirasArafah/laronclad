<?php

declare(strict_types=1);

namespace Laronclad\Analysis\Rules;

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\RuleInterface;
use Laronclad\Analysis\ThreatMatch;
use Laronclad\Analysis\ThreatType;
use Laronclad\Support\HostAddress;

/**
 * Detects requests to cloud provider metadata endpoints.
 *
 * These endpoints expose instance credentials, tokens, and other
 * sensitive data. They are never the intended target of legitimate
 * application code.
 *
 * Addresses are compared as numbers, so decimal, octal and hex
 * spellings, IPv4 carried inside IPv6 and percent-encoding all reach
 * the same verdict as the plain form.
 *
 * Endpoints covered:
 *   - AWS / OpenStack / Azure: 169.254.169.254
 *   - AWS over IPv6:           fd00:ec2::254
 *   - Azure WireServer:        168.63.129.16
 *   - GCP:                     metadata.google.internal,
 *                              metadata.goog
 *   - Alibaba Cloud:           100.100.100.200
 */
final class MetadataEndpointRule implements RuleInterface
{
    private const HOSTNAMES = [
        'metadata.google.internal',
        'metadata.goog',
    ];

    private const IPV4 = [
        '169.254.169.254',
        '100.100.100.200',
        '168.63.129.16',
    ];

    private const IPV6 = [
        'fd00:ec2::254',
    ];

    public function matches(string $input): ?ThreatMatch
    {
        if (! $this->isMetadataEndpoint(HostAddress::normalize($input))) {
            return null;
        }

        return new ThreatMatch(
            type: $this->type(),
            confidence: $this->confidence(),
            rule: $this->name(),
            description: 'Request to cloud metadata endpoint',
        );
    }

    public function name(): string
    {
        return 'metadata_endpoint';
    }

    public function type(): ThreatType
    {
        return ThreatType::Ssrf;
    }

    public function confidence(): ConfidenceLevel
    {
        return ConfidenceLevel::High;
    }

    private function isMetadataEndpoint(string $host): bool
    {
        if ($host === '') {
            return false;
        }

        if (in_array($host, self::HOSTNAMES, true)) {
            return true;
        }

        $ipv4 = HostAddress::ipv4($host);

        if ($ipv4 !== null && in_array(long2ip($ipv4), self::IPV4, true)) {
            return true;
        }

        $ipv6 = HostAddress::ipv6($host);

        if ($ipv6 === null) {
            return false;
        }

        foreach (self::IPV6 as $address) {
            if (inet_pton($address) === $ipv6) {
                return true;
            }
        }

        return false;
    }
}
