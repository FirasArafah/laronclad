<?php

declare(strict_types=1);

namespace Laronclad\Analysis\Rules;

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\RuleInterface;
use Laronclad\Analysis\ThreatMatch;
use Laronclad\Analysis\ThreatType;

/**
 * Detects requests to cloud provider metadata endpoints.
 *
 * These endpoints expose instance credentials, tokens, and other
 * sensitive data. They are never the intended target of legitimate
 * application code.
 *
 * Endpoints covered:
 *   - AWS / OpenStack / Azure: 169.254.169.254
 *   - GCP:                     metadata.google.internal,
 *                              metadata.goog
 *   - Alibaba Cloud:           100.100.100.200
 */
final class MetadataEndpointRule implements RuleInterface
{
    private const PATTERN = '/^(?:'
        .'169\.254\.169\.254'
        .'|metadata\.google\.internal'
        .'|metadata\.goog'
        .'|100\.100\.100\.200'
        .')$/i';

    public function matches(string $input): ?ThreatMatch
    {
        if (preg_match(self::PATTERN, $input) !== 1) {
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
}
