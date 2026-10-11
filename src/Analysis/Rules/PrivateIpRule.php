<?php

declare(strict_types=1);

namespace Laronclad\Analysis\Rules;

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\RuleInterface;
use Laronclad\Analysis\ThreatMatch;
use Laronclad\Analysis\ThreatType;

/**
 * Detects outbound requests targeting private or reserved IP ranges.
 *
 * These ranges should not be reachable from a public-facing
 * application. An attempt to reach them is a strong indicator of
 * SSRF.
 *
 * Ranges covered:
 *   - IPv4: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8,
 *           169.254.0.0/16, 0.0.0.0/8
 *   - IPv6: ::1, fc00::/7, fe80::/10
 *
 * The rule operates on a URL host. If the host is not an IP literal,
 * resolution is out of scope for v0.1 (we do not perform DNS
 * lookups during monitoring).
 */
final class PrivateIpRule implements RuleInterface
{
    /**
     * Matches a host that is one of the private/reserved IPv4 ranges
     * or the loopback/unspecified IPv6 addresses.
     */
    private const PATTERN = '/^(?:'
        .'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        .'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
        .'|192\.168\.\d{1,3}\.\d{1,3}'
        .'|127\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        .'|169\.254\.\d{1,3}\.\d{1,3}'
        .'|0\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        .'|\[?::1\]?'
        .'|\[?f[cd][0-9a-f]{2}:.*\]?'
        .'|\[?fe[89ab][0-9a-f]:.*\]?'
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
            description: 'Request to private or reserved IP range',
        );
    }

    public function name(): string
    {
        return 'private_ip';
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
