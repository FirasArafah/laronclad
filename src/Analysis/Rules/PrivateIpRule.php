<?php

declare(strict_types=1);

namespace Laronclad\Analysis\Rules;

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\RuleInterface;
use Laronclad\Analysis\ThreatMatch;
use Laronclad\Analysis\ThreatType;
use Laronclad\Support\HostAddress;

/**
 * Detects outbound requests targeting private, loopback or reserved
 * addresses.
 *
 * These addresses should not be reachable from a public-facing
 * application. An attempt to reach them is a strong indicator of
 * SSRF.
 *
 * The host is parsed, not pattern-matched, so every spelling an HTTP
 * client accepts is covered: dotted, decimal, octal and hex IPv4
 * (127.1, 2130706433, 0x7f000001, 0177.0.0.1), IPv6 literals with
 * brackets or a zone id, IPv4 carried inside IPv6
 * (::ffff:127.0.0.1), percent-encoding and trailing dots. The names
 * localhost and *.localhost are covered too.
 *
 * Ranges covered:
 *   - IPv4: 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
 *           169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24,
 *           192.168.0.0/16, 198.18.0.0/15, 240.0.0.0/4
 *   - IPv6: ::, ::1, fc00::/7, fe80::/10, fec0::/10
 *
 * Other names are not resolved (we do not perform DNS lookups during
 * monitoring), so a DNS name that points at a private address is not
 * detected.
 */
final class PrivateIpRule implements RuleInterface
{
    public function matches(string $input): ?ThreatMatch
    {
        if (! $this->isPrivate(HostAddress::normalize($input))) {
            return null;
        }

        return new ThreatMatch(
            type: $this->type(),
            confidence: $this->confidence(),
            rule: $this->name(),
            description: 'Request to a private, loopback or reserved address',
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

    private function isPrivate(string $host): bool
    {
        if ($host === '') {
            return false;
        }

        if (HostAddress::isLocalName($host)) {
            return true;
        }

        $ipv4 = HostAddress::ipv4($host);

        if ($ipv4 !== null && HostAddress::isReservedIpv4($ipv4)) {
            return true;
        }

        $ipv6 = HostAddress::ipv6($host);

        return $ipv6 !== null && HostAddress::isReservedIpv6($ipv6);
    }
}
