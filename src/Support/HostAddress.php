<?php

declare(strict_types=1);

namespace Laronclad\Support;

/**
 * Understands the many ways a URL host can name an address.
 *
 * HTTP clients accept far more than dotted-quad IPv4. The same
 * loopback address can be written 127.1, 2130706433, 0x7f000001,
 * 0177.0.0.1 or ::ffff:127.0.0.1, and a host can be percent-encoded.
 * Matching spellings with patterns always leaves one out, so hosts
 * are parsed into numbers and compared as numbers instead.
 *
 * IPv4 parsing follows inet_aton(), which is what curl accepts:
 * one to four parts, each decimal, octal (leading 0) or hex (0x),
 * where the last part fills the remaining bytes.
 *
 * Names are never resolved. A DNS name that points at a private
 * address is outside what this class can see.
 */
final class HostAddress
{
    /**
     * Private, loopback and reserved IPv4 ranges. Documentation
     * ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are
     * deliberately left out: they are not a way into a network.
     *
     * @var list<string>
     */
    private const RESERVED_IPV4 = [
        '0.0.0.0/8',
        '10.0.0.0/8',
        '100.64.0.0/10',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '172.16.0.0/12',
        '192.0.0.0/24',
        '192.168.0.0/16',
        '198.18.0.0/15',
        '240.0.0.0/4',
    ];

    /**
     * Turns a URL host into the form the rest of this class expects:
     * percent-decoded once (curl does the same), lowercase, without
     * IPv6 brackets or zone id, and without trailing dots.
     */
    public static function normalize(string $host): string
    {
        $host = strtolower(trim(rawurldecode($host)));

        if (str_starts_with($host, '[')) {
            $end = strpos($host, ']');

            if ($end !== false) {
                $host = substr($host, 1, $end - 1);
            }
        }

        $zone = strpos($host, '%');

        if ($zone !== false) {
            $host = substr($host, 0, $zone);
        }

        return rtrim($host, '.');
    }

    /**
     * Names that always mean the machine itself. Expects a
     * normalized host.
     */
    public static function isLocalName(string $host): bool
    {
        return $host === 'localhost'
            || str_ends_with($host, '.localhost')
            || in_array($host, ['localhost.localdomain', 'ip6-localhost', 'ip6-loopback'], true);
    }

    /**
     * The IPv4 address a normalized host stands for, as an unsigned
     * 32-bit integer, or null. Looks at IPv4 spellings first, then at
     * IPv6 literals that carry an IPv4 address (mapped, compatible,
     * NAT64 and 6to4).
     */
    public static function ipv4(string $host): ?int
    {
        $address = self::parseIpv4($host);

        if ($address !== null) {
            return $address;
        }

        $bytes = self::ipv6($host);

        return $bytes === null ? null : self::embeddedIpv4($bytes);
    }

    /**
     * The 16 bytes of an IPv6 literal in a normalized host, or null.
     */
    public static function ipv6(string $host): ?string
    {
        if (! str_contains($host, ':')) {
            return null;
        }

        // Validate first: inet_pton() raises a warning on bad input.
        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
            return null;
        }

        $bytes = inet_pton($host);

        return is_string($bytes) && strlen($bytes) === 16 ? $bytes : null;
    }

    public static function isReservedIpv4(int $address): bool
    {
        foreach (self::RESERVED_IPV4 as $cidr) {
            [$network, $bits] = explode('/', $cidr);

            $mask = (-1 << (32 - (int) $bits)) & 0xFFFFFFFF;

            if (($address & $mask) === (int) ip2long($network)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Unspecified, loopback, unique-local, link-local and site-local
     * IPv6 addresses, given as 16 bytes.
     */
    public static function isReservedIpv6(string $bytes): bool
    {
        if ($bytes === str_repeat("\0", 16) || $bytes === str_repeat("\0", 15)."\x01") {
            return true;
        }

        $first = ord($bytes[0]);
        $second = ord($bytes[1]);

        // fc00::/7 unique local
        if (($first & 0xFE) === 0xFC) {
            return true;
        }

        // fe80::/10 link-local and fec0::/10 site-local
        return $first === 0xFE && (($second & 0xC0) === 0x80 || ($second & 0xC0) === 0xC0);
    }

    private static function parseIpv4(string $host): ?int
    {
        $parts = explode('.', $host);
        $count = count($parts);

        if ($count > 4) {
            return null;
        }

        $numbers = [];

        foreach ($parts as $part) {
            $number = self::parseIpv4Part($part);

            if ($number === null) {
                return null;
            }

            $numbers[] = $number;
        }

        // Every part but the last is one byte. The last part fills
        // the bytes that remain.
        $last = array_pop($numbers);

        if ($last >= 256 ** (5 - $count)) {
            return null;
        }

        $address = $last;

        foreach ($numbers as $index => $number) {
            if ($number > 255) {
                return null;
            }

            $address |= $number << (8 * (3 - $index));
        }

        return $address;
    }

    private static function parseIpv4Part(string $part): ?int
    {
        if (preg_match('/^0x([0-9a-f]+)$/Di', $part, $hex) === 1) {
            $digits = ltrim($hex[1], '0');

            if ($digits === '') {
                return 0;
            }

            return strlen($digits) > 8 ? null : (int) hexdec($digits);
        }

        if (preg_match('/^0[0-7]*$/D', $part) === 1) {
            $digits = ltrim($part, '0');

            if ($digits === '') {
                return 0;
            }

            return strlen($digits) > 11 ? null : (int) octdec($digits);
        }

        if (preg_match('/^[1-9][0-9]*$/D', $part) === 1) {
            return strlen($part) > 10 ? null : (int) $part;
        }

        return null;
    }

    private static function embeddedIpv4(string $bytes): ?int
    {
        $prefix = substr($bytes, 0, 12);

        $carriesIpv4InTail = [
            str_repeat("\0", 10)."\xff\xff",       // ::ffff:a.b.c.d (IPv4-mapped)
            str_repeat("\0", 12),                  // ::a.b.c.d (IPv4-compatible)
            "\x00\x64\xff\x9b".str_repeat("\0", 8), // 64:ff9b::/96 (NAT64)
        ];

        if (in_array($prefix, $carriesIpv4InTail, true)) {
            return self::toInt(substr($bytes, 12, 4));
        }

        // 2002::/16 (6to4) carries it right after the prefix.
        if (substr($bytes, 0, 2) === "\x20\x02") {
            return self::toInt(substr($bytes, 2, 4));
        }

        return null;
    }

    private static function toInt(string $fourBytes): ?int
    {
        $parts = unpack('N', $fourBytes);

        return is_array($parts) ? (int) $parts[1] : null;
    }
}
