<?php

declare(strict_types=1);

namespace Laronclad\Support;

/**
 * Matches SQL patterns the way a database would read the text.
 *
 * Databases skip comments between tokens, and MySQL and MariaDB even
 * run the text inside versioned comments, so a pattern applied to the
 * raw query misses a UNION, a comment and then a SELECT. Comments
 * cannot simply be deleted either: a quote can put a comment marker
 * inside a string, and deleting from there would hide a real payload
 * that follows it.
 *
 * So a pattern is tried against the raw text, then against the text
 * without block comments, then against the text without any comments.
 * A match in any of them counts. Nothing the raw text matches can be
 * lost this way.
 */
final class SqlText
{
    /**
     * Whether the pattern matches the SQL in any of those readings.
     *
     * Returns null when pattern matching itself failed. The PCRE error
     * is then still set, which is how ThreatAnalyzer notices that an
     * input defeated the matcher.
     */
    public static function matches(string $pattern, string $sql): ?bool
    {
        $candidates = [$sql];

        $withoutBlocks = self::withoutBlockComments($sql);

        if ($withoutBlocks !== $sql) {
            $candidates[] = $withoutBlocks;
        }

        $withoutComments = preg_replace('/(?:--|#)[^\n]*+/', ' ', $withoutBlocks);

        if ($withoutComments === null) {
            return null;
        }

        if (! in_array($withoutComments, $candidates, true)) {
            $candidates[] = $withoutComments;
        }

        foreach ($candidates as $candidate) {
            $result = preg_match($pattern, $candidate);

            if ($result === false) {
                return null;
            }

            if ($result === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * Replaces each block comment with a space. The body of a MySQL
     * or MariaDB versioned comment is kept, because the database
     * runs it as SQL.
     *
     * Runs in one pass. A comment that never closes is left as it
     * is, so a long run of opening markers cannot make this scan the
     * same text again and again.
     */
    public static function withoutBlockComments(string $sql): string
    {
        $output = '';
        $position = 0;

        while (true) {
            $open = strpos($sql, '/*', $position);

            if ($open === false) {
                return $output.substr($sql, $position);
            }

            $bodyStart = $open + 2;
            $close = strpos($sql, '*/', $bodyStart);

            if ($close === false) {
                return $output.substr($sql, $position);
            }

            $output .= substr($sql, $position, $open - $position);

            $marker = self::versionedMarkerLength($sql, $bodyStart);

            if ($marker === null) {
                $output .= ' ';
            } else {
                $output .= ' '.substr($sql, $bodyStart + $marker, $close - $bodyStart - $marker).' ';
            }

            $position = $close + 2;
        }
    }

    /**
     * Length of a versioned-comment marker (!, !50000, M!100100) at
     * the start of a comment body, or null for an ordinary comment.
     */
    private static function versionedMarkerLength(string $sql, int $bodyStart): ?int
    {
        $first = $sql[$bodyStart] ?? '';

        if ($first === '!') {
            return 1 + strspn($sql, '0123456789', $bodyStart + 1);
        }

        if ($first === 'M' && ($sql[$bodyStart + 1] ?? '') === '!') {
            return 2 + strspn($sql, '0123456789', $bodyStart + 2);
        }

        return null;
    }
}
