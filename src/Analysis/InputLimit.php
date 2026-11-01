<?php

declare(strict_types=1);

namespace Laronclad\Analysis;

/**
 * Keeps analysis bounded without letting input size be a way around it.
 *
 * Input up to the limit is analyzed whole. Longer input has its first
 * and last halves analyzed, and always produces a low-confidence
 * "oversized_input" finding, because the middle was not inspected.
 * Skipping the rest silently would let padding in front of a payload
 * hide it.
 */
final class InputLimit
{
    public const RULE = 'oversized_input';

    private const MIN_LIMIT = 2;

    /**
     * @return list<ThreatMatch>
     */
    public static function analyze(
        ThreatAnalyzer $analyzer,
        string $input,
        int $limit,
        ThreatType $type,
    ): array {
        $limit = max(self::MIN_LIMIT, $limit);

        if (strlen($input) <= $limit) {
            return $analyzer->analyze($input, $type);
        }

        $half = intdiv($limit, 2);

        $matches = [];
        $seen = [];

        foreach ([substr($input, 0, $half), substr($input, -$half)] as $slice) {
            foreach ($analyzer->analyze($slice, $type) as $match) {
                if (isset($seen[$match->rule])) {
                    continue;
                }

                $seen[$match->rule] = true;
                $matches[] = $match;
            }
        }

        $matches[] = self::oversizedFinding($type);

        return $matches;
    }

    /**
     * The finding reported when input was too large to inspect fully.
     */
    public static function oversizedFinding(ThreatType $type): ThreatMatch
    {
        return new ThreatMatch(
            type: $type,
            confidence: ConfidenceLevel::Low,
            rule: self::RULE,
            description: 'Input exceeded the analysis size limit and was only partly inspected',
        );
    }
}
