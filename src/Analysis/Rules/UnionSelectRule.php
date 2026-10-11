<?php

declare(strict_types=1);

namespace Laronclad\Analysis\Rules;

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\RuleInterface;
use Laronclad\Analysis\ThreatMatch;
use Laronclad\Analysis\ThreatType;

/**
 * Detects UNION SELECT patterns in a query.
 *
 * A UNION SELECT is a classic way to append an attacker-controlled
 * query to a legitimate one. It is not always malicious: some
 * applications build UNION queries legitimately. That is why the
 * confidence is Medium, not High.
 *
 * The regex is written to avoid catastrophic backtracking. It has
 * no nested quantifiers and no optional groups that could overlap.
 * Input is length-limited before matching by the caller.
 */
final class UnionSelectRule implements RuleInterface
{
    /**
     * Matches "union" followed by optional whitespace, optional
     * "all", optional whitespace, then "select".
     *
     * Word boundaries prevent matching substrings like "reunion"
     * or "selection".
     */
    private const PATTERN = '/\bunion\b\s+(?:all\s+)?\bselect\b/i';

    public function matches(string $input): ?ThreatMatch
    {
        if (preg_match(self::PATTERN, $input) !== 1) {
            return null;
        }

        return new ThreatMatch(
            type: $this->type(),
            confidence: $this->confidence(),
            rule: $this->name(),
            description: 'UNION SELECT pattern found in query',
        );
    }

    public function name(): string
    {
        return 'union_select';
    }

    public function type(): ThreatType
    {
        return ThreatType::SqlInjection;
    }

    public function confidence(): ConfidenceLevel
    {
        return ConfidenceLevel::Medium;
    }
}
