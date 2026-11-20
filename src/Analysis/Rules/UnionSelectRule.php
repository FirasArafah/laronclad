<?php

declare(strict_types=1);

namespace Laronclad\Analysis\Rules;

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\RuleInterface;
use Laronclad\Analysis\ThreatMatch;
use Laronclad\Analysis\ThreatType;
use Laronclad\Support\SqlText;

/**
 * Detects UNION SELECT patterns in a query.
 *
 * A UNION SELECT is a classic way to append an attacker-controlled
 * query to a legitimate one. It is not always malicious: some
 * applications build UNION queries legitimately. That is why the
 * confidence is Medium, not High.
 *
 * Covered spellings: any whitespace between the words, ALL or
 * DISTINCT, opening parentheses (UNION(SELECT, UNION ALL (SELECT),
 * and comments in between, including MySQL versioned comments.
 * Comments are handled by SqlText, which also reads the raw text,
 * so a comment marker inside a string cannot hide a payload.
 *
 * The pattern has no nested quantifiers and every repetition is
 * possessive, so it cannot backtrack catastrophically.
 *
 * Word boundaries prevent matching substrings like "reunion" or
 * "selection". Text inside a comment can still match, because the
 * raw text is checked as well.
 */
final class UnionSelectRule implements RuleInterface
{
    private const PATTERN = '/(?<![a-z_])union(?![a-z0-9_$])\s*+(?:(?:all|distinct)(?![a-z0-9_$])\s*+)?(?:\(\s*+)*+select(?![a-z0-9_$])/i';

    public function matches(string $input): ?ThreatMatch
    {
        if (SqlText::matches(self::PATTERN, $input) !== true) {
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
