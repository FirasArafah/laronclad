<?php

declare(strict_types=1);

namespace Laronclad\Analysis\Rules;

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\RuleInterface;
use Laronclad\Analysis\ThreatMatch;
use Laronclad\Analysis\ThreatType;

/**
 * Detects stacked queries: a semicolon followed by another statement.
 *
 * Legitimate applications rarely stack statements in a single call
 * to the database driver. Attackers do it to append a second query
 * (INSERT, DROP, UPDATE) to an injected one.
 *
 * Some query builders emit trailing semicolons, so we only match
 * when there is non-whitespace content after the semicolon.
 */
final class StackedQueryRule implements RuleInterface
{
    private const PATTERN = '/;\s*\S/';

    public function matches(string $input): ?ThreatMatch
    {
        if (preg_match(self::PATTERN, $input) !== 1) {
            return null;
        }

        return new ThreatMatch(
            type: $this->type(),
            confidence: $this->confidence(),
            rule: $this->name(),
            description: 'Stacked query pattern found',
        );
    }

    public function name(): string
    {
        return 'stacked_query';
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
