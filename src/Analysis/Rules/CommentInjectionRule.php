<?php

declare(strict_types=1);

namespace Laronclad\Analysis\Rules;

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\RuleInterface;
use Laronclad\Analysis\ThreatMatch;
use Laronclad\Analysis\ThreatType;

/**
 * Detects SQL comment sequences in a query.
 *
 * Comments are used to truncate the rest of a legitimate query, so
 * an injected payload can finish the statement cleanly. They are
 * also used legitimately in raw SQL, so the confidence is Low.
 *
 * A single trailing comment on a raw query is common. This rule
 * therefore only fires when a comment sequence is present and the
 * query contains other suspicious markers, OR when multiple comment
 * sequences appear.
 *
 * For v0.1, we simply flag any comment sequence. The analyzer
 * decides what to do with Low confidence matches (log only).
 */
final class CommentInjectionRule implements RuleInterface
{
    private const PATTERN = '/(?:--|#|\/\*)/';

    public function matches(string $input): ?ThreatMatch
    {
        if (preg_match(self::PATTERN, $input) !== 1) {
            return null;
        }

        return new ThreatMatch(
            type: $this->type(),
            confidence: $this->confidence(),
            rule: $this->name(),
            description: 'SQL comment sequence found in query',
        );
    }

    public function name(): string
    {
        return 'comment_injection';
    }

    public function type(): ThreatType
    {
        return ThreatType::SqlInjection;
    }

    public function confidence(): ConfidenceLevel
    {
        return ConfidenceLevel::Low;
    }
}
