<?php

declare(strict_types=1);

namespace Laronclad\Analysis;

/**
 * A single finding produced by a rule.
 *
 * Immutable. A rule returns one of these when it matches, or null
 * when it doesn't. The analyzer collects matches and hands them to
 * the logger.
 *
 * Context is intentionally a plain array of scalars. It's not meant
 * to hold user input; only metadata that is safe to log as-is.
 */
final readonly class ThreatMatch
{
    /**
     * @param  array<string, scalar|null>  $context
     */
    public function __construct(
        public ThreatType $type,
        public ConfidenceLevel $confidence,
        public string $rule,
        public string $description,
        public array $context = [],
    ) {}
}
