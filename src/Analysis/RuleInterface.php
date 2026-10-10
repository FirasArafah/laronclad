<?php

declare(strict_types=1);

namespace Laronclad\Analysis;

/**
 * Contract for every detection rule.
 *
 * A rule receives some input (a SQL query, an outbound URL, a
 * process command) and either returns a ThreatMatch describing what
 * it found, or null if it has nothing to report.
 *
 * Rules are stateless. They must not cache results between calls,
 * and they must not depend on request context. Anything they need
 * must be passed in.
 */
interface RuleInterface
{
    /**
     * Inspect the given input and return a match if it applies.
     *
     * Implementations decide what "input" means. A SQL rule expects
     * a query string, an SSRF rule expects a URL, and so on.
     */
    public function matches(string $input): ?ThreatMatch;

    /**
     * A short, stable identifier for this rule.
     *
     * Ends up in every log line and in user config, so it must not
     * change once released.
     */
    public function name(): string;

    /**
     * The threat type this rule produces.
     *
     * Used by the analyzer to group matches and by the logger to
     * filter them.
     */
    public function type(): ThreatType;

    /**
     * How confident this rule is in its own matches.
     *
     * Determines whether a match may block in future versions.
     */
    public function confidence(): ConfidenceLevel;
}
