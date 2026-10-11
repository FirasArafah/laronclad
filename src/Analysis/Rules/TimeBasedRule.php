<?php

declare(strict_types=1);

namespace Laronclad\Analysis\Rules;

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\RuleInterface;
use Laronclad\Analysis\ThreatMatch;
use Laronclad\Analysis\ThreatType;

/**
 * Detects time-based blind SQL injection patterns.
 *
 * These functions are almost never used in application queries.
 * When they appear, it is usually an attacker probing for a
 * time-based injection vector.
 *
 * Patterns covered:
 *   - MySQL:    SLEEP(), BENCHMARK()
 *   - MSSQL:    WAITFOR DELAY
 *   - Postgres: pg_sleep()
 */
final class TimeBasedRule implements RuleInterface
{
    private const PATTERN = '/\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b/i';

    public function matches(string $input): ?ThreatMatch
    {
        if (preg_match(self::PATTERN, $input) !== 1) {
            return null;
        }

        return new ThreatMatch(
            type: $this->type(),
            confidence: $this->confidence(),
            rule: $this->name(),
            description: 'Time-based injection pattern found',
        );
    }

    public function name(): string
    {
        return 'time_based';
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
