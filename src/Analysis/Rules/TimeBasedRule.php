<?php

declare(strict_types=1);

namespace Laronclad\Analysis\Rules;

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\RuleInterface;
use Laronclad\Analysis\ThreatMatch;
use Laronclad\Analysis\ThreatType;
use Laronclad\Support\SqlText;

/**
 * Detects time-based blind SQL injection patterns.
 *
 * These functions are almost never used in application queries.
 * When they appear, it is usually an attacker probing for a
 * time-based injection vector.
 *
 * Patterns covered:
 *   - MySQL:      SLEEP(), BENCHMARK()
 *   - MSSQL:      WAITFOR DELAY, WAITFOR TIME
 *   - Postgres:   pg_sleep(), pg_sleep_for(), pg_sleep_until()
 *   - Oracle:     DBMS_LOCK.SLEEP(), DBMS_PIPE.RECEIVE_MESSAGE()
 *
 * Comments between the name and the parenthesis are handled by
 * SqlText, so SLEEP, a comment, then (5) is still found.
 *
 * A table or column that is merely called "sleep" followed by an
 * opening parenthesis can match; that is accepted at Medium
 * confidence.
 */
final class TimeBasedRule implements RuleInterface
{
    private const PATTERN = '/(?<![a-z0-9_$])(?:(?:sleep|benchmark|pg_sleep(?:_for|_until)?)\s*\(|waitfor\s+(?:delay|time)(?![a-z0-9_$])|dbms_lock\s*\.\s*sleep\s*\(|dbms_pipe\s*\.\s*receive_message\s*\()/i';

    public function matches(string $input): ?ThreatMatch
    {
        if (SqlText::matches(self::PATTERN, $input) !== true) {
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
