<?php

declare(strict_types=1);

namespace Laronclad\Analysis\Rules;

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\RuleInterface;
use Laronclad\Analysis\ThreatMatch;
use Laronclad\Analysis\ThreatType;

/**
 * Detects dangerous patterns in shell commands.
 *
 * This rule looks for common destructive or pivot patterns. It is
 * not exhaustive. Legitimate maintenance scripts might use some of
 * these; that is why confidence is Medium.
 *
 * Patterns covered:
 *   - rm -rf on root or home
 *   - piping curl/wget output to a shell
 *   - reverse shell markers (nc -e, bash -i, /dev/tcp/)
 *   - chmod 777 on sensitive paths
 */
final class DangerousCommandRule implements RuleInterface
{
    /**
     * @var list<string>
     */
    private const PATTERNS = [
        '/\brm\s+-rf?\s+\/(?:\s|$)/i',
        '/\bcurl\b[^|]*\|\s*(?:ba)?sh\b/i',
        '/\bwget\b[^|]*\|\s*(?:ba)?sh\b/i',
        '/\bnc\b[^\n]*\s-e\s/i',
        '/\bbash\s+-i\b/i',
        '/\/dev\/tcp\//i',
        '/\bchmod\s+777\b/i',
    ];

    public function matches(string $input): ?ThreatMatch
    {
        foreach (self::PATTERNS as $pattern) {
            if (preg_match($pattern, $input) === 1) {
                return new ThreatMatch(
                    type: $this->type(),
                    confidence: $this->confidence(),
                    rule: $this->name(),
                    description: 'Dangerous command pattern found',
                );
            }
        }

        return null;
    }

    public function name(): string
    {
        return 'dangerous_command';
    }

    public function type(): ThreatType
    {
        return ThreatType::ProcessExecution;
    }

    public function confidence(): ConfidenceLevel
    {
        return ConfidenceLevel::Medium;
    }
}
