<?php

declare(strict_types=1);

namespace Laronclad\Analysis;

/**
 * How confident a rule is in a match.
 *
 * Only High may block in future versions. Low and Medium are
 * log-only. This keeps false positives from breaking real traffic.
 */
enum ConfidenceLevel: string
{
    /**
     * Pattern is loose. False positives expected.
     */
    case Low = 'low';

    /**
     * Pattern is specific but not definitive.
     */
    case Medium = 'medium';

    /**
     * Pattern almost certainly indicates an attack.
     */
    case High = 'high';

    /**
     * Whether a match at this level may be blocked.
     *
     * Reserved for v1.0. In v0.1, nothing blocks regardless of
     * level. Rules use this to document their own severity.
     */
    public function allowsBlocking(): bool
    {
        return $this === self::High;
    }
}
