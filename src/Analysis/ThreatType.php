<?php

declare(strict_types=1);

namespace Laronclad\Analysis;

/**
 * Categories of threats Laronclad can detect.
 *
 * Each case represents one kind of suspicious behavior the package
 * watches for. Rules are grouped by type, and the type ends up in
 * every logged event so consumers can filter on it.
 */
enum ThreatType: string
{
    /**
     * SQL injection patterns observed in a database query.
     */
    case SqlInjection = 'sqli';

    /**
     * Server-side request forgery observed in an outbound HTTP call.
     */
    case Ssrf = 'ssrf';

    /**
     * Suspicious process execution observed through Laravel's Process
     * facade.
     */
    case ProcessExecution = 'process';
}
