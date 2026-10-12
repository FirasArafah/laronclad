<?php

declare(strict_types=1);

namespace Laronclad\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Laronclad\Analysis\ThreatMatch;

/**
 * Fired when a rule matches and the finding is logged.
 *
 * Users can listen for this event to forward findings to a
 * dedicated system (Slack, Sentry, SIEM). It is not fired for
 * deduplicated findings.
 */
final readonly class ThreatDetected
{
    use Dispatchable;

    /**
     * @param  array<array-key, mixed>  $context
     */
    public function __construct(
        public ThreatMatch $match,
        public array $context = [],
    ) {}
}
