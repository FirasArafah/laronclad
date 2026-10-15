<?php

declare(strict_types=1);

namespace Laronclad\Events;

use Laronclad\Analysis\ThreatMatch;

/**
 * Fired when a rule matches and the finding is logged.
 *
 * Users can listen for this event to forward findings to a
 * dedicated system (Slack, Sentry, SIEM). It is not fired for
 * deduplicated findings.
 *
 * Listen with Event::listen(ThreatDetected::class, ...). The event
 * is plain on purpose: it has no dependency on Laravel's Foundation
 * layer.
 */
final readonly class ThreatDetected
{
    /**
     * @param  array<array-key, mixed>  $context
     */
    public function __construct(
        public ThreatMatch $match,
        public array $context = [],
    ) {}
}
