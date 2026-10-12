<?php

declare(strict_types=1);

namespace Laronclad\Process;

use Laronclad\Analysis\ThreatAnalyzer;
use Laronclad\Analysis\ThreatType;
use Laronclad\Logging\SafeLogger;

/**
 * Inspects shell commands before execution.
 *
 * The guard itself does not run or block commands. It analyzes the
 * command string and hands matches to the logger. Wiring to Laravel's
 * Process facade is done by the service provider.
 *
 * Both string and array command forms are supported. Array commands
 * are joined with spaces for analysis only; the original array is
 * not modified.
 */
final readonly class ProcessGuard
{
    public function __construct(
        private ThreatAnalyzer $analyzer,
        private SafeLogger $logger,
    ) {}

    /**
     * @param  string|array<int, string>|null  $command
     */
    public function inspect(string|array|null $command): void
    {
        $subject = $this->normalize($command);

        if ($subject === null) {
            return;
        }

        $matches = $this->analyzer->analyze($subject, ThreatType::ProcessExecution);

        foreach ($matches as $match) {
            $this->logger->log($match, [
                'command_length' => strlen($subject),
            ]);
        }
    }

    /**
     * @param  string|array<int, string>|null  $command
     */
    private function normalize(string|array|null $command): ?string
    {
        if ($command === null) {
            return null;
        }

        if (is_string($command)) {
            return $command;
        }

        return implode(' ', $command);
    }
}
