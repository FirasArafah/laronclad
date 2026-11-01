<?php

declare(strict_types=1);

namespace Laronclad\Process;

use Laronclad\Analysis\InputLimit;
use Laronclad\Analysis\ThreatAnalyzer;
use Laronclad\Analysis\ThreatType;
use Laronclad\Logging\SafeLogger;

/**
 * Inspects shell commands before execution.
 *
 * Status in v0.1: NOT HOOKED. Nothing in the package calls this
 * class automatically, and the "process.enabled" config option is
 * reserved. No public Laravel extension point for observing Process
 * calls was identified, and the package only uses public ones.
 *
 * The class is bound in the container, so application code can run
 * it by hand where it launches commands:
 *
 *     app(ProcessGuard::class)->inspect($command);
 *
 * The guard itself does not run or block commands. It analyzes the
 * command string and hands matches to the logger.
 *
 * Both string and array command forms are supported. Array commands
 * are joined with spaces for analysis only; the original array is
 * not modified.
 *
 * Commands longer than the limit have their first and last halves
 * analyzed and produce an "oversized_input" finding. The limit is
 * low on purpose: some command patterns scan quadratically on long
 * input.
 */
final readonly class ProcessGuard
{
    public const DEFAULT_MAX_INPUT_LENGTH = 8192;

    public function __construct(
        private ThreatAnalyzer $analyzer,
        private SafeLogger $logger,
        private int $maxInputLength = self::DEFAULT_MAX_INPUT_LENGTH,
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

        $limit = $this->maxInputLength > 0
            ? $this->maxInputLength
            : self::DEFAULT_MAX_INPUT_LENGTH;

        $matches = InputLimit::analyze(
            $this->analyzer,
            $subject,
            $limit,
            ThreatType::ProcessExecution,
        );

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
