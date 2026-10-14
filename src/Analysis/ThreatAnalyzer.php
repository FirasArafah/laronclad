<?php

declare(strict_types=1);

namespace Laronclad\Analysis;

use Throwable;

/**
 * Runs a set of rules against a single input.
 *
 * The analyzer is stateless. It receives rules through the
 * constructor and returns whatever they find. It does not log,
 * cache, or persist findings. That is the job of the caller.
 *
 * Rules are filtered by type at analysis time. This lets the same
 * analyzer instance serve SQL, HTTP, and Process checks without
 * wasting CPU on rules that cannot possibly apply.
 *
 * Fail-open: a rule that throws is skipped and reported to PHP's
 * error log by class names only. The remaining rules still run, so
 * one faulty rule cannot disable all detection or break the caller.
 */
final readonly class ThreatAnalyzer
{
    /**
     * @param  list<RuleInterface>  $rules
     */
    public function __construct(private array $rules) {}

    /**
     * Run every applicable rule against the input.
     *
     * @return list<ThreatMatch>
     */
    public function analyze(string $input, ThreatType $type): array
    {
        $matches = [];

        foreach ($this->rules as $rule) {
            try {
                if ($rule->type() !== $type) {
                    continue;
                }

                $match = $rule->matches($input);

                if ($match !== null) {
                    $matches[] = $match;
                }
            } catch (Throwable $e) {
                error_log('[laronclad] rule failed: '.get_debug_type($rule).' threw '.$e::class);
            }
        }

        return $matches;
    }

    /**
     * Return the rules this analyzer was built with.
     *
     * Useful for status commands and debugging.
     *
     * @return list<RuleInterface>
     */
    public function rules(): array
    {
        return $this->rules;
    }
}
