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
 *
 * Failed pattern matching is not silence: when a rule finds no match
 * but PCRE reports an error (invalid data, backtrack or JIT limit),
 * the input defeated the matcher. That is reported as one
 * "analysis_limit" finding, so crafting input that makes a regex
 * fail cannot be used to hide a payload.
 */
final readonly class ThreatAnalyzer
{
    /**
     * Rule name of the finding reported when pattern matching failed.
     */
    public const LIMIT_RULE = 'analysis_limit';

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
        $limitReached = false;

        foreach ($this->rules as $rule) {
            try {
                if ($rule->type() !== $type) {
                    continue;
                }

                // A successful call clears any PCRE error left behind by
                // earlier code, so an error seen after the rule ran
                // belongs to that rule.
                preg_match('/^/', '');

                $match = $rule->matches($input);

                if ($match !== null) {
                    $matches[] = $match;
                } elseif (preg_last_error() !== PREG_NO_ERROR) {
                    $limitReached = true;
                }
            } catch (Throwable $e) {
                error_log('[laronclad] rule failed: '.get_debug_type($rule).' threw '.$e::class);
            }
        }

        if ($limitReached) {
            $matches[] = new ThreatMatch(
                type: $type,
                confidence: ConfidenceLevel::Medium,
                rule: self::LIMIT_RULE,
                description: 'Pattern matching failed on this input (limit reached or malformed data)',
            );
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
