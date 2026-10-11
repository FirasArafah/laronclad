<?php

declare(strict_types=1);

namespace Laronclad\Analysis;

/**
 * Runs a set of rules against a single input.
 *
 * The analyzer is stateless. It receives rules through the
 * constructor and returns whatever they find. It does not log,
 * cache, or persist anything. That is the job of the caller.
 *
 * Rules are filtered by type at analysis time. This lets the same
 * analyzer instance serve SQL, HTTP, and Process checks without
 * wasting CPU on rules that cannot possibly apply.
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
            if ($rule->type() !== $type) {
                continue;
            }

            $match = $rule->matches($input);

            if ($match !== null) {
                $matches[] = $match;
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
