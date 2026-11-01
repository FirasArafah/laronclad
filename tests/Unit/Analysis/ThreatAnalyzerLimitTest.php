<?php

declare(strict_types=1);

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\RuleInterface;
use Laronclad\Analysis\Rules\UnionSelectRule;
use Laronclad\Analysis\ThreatAnalyzer;
use Laronclad\Analysis\ThreatMatch;
use Laronclad\Analysis\ThreatType;

/**
 * A rule for the failure tests. When $failing is true its pattern
 * cannot process the input: invalid UTF-8 with the /u flag makes
 * preg_match return false and sets a PCRE error. When false it makes
 * no preg call at all.
 */
function limitTestRule(bool $failing): RuleInterface
{
    return new class($failing) implements RuleInterface
    {
        public function __construct(private bool $failing) {}

        public function matches(string $input): ?ThreatMatch
        {
            if ($this->failing) {
                preg_match('/./u', "\xff\xfe");
            }

            return null;
        }

        public function name(): string
        {
            return 'limit_test';
        }

        public function type(): ThreatType
        {
            return ThreatType::SqlInjection;
        }

        public function confidence(): ConfidenceLevel
        {
            return ConfidenceLevel::Low;
        }
    };
}

it('reports a finding when a rule could not process the input', function () {
    $analyzer = new ThreatAnalyzer([limitTestRule(failing: true)]);

    $matches = $analyzer->analyze('x', ThreatType::SqlInjection);

    expect($matches)->toHaveCount(1);
    expect($matches[0]->rule)->toBe('analysis_limit');
    expect($matches[0]->confidence)->toBe(ConfidenceLevel::Medium);
    expect($matches[0]->type)->toBe(ThreatType::SqlInjection);
});

it('reports the limit finding once even if several rules fail', function () {
    $analyzer = new ThreatAnalyzer([
        limitTestRule(failing: true),
        limitTestRule(failing: true),
    ]);

    expect($analyzer->analyze('x', ThreatType::SqlInjection))->toHaveCount(1);
});

it('still returns real matches next to the limit finding', function () {
    $analyzer = new ThreatAnalyzer([
        limitTestRule(failing: true),
        new UnionSelectRule,
    ]);

    $matches = $analyzer->analyze('SELECT 1 UNION SELECT 2', ThreatType::SqlInjection);

    expect(array_map(
        static fn (ThreatMatch $match): string => $match->rule,
        $matches,
    ))->toBe(['union_select', 'analysis_limit']);
});

it('does not carry a failure over to the next analysis', function () {
    $failing = new ThreatAnalyzer([limitTestRule(failing: true)]);
    $quiet = new ThreatAnalyzer([limitTestRule(failing: false)]);

    expect($failing->analyze('x', ThreatType::SqlInjection))->toHaveCount(1);

    // The quiet rule makes no preg call, so a stale PCRE error from the
    // call above would be reported here if the analyzer did not reset it.
    expect($quiet->analyze('x', ThreatType::SqlInjection))->toBe([]);
});

it('ignores failures of rules for another type', function () {
    $analyzer = new ThreatAnalyzer([limitTestRule(failing: true)]);

    expect($analyzer->analyze('x', ThreatType::Ssrf))->toBe([]);
});
