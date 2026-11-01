<?php

declare(strict_types=1);

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\InputLimit;
use Laronclad\Analysis\Rules\UnionSelectRule;
use Laronclad\Analysis\ThreatAnalyzer;
use Laronclad\Analysis\ThreatMatch;
use Laronclad\Analysis\ThreatType;

function limitAnalyzer(): ThreatAnalyzer
{
    return new ThreatAnalyzer([new UnionSelectRule]);
}

/**
 * @param  list<ThreatMatch>  $matches
 * @return list<string>
 */
function limitRuleNames(array $matches): array
{
    return array_map(
        static fn (ThreatMatch $match): string => $match->rule,
        $matches,
    );
}

it('analyzes input within the limit as a whole', function () {
    $matches = InputLimit::analyze(
        limitAnalyzer(),
        'SELECT 1 UNION SELECT 2',
        1000,
        ThreatType::SqlInjection,
    );

    expect(limitRuleNames($matches))->toBe(['union_select']);
});

it('analyzes input of exactly the limit as a whole', function () {
    $input = str_pad('SELECT 1 UNION SELECT 2', 100);

    expect(strlen($input))->toBe(100);

    $matches = InputLimit::analyze(limitAnalyzer(), $input, 100, ThreatType::SqlInjection);

    expect(limitRuleNames($matches))->toBe(['union_select']);
});

it('analyzes the start of oversized input and flags it', function () {
    $input = 'SELECT 1 UNION SELECT 2 '.str_repeat('a', 500);

    $matches = InputLimit::analyze(limitAnalyzer(), $input, 100, ThreatType::SqlInjection);

    expect(limitRuleNames($matches))->toBe(['union_select', 'oversized_input']);
});

it('analyzes the end of oversized input and flags it', function () {
    $input = str_repeat('a', 500).' UNION SELECT 2';

    $matches = InputLimit::analyze(limitAnalyzer(), $input, 100, ThreatType::SqlInjection);

    expect(limitRuleNames($matches))->toBe(['union_select', 'oversized_input']);
});

it('cannot see the middle of oversized input but still flags it', function () {
    $input = str_repeat('a', 200).' UNION SELECT 1 '.str_repeat('b', 200);

    $matches = InputLimit::analyze(limitAnalyzer(), $input, 100, ThreatType::SqlInjection);

    expect(limitRuleNames($matches))->toBe(['oversized_input']);
});

it('reports a rule once when both ends match', function () {
    $input = 'UNION SELECT 1 '.str_repeat('a', 300).' UNION SELECT 2';

    $matches = InputLimit::analyze(limitAnalyzer(), $input, 100, ThreatType::SqlInjection);

    expect(limitRuleNames($matches))->toBe(['union_select', 'oversized_input']);
});

it('gives the oversized finding low confidence and the requested type', function () {
    $matches = InputLimit::analyze(
        limitAnalyzer(),
        str_repeat('a', 500),
        100,
        ThreatType::Ssrf,
    );

    expect($matches)->toHaveCount(1);
    expect($matches[0]->rule)->toBe('oversized_input');
    expect($matches[0]->confidence)->toBe(ConfidenceLevel::Low);
    expect($matches[0]->type)->toBe(ThreatType::Ssrf);
});

it('handles a tiny limit safely', function () {
    $matches = InputLimit::analyze(
        limitAnalyzer(),
        'abcdef',
        0,
        ThreatType::SqlInjection,
    );

    expect(limitRuleNames($matches))->toBe(['oversized_input']);
});
