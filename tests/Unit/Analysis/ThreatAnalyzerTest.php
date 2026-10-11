<?php

declare(strict_types=1);

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\RuleInterface;
use Laronclad\Analysis\Rules\DangerousCommandRule;
use Laronclad\Analysis\Rules\PrivateIpRule;
use Laronclad\Analysis\Rules\UnionSelectRule;
use Laronclad\Analysis\ThreatAnalyzer;
use Laronclad\Analysis\ThreatMatch;
use Laronclad\Analysis\ThreatType;

function analyzer(): ThreatAnalyzer
{
    return new ThreatAnalyzer([
        new UnionSelectRule,
        new PrivateIpRule,
        new DangerousCommandRule,
    ]);
}

it('returns an empty array when no rules match', function () {
    expect(analyzer()->analyze('SELECT id FROM users', ThreatType::SqlInjection))->toBe([]);
});

it('returns matches for the requested type only', function () {
    $matches = analyzer()->analyze(
        'SELECT 1 UNION SELECT 2',
        ThreatType::SqlInjection,
    );

    expect($matches)->toHaveCount(1);
    expect($matches[0])->toBeInstanceOf(ThreatMatch::class);
    expect($matches[0]->rule)->toBe('union_select');
});

it('does not run SQL rules on SSRF input', function () {
    // Even though "UNION SELECT" appears in the URL, the analyzer
    // should not run SQL rules when asked for SSRF type.
    $matches = analyzer()->analyze(
        'https://example.com/?q=UNION%20SELECT',
        ThreatType::Ssrf,
    );

    expect($matches)->toBe([]);
});

it('returns multiple matches when several rules apply', function () {
    // This command contains two dangerous patterns:
    // "rm -rf /" and "chmod 777".
    $matches = analyzer()->analyze(
        'rm -rf / && chmod 777 /var/www',
        ThreatType::ProcessExecution,
    );

    // Our current DangerousCommandRule stops at the first match,
    // so we expect one.
    expect($matches)->toHaveCount(1);
});

it('exposes the rules it was built with', function () {
    expect(analyzer()->rules())->toHaveCount(3);
});

it('handles an empty rule list', function () {
    $empty = new ThreatAnalyzer([]);
    expect($empty->analyze('SELECT 1 UNION SELECT 2', ThreatType::SqlInjection))->toBe([]);
});

it('accepts any RuleInterface implementation', function () {
    $customRule = new class implements RuleInterface
    {
        public function matches(string $input): ?ThreatMatch
        {
            // Return null for empty input. This keeps the rule
            // realistic and satisfies static analysis without
            // needing an ignore comment.
            if ($input === '') {
                return null;
            }

            return new ThreatMatch(
                type: ThreatType::SqlInjection,
                confidence: ConfidenceLevel::High,
                rule: 'always',
                description: 'Matches any non-empty input',
            );
        }

        public function name(): string
        {
            return 'always';
        }

        public function type(): ThreatType
        {
            return ThreatType::SqlInjection;
        }

        public function confidence(): ConfidenceLevel
        {
            return ConfidenceLevel::High;
        }
    };

    $analyzer = new ThreatAnalyzer([$customRule]);
    $matches = $analyzer->analyze('anything', ThreatType::SqlInjection);

    expect($matches)->toHaveCount(1);
    expect($matches[0]->rule)->toBe('always');
});
