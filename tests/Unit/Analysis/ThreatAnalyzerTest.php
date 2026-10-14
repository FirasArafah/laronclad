<?php

declare(strict_types=1);

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\RuleInterface;
use Laronclad\Analysis\Rules\CommentInjectionRule;
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

/**
 * A rule that always fails, to prove the analyzer isolates it.
 */
function throwingRule(bool $throwInType = false): RuleInterface
{
    return new class($throwInType) implements RuleInterface
    {
        public function __construct(private bool $throwInType) {}

        public function matches(string $input): ?ThreatMatch
        {
            throw new RuntimeException('sensitive-detail');
        }

        public function name(): string
        {
            return 'boom';
        }

        public function type(): ThreatType
        {
            if ($this->throwInType) {
                throw new RuntimeException('sensitive-detail');
            }

            return ThreatType::SqlInjection;
        }

        public function confidence(): ConfidenceLevel
        {
            return ConfidenceLevel::High;
        }
    };
}

/**
 * Runs the callback and returns whatever it wrote to PHP's error log.
 */
function captureAnalyzerErrorLog(Closure $callback): string
{
    $file = (string) tempnam(sys_get_temp_dir(), 'laronclad');
    $previous = ini_set('error_log', $file);

    try {
        $callback();
    } finally {
        ini_set('error_log', (string) $previous);
    }

    $output = (string) file_get_contents($file);
    unlink($file);

    return $output;
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

it('returns one match per applicable rule', function () {
    $analyzer = new ThreatAnalyzer([
        new UnionSelectRule,
        new CommentInjectionRule,
    ]);

    $matches = $analyzer->analyze(
        'SELECT 1 UNION SELECT 2 -- x',
        ThreatType::SqlInjection,
    );

    expect(array_map(
        static fn (ThreatMatch $match): string => $match->rule,
        $matches,
    ))->toBe(['union_select', 'comment_injection']);
});

it('returns at most one match per rule', function () {
    // This command contains two dangerous patterns:
    // "rm -rf /" and "chmod 777". DangerousCommandRule is a single
    // rule and stops at its first matching pattern, so the analyzer
    // reports one match for it.
    $matches = analyzer()->analyze(
        'rm -rf / && chmod 777 /var/www',
        ThreatType::ProcessExecution,
    );

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

it('skips a rule that throws and keeps running the rest', function () {
    $analyzer = new ThreatAnalyzer([throwingRule(), new UnionSelectRule]);

    $matches = [];

    captureAnalyzerErrorLog(function () use ($analyzer, &$matches) {
        $matches = $analyzer->analyze('SELECT 1 UNION SELECT 2', ThreatType::SqlInjection);
    });

    expect($matches)->toHaveCount(1);
    expect($matches[0]->rule)->toBe('union_select');
});

it('skips a rule whose type() throws', function () {
    $analyzer = new ThreatAnalyzer([throwingRule(throwInType: true), new UnionSelectRule]);

    $matches = [];

    captureAnalyzerErrorLog(function () use ($analyzer, &$matches) {
        $matches = $analyzer->analyze('SELECT 1 UNION SELECT 2', ThreatType::SqlInjection);
    });

    expect($matches)->toHaveCount(1);
    expect($matches[0]->rule)->toBe('union_select');
});

it('reports a failing rule by class name only', function () {
    $analyzer = new ThreatAnalyzer([throwingRule()]);

    $output = captureAnalyzerErrorLog(function () use ($analyzer) {
        $analyzer->analyze('SELECT 1', ThreatType::SqlInjection);
    });

    expect($output)->toContain('rule failed');
    expect($output)->toContain('threw RuntimeException');
    expect($output)->not->toContain('sensitive-detail');
});
