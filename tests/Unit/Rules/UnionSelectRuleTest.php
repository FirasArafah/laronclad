<?php

declare(strict_types=1);

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\Rules\UnionSelectRule;
use Laronclad\Analysis\ThreatMatch;
use Laronclad\Analysis\ThreatType;

/**
 * Returns a fresh instance for each test.
 *
 * Using a function instead of a $this-> property keeps PHPStan
 * happy: it can infer the return type, and Pest tests remain
 * stateless between runs.
 */
function rule(): UnionSelectRule
{
    return new UnionSelectRule;
}

it('exposes its identity', function () {
    expect(rule()->name())->toBe('union_select');
    expect(rule()->type())->toBe(ThreatType::SqlInjection);
    expect(rule()->confidence())->toBe(ConfidenceLevel::Medium);
});

it('matches a basic union select', function () {
    $match = rule()->matches(
        'SELECT id FROM users WHERE name = \'x\' UNION SELECT password FROM admins'
    );

    expect($match)->toBeInstanceOf(ThreatMatch::class);
    expect($match?->rule)->toBe('union_select');
    expect($match?->type)->toBe(ThreatType::SqlInjection);
});

it('matches union all select', function () {
    expect(rule()->matches('SELECT 1 UNION ALL SELECT 2'))->not->toBeNull();
});

it('matches case-insensitively', function () {
    expect(rule()->matches('select 1 UnIoN SeLeCt 2'))->not->toBeNull();
    expect(rule()->matches('SELECT 1 union select 2'))->not->toBeNull();
});

it('matches with irregular whitespace', function () {
    expect(rule()->matches("SELECT 1\tUNION\nSELECT 2"))->not->toBeNull();
    expect(rule()->matches('SELECT 1    UNION     SELECT 2'))->not->toBeNull();
});

it('does not match a plain select', function () {
    expect(rule()->matches('SELECT id, name FROM users'))->toBeNull();
});

it('does not match substrings that contain the letters', function () {
    expect(rule()->matches('SELECT reunion FROM events'))->toBeNull();
    expect(rule()->matches('SELECT selection FROM menu'))->toBeNull();
});

it('does not match union without select', function () {
    expect(rule()->matches('SELECT 1 UNION 2'))->toBeNull();
});

it('does not match select without union', function () {
    expect(rule()->matches('SELECT 1 SELECT 2'))->toBeNull();
});

it('handles empty input', function () {
    expect(rule()->matches(''))->toBeNull();
});

it('handles very long input without hanging', function () {
    // ReDoS guard. A pathological input must return quickly.
    $input = str_repeat('union ', 5000);

    $start = microtime(true);
    rule()->matches($input);
    $elapsed = microtime(true) - $start;

    expect($elapsed)->toBeLessThan(0.5);
});

it('matches comments between the words', function (string $query) {
    expect(rule()->matches($query))->not->toBeNull();
})->with([
    'SELECT 1 UNION/**/SELECT 2',
    'SELECT 1 UNION/*padding that is long*/SELECT 2',
    'SELECT 1 UNION /**/ ALL /**/ SELECT 2',
    "SELECT 1 UNION -- note\nSELECT 2",
    "SELECT 1 UNION # note\nSELECT 2",
]);

it('matches ALL, DISTINCT and opening parentheses', function (string $query) {
    expect(rule()->matches($query))->not->toBeNull();
})->with([
    'SELECT 1 UNION(SELECT 2)',
    'SELECT 1 UNION ALL(SELECT 2)',
    'SELECT 1 UNION DISTINCT SELECT 2',
    'SELECT 1 UNION ((SELECT 2))',
    'SELECT 1 UNION ( ( SELECT 2 ) )',
    '(SELECT 1)UNION(SELECT 2)',
    "SELECT 1 UNION\r\nSELECT 2",
]);

it('matches MySQL and MariaDB versioned comments', function (string $query) {
    expect(rule()->matches($query))->not->toBeNull();
})->with([
    'SELECT 1 /*!50000UNION*/ /*!50000SELECT*/ 2',
    'SELECT 1 /*!UNION*/ /*!SELECT*/ 2',
    'SELECT 1 /*M!100100 UNION SELECT*/ 2',
    'SELECT 1 UNION/*!50000SELECT*/ 2',
]);

it('still matches when a string holds a comment marker', function (string $query) {
    expect(rule()->matches($query))->not->toBeNull();
})->with([
    "SELECT '#' UNION/**/SELECT 1",
    "SELECT '/*' UNION SELECT 1, '*/'",
    "x = '--' UNION SELECT 1",
]);

it('does not match words that only look like it', function (string $query) {
    expect(rule()->matches($query))->toBeNull();
})->with([
    'SELECT 1 UNION/**/ 2',
    'SELECT 1 UNION /**/ FROM t',
    'SELECT unionselect FROM t',
    'SELECT a_union SELECT',
    'SELECT 1 UNION ALLSELECT 2',
    'SELECT 1 UNION SELECTION',
    'SELECT union_col, select_col FROM t',
]);

it('handles a flood of unterminated comments without hanging', function () {
    $start = microtime(true);

    rule()->matches(str_repeat('union /*', 100000));

    expect(microtime(true) - $start)->toBeLessThan(0.5);
});
