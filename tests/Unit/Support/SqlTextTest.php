<?php

declare(strict_types=1);

use Laronclad\Support\SqlText;

it('replaces block comments with a space', function (string $sql, string $expected) {
    expect(SqlText::withoutBlockComments($sql))->toBe($expected);
})->with([
    ['a/**/b', 'a b'],
    ['a/*x*/b/*y*/c', 'a b c'],
    ['no comments', 'no comments'],
    ['', ''],
]);

it('keeps the body of a versioned comment because the database runs it', function (string $sql, string $expected) {
    expect(SqlText::withoutBlockComments($sql))->toBe($expected);
})->with([
    ['a/*!50000b*/c', 'a b c'],
    ['a/*!b*/c', 'a b c'],
    ['a/*M!100100 b*/c', 'a  b c'],
    ['a/*!*/b', 'a  b'],
]);

it('leaves a comment that never closes untouched', function (string $sql) {
    expect(SqlText::withoutBlockComments($sql))->toBe($sql);
})->with([
    'a/*unterminated b',
    'a/*/b',
    '/*',
]);

it('matches a pattern in the raw text', function () {
    expect(SqlText::matches('/union/i', 'x UNION y'))->toBeTrue();
});

it('matches after block comments are removed', function () {
    expect(SqlText::matches('/union\s+select/i', 'union/**/select'))->toBeTrue();
    expect(SqlText::matches('/union\s+select/i', 'union/*padding*/select'))->toBeTrue();
});

it('matches after line comments are removed', function () {
    expect(SqlText::matches('/union\s+select/i', "union -- note\nselect"))->toBeTrue();
    expect(SqlText::matches('/union\s+select/i', "union # note\nselect"))->toBeTrue();
});

it('does not lose a payload that follows a comment marker inside a string', function () {
    expect(SqlText::matches('/union\s+select/i', "x = '#' UNION SELECT 1"))->toBeTrue();
    expect(SqlText::matches('/union\s+select/i', "x = '--' UNION SELECT 1"))->toBeTrue();
    expect(SqlText::matches('/union\s+select/i', "x = '/*' UNION SELECT 1, '*/'"))->toBeTrue();
});

it('returns false when no reading matches', function () {
    expect(SqlText::matches('/union\s+select/i', 'SELECT id FROM users'))->toBeFalse();
});

it('returns null and leaves the PCRE error set when matching fails', function () {
    // Invalid UTF-8 with the /u flag makes preg_match fail.
    expect(SqlText::matches('/./u', "\xff\xfe"))->toBeNull();
    expect(preg_last_error())->toBe(PREG_BAD_UTF8_ERROR);
});

it('handles a long run of opening markers quickly', function () {
    $start = microtime(true);

    SqlText::matches('/union/i', str_repeat('/*', 300000));

    expect(microtime(true) - $start)->toBeLessThan(0.5);
});
