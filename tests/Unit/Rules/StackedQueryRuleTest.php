<?php

declare(strict_types=1);

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\Rules\StackedQueryRule;
use Laronclad\Analysis\ThreatType;

function stackedRule(): StackedQueryRule
{
    return new StackedQueryRule;
}

it('exposes its identity', function () {
    expect(stackedRule()->name())->toBe('stacked_query');
    expect(stackedRule()->type())->toBe(ThreatType::SqlInjection);
    expect(stackedRule()->confidence())->toBe(ConfidenceLevel::Medium);
});

it('matches a stacked query', function () {
    expect(stackedRule()->matches('SELECT 1; DROP TABLE users'))->not->toBeNull();
});

it('matches with extra whitespace after the semicolon', function () {
    expect(stackedRule()->matches('SELECT 1;   DELETE FROM users'))->not->toBeNull();
});

it('matches with a newline after the semicolon', function () {
    expect(stackedRule()->matches("SELECT 1;\nDROP TABLE users"))->not->toBeNull();
});

it('does not match a trailing semicolon', function () {
    expect(stackedRule()->matches('SELECT 1;'))->toBeNull();
});

it('does not match a trailing semicolon with whitespace', function () {
    expect(stackedRule()->matches('SELECT 1;   '))->toBeNull();
});

it('does not match a query without a semicolon', function () {
    expect(stackedRule()->matches('SELECT id FROM users'))->toBeNull();
});
