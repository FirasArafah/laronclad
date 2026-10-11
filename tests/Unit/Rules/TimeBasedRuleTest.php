<?php

declare(strict_types=1);

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\Rules\TimeBasedRule;
use Laronclad\Analysis\ThreatType;

function timeRule(): TimeBasedRule
{
    return new TimeBasedRule;
}

it('exposes its identity', function () {
    expect(timeRule()->name())->toBe('time_based');
    expect(timeRule()->type())->toBe(ThreatType::SqlInjection);
    expect(timeRule()->confidence())->toBe(ConfidenceLevel::Medium);
});

it('matches MySQL SLEEP', function () {
    expect(timeRule()->matches('SELECT 1 OR SLEEP(5)'))->not->toBeNull();
});

it('matches MySQL SLEEP case-insensitively', function () {
    expect(timeRule()->matches('SELECT 1 OR sleep(5)'))->not->toBeNull();
});

it('matches MySQL BENCHMARK', function () {
    expect(timeRule()->matches('SELECT BENCHMARK(1000000, MD5(1))'))->not->toBeNull();
});

it('matches Postgres pg_sleep', function () {
    expect(timeRule()->matches('SELECT pg_sleep(5)'))->not->toBeNull();
});

it('matches MSSQL WAITFOR DELAY', function () {
    expect(timeRule()->matches("WAITFOR DELAY '0:0:5'"))->not->toBeNull();
});

it('does not match the word sleep in another context', function () {
    expect(timeRule()->matches('SELECT * FROM sleep_logs'))->toBeNull();
});

it('does not match a plain select', function () {
    expect(timeRule()->matches('SELECT id FROM users'))->toBeNull();
});
