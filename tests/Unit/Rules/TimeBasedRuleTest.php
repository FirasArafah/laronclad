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

it('matches a comment between the name and the parenthesis', function (string $query) {
    expect(timeRule()->matches($query))->not->toBeNull();
})->with([
    'SELECT SLEEP /**/ (5)',
    'SELECT SLEEP/*x*/(5)',
    'SELECT/*!50000SLEEP*/(5)',
    "WAITFOR/**/DELAY '0:0:5'",
    "SELECT 1 -- note\n, SLEEP(5)",
    "SELECT '--' , SLEEP /**/ (5)",
]);

it('matches the Postgres variants', function (string $query) {
    expect(timeRule()->matches($query))->not->toBeNull();
})->with([
    "SELECT pg_sleep_for('5 seconds')",
    "SELECT pg_sleep_until('tomorrow')",
    'SELECT pg_catalog.pg_sleep(5)',
]);

it('matches WAITFOR TIME', function () {
    expect(timeRule()->matches("WAITFOR TIME '10:00'"))->not->toBeNull();
});

it('matches the Oracle variants', function (string $query) {
    expect(timeRule()->matches($query))->not->toBeNull();
})->with([
    'SELECT dbms_lock.sleep(5) FROM dual',
    'SELECT DBMS_LOCK . SLEEP (5) FROM dual',
    "SELECT dbms_pipe.receive_message('a', 5) FROM dual",
]);

it('does not match names that only contain these words', function (string $query) {
    expect(timeRule()->matches($query))->toBeNull();
})->with([
    'SELECT my_sleep(5)',
    'SELECT pg_sleepy(1)',
    'SELECT waitfor FROM t',
    'SELECT waitfor_delay FROM t',
    'SELECT benchmark_results FROM t',
]);

it('still matches text inside a comment because the raw query is read too', function () {
    expect(timeRule()->matches('SELECT 1 /* SLEEP(5) */'))->not->toBeNull();
});

it('handles a flood of repeated words without hanging', function () {
    $start = microtime(true);

    timeRule()->matches(str_repeat('sleep ', 100000));
    timeRule()->matches(str_repeat('waitfor ', 100000));

    expect(microtime(true) - $start)->toBeLessThan(0.5);
});
