<?php

declare(strict_types=1);
use Laronclad\Analysis\ThreatAnalyzer;
use Laronclad\Logging\SafeLogger;

it('loads the service provider', function () {
    expect(config('laronclad'))->toBeArray();
});

it('merges the default config', function () {
    expect(config('laronclad.enabled'))->toBeTrue();
});

it('binds the threat analyzer as a singleton', function () {
    $a = app(ThreatAnalyzer::class);
    $b = app(ThreatAnalyzer::class);

    expect($a)->toBe($b);
});

it('binds the safe logger as a singleton', function () {
    $a = app(SafeLogger::class);
    $b = app(SafeLogger::class);

    expect($a)->toBe($b);
});

it('binds the laronclad entry point', function () {
    expect(app(Laronclad\Laronclad::class))->toBeInstanceOf(Laronclad\Laronclad::class);
});

it('exposes the laronclad string alias', function () {
    $fromClass = app(Laronclad\Laronclad::class);
    $fromAlias = app('laronclad');

    // Compare references without passing a mixed value to expect().
    // PHPStan cannot infer TValue from app('laronclad'), which
    // returns mixed.
    expect($fromAlias === $fromClass)->toBeTrue();
});

it('registers the seven default rules', function () {
    $analyzer = app(ThreatAnalyzer::class);

    expect($analyzer->rules())->toHaveCount(7);
});
