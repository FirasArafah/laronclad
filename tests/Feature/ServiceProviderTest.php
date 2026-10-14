<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\ServiceProvider;
use Laronclad\Analysis\ThreatAnalyzer;
use Laronclad\Laronclad;
use Laronclad\LaroncladServiceProvider;
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
    expect(app(Laronclad::class))->toBeInstanceOf(Laronclad::class);
});

it('exposes the laronclad string alias', function () {
    $fromClass = app(Laronclad::class);
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

it('registers its artisan commands', function () {
    $commands = Artisan::all();

    expect($commands)->toHaveKey('laronclad:status');
    expect($commands)->toHaveKey('laronclad:clear-logs');
});

it('registers the config publish tag', function () {
    $paths = ServiceProvider::pathsToPublish(
        LaroncladServiceProvider::class,
        'laronclad-config',
    );

    expect($paths)->toHaveCount(1);
});

it('installs the outbound http hook when enabled', function () {
    expect(Http::getGlobalMiddleware())->toHaveCount(1);
});

it('keeps commands but installs no hooks when disabled', function () {
    $_ENV['LARONCLAD_ENABLED'] = 'false';
    $_SERVER['LARONCLAD_ENABLED'] = 'false';

    try {
        // rebootApplication() is defined on Laronclad\Tests\TestCase,
        // but PHPStan types Pest's $this as the bare PHPUnit TestCase.
        /** @phpstan-ignore-next-line method.notFound */
        $this->rebootApplication();

        expect(config('laronclad.enabled'))->toBeFalse();
        expect(Http::getGlobalMiddleware())->toBe([]);

        $commands = Artisan::all();

        expect($commands)->toHaveKey('laronclad:status');
        expect($commands)->toHaveKey('laronclad:clear-logs');
    } finally {
        unset($_ENV['LARONCLAD_ENABLED'], $_SERVER['LARONCLAD_ENABLED']);
    }
});
