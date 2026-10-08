<?php

declare(strict_types=1);

/*
 * The provider must load its config on register. If this fails,
 * everything else in the package breaks silently.
 */

it('loads the service provider', function () {
    // If the provider registered, config() returns an array.
    expect(config('laronclad'))->toBeArray();
});

it('merges the default config', function () {
    // The config file ships with enabled = true. No environment
    // override is applied in tests, so we expect the default.
    expect(config('laronclad.enabled'))->toBeTrue();
});
