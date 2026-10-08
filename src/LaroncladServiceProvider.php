<?php

declare(strict_types=1);

namespace Laronclad;

use Illuminate\Support\ServiceProvider;

/**
 * Entry point for the Laronclad package.
 *
 * Laravel loads this class automatically through package discovery
 * (see the "extra.laravel.providers" entry in composer.json). It
 * registers the config file and publishes it for the user.
 *
 * Keep this class thin. All monitoring logic lives in dedicated
 * classes under src/.
 */
final class LaroncladServiceProvider extends ServiceProvider
{
    /**
     * Register bindings in the container.
     *
     * Runs before the application is booted. At this stage we only
     * merge the package config so that any class resolving later can
     * read from config('laronclad.*').
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/laronclad.php',
            'laronclad'
        );
    }

    /**
     * Bootstrap package services.
     *
     * Runs after all providers are registered. Publishing is only
     * meaningful in a console context, so we guard it accordingly.
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/laronclad.php' => config_path('laronclad.php'),
            ], 'laronclad-config');
        }
    }
}
