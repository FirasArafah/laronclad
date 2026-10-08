<?php

declare(strict_types=1);

namespace Laronclad\Tests;

use Illuminate\Foundation\Application;
use Laronclad\LaroncladServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

/**
 * Base test case for Laronclad.
 *
 * Orchestra Testbench boots a minimal Laravel application so we can
 * test the package without a full Laravel install. Any provider the
 * package needs must be registered here.
 */
abstract class TestCase extends Orchestra
{
    /**
     * Register the package's own service provider.
     *
     * @param  Application  $app
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            LaroncladServiceProvider::class,
        ];
    }
}
