<?php

declare(strict_types=1);

/**
 * Laronclad configuration.
 *
 * Every option here is read through config('laronclad.*'). Do not
 * access env() directly from other parts of the package; always go
 * through config so that a user can override values at runtime.
 */
return [
    /*
     * Master switch. When disabled, Laronclad does nothing.
     */
    'enabled' => env('LARONCLAD_ENABLED', true),

    /*
     * Mode. In v0.1 only "dry-run" is supported. A future version
     * will add "enforcing" for high-confidence threats.
     */
    'mode' => env('LARONCLAD_MODE', 'dry-run'),

    /*
     * Logging.
     *
     * The channel is any name registered in config/logging.php. If
     * left as null, Laronclad uses the application's default channel.
     *
     * The deduplication window is in seconds. Zero disables it.
     */
    'logging' => [
        'channel' => env('LARONCLAD_LOG_CHANNEL'),
        'deduplication_window' => (int) env('LARONCLAD_LOG_DEDUP_WINDOW', 60),
    ],

    /*
     * Database monitoring.
     */
    'database' => [
        'enabled' => env('LARONCLAD_DATABASE_ENABLED', true),
        'max_input_length' => (int) env('LARONCLAD_DATABASE_MAX_INPUT', 8192),
    ],

    /*
     * Outbound HTTP monitoring.
     */
    'http' => [
        'enabled' => env('LARONCLAD_HTTP_ENABLED', true),
    ],

    /*
     * Process monitoring.
     */
    'process' => [
        'enabled' => env('LARONCLAD_PROCESS_ENABLED', true),
    ],

    /*
     * Whitelist.
     *
     * Routes and Artisan commands listed here are skipped entirely.
     * Patterns use fnmatch() syntax.
     *
     * Example:
     *   'routes' => ['admin.*', 'horizon.*'],
     *   'commands' => ['migrate', 'queue:work'],
     */
    'whitelist' => [
        'routes' => [],
        'commands' => [],
    ],
];
