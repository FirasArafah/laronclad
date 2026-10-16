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
     * Master switch. When disabled, no monitoring hooks are installed.
     * The Artisan commands stay available so status can still be read.
     */
    'enabled' => env('LARONCLAD_ENABLED', true),

    /*
     * Mode. In v0.1 only "dry-run" exists: findings are logged and
     * nothing is ever blocked. Any other value is ignored. A future
     * version may add "enforcing" for high-confidence threats.
     */
    'mode' => env('LARONCLAD_MODE', 'dry-run'),

    /*
     * Logging.
     *
     * Channel: if null, findings go to storage/logs/laronclad.log, a
     * dedicated file with no rotation. To use one of your own channels
     * (for example "daily"), set any name registered in
     * config/logging.php.
     *
     * Deduplication window, in seconds: the same finding from the same
     * source (client IP, else user id) is logged once per window.
     * Zero disables deduplication.
     */
    'logging' => [
        'channel' => env('LARONCLAD_LOG_CHANNEL'),
        'deduplication_window' => (int) env('LARONCLAD_LOG_DEDUP_WINDOW', 60),
    ],

    /*
     * Database monitoring.
     *
     * Covers the default database connection only. Only the first
     * max_input_length bytes of each query are analyzed.
     */
    'database' => [
        'enabled' => env('LARONCLAD_DATABASE_ENABLED', true),
        'max_input_length' => (int) env('LARONCLAD_DATABASE_MAX_INPUT', 8192),
    ],

    /*
     * Outbound HTTP monitoring.
     *
     * Covers requests made with Laravel's HTTP client only.
     */
    'http' => [
        'enabled' => env('LARONCLAD_HTTP_ENABLED', true),
    ],

    /*
     * Process monitoring.
     *
     * Reserved. No process hook is installed in v0.1, so this option
     * has no effect yet.
     */
    'process' => [
        'enabled' => env('LARONCLAD_PROCESS_ENABLED', true),
    ],

    /*
     * Whitelist.
     *
     * Reserved. These lists are read and validated, but they are not
     * applied in v0.1: listed routes and commands are still monitored.
     * Patterns will use fnmatch() syntax.
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
