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
     *
     * In v0.1 there is no runtime toggle beyond this: if it's off,
     * the package stays out of the way entirely.
     */
    'enabled' => env('LARONCLAD_ENABLED', true),
];
