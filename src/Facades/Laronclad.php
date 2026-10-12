<?php

declare(strict_types=1);

namespace Laronclad\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * Facade for the Laronclad package.
 *
 * @method static array<string, mixed> status()
 * @method static list<\Laronclad\Analysis\RuleInterface> rules()
 *
 * @see \Laronclad\Laronclad
 */
final class Laronclad extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'laronclad';
    }
}
