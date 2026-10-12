<?php

declare(strict_types=1);

namespace Laronclad\Support;

/**
 * Determines whether the current context is excluded from monitoring.
 *
 * Users know their own safe patterns better than we can guess them.
 * When a route, Artisan command, or queue name matches a whitelist
 * entry, Laronclad skips it entirely.
 *
 * Patterns use fnmatch() syntax: '*' matches any characters, '?'
 * matches one. Example: 'admin.*' matches 'admin.users.index'.
 */
final readonly class Whitelist
{
    /**
     * @param  list<string>  $routes
     * @param  list<string>  $commands
     */
    public function __construct(
        private array $routes = [],
        private array $commands = [],
    ) {}

    public function matchesRoute(?string $route): bool
    {
        return $this->matchesAny($route, $this->routes);
    }

    public function matchesCommand(?string $command): bool
    {
        return $this->matchesAny($command, $this->commands);
    }

    public function isEmpty(): bool
    {
        return $this->routes === [] && $this->commands === [];
    }

    /**
     * @param  list<string>  $patterns
     */
    private function matchesAny(?string $subject, array $patterns): bool
    {
        if ($subject === null) {
            return false;
        }

        foreach ($patterns as $pattern) {
            if (fnmatch($pattern, $subject)) {
                return true;
            }
        }

        return false;
    }
}
