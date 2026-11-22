<?php

declare(strict_types=1);

namespace Laronclad\Support;

/**
 * Determines whether the current context is excluded from monitoring.
 *
 * Users know their own safe patterns better than we can guess them.
 * When a route name or Artisan command matches a whitelist entry,
 * Laronclad skips it entirely.
 *
 * Patterns use fnmatch() syntax: '*' matches any characters, '?'
 * matches one. Example: 'admin.*' matches 'admin.users.index'.
 *
 * A pattern made only of stars, or an empty one, would exclude
 * everything. That is what the enabled switch is for, so such
 * patterns are ignored instead of silently turning monitoring off.
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
        return $this->usable($this->routes) === [] && $this->usable($this->commands) === [];
    }

    /**
     * @param  list<string>  $patterns
     */
    private function matchesAny(?string $subject, array $patterns): bool
    {
        if ($subject === null || $subject === '') {
            return false;
        }

        foreach ($this->usable($patterns) as $pattern) {
            if (fnmatch($pattern, $subject)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The patterns that are allowed to match: not empty, and not
     * made only of stars.
     *
     * @param  list<string>  $patterns
     * @return list<string>
     */
    private function usable(array $patterns): array
    {
        return array_values(array_filter(
            $patterns,
            static fn (string $pattern): bool => trim($pattern, "* \t") !== '',
        ));
    }
}
