<?php

declare(strict_types=1);

namespace Laronclad\Support;

use Closure;
use Illuminate\Http\Request;
use Throwable;

/**
 * Knows whether what is running right now is excluded from monitoring.
 *
 * Two things can be excluded: a route, by its name, and an Artisan
 * command, by its name. The running command is tracked from the
 * console command events, as a stack, because a command can call
 * another one.
 *
 * Fail-open in the direction that matters: if the whitelist cannot
 * be read or a check fails, the answer is "not excluded", so a
 * broken check never turns monitoring off. The whitelist is read at
 * check time, so config changes made at runtime apply.
 *
 * A route is only known once routing has run. Queries and requests
 * made before that, for example in global middleware, are monitored.
 */
final class MonitoringScope
{
    /**
     * @var list<string>
     */
    private array $commands = [];

    /**
     * @param  Closure(): Whitelist  $whitelist
     */
    public function __construct(private readonly Closure $whitelist) {}

    public function enterCommand(string $command): void
    {
        $this->commands[] = $command;
    }

    /**
     * Marks a command as finished. Commands entered after it are
     * finished too, so they are dropped with it. A command that was
     * never entered is ignored.
     */
    public function leaveCommand(string $command): void
    {
        for ($index = count($this->commands) - 1; $index >= 0; $index--) {
            if ($this->commands[$index] === $command) {
                $this->commands = array_slice($this->commands, 0, $index);

                return;
            }
        }
    }

    public function isExcluded(): bool
    {
        try {
            $whitelist = ($this->whitelist)();

            if ($whitelist->isEmpty()) {
                return false;
            }

            $command = $this->commands === []
                ? null
                : $this->commands[array_key_last($this->commands)];

            return $whitelist->matchesCommand($command)
                || $whitelist->matchesRoute($this->routeName());
        } catch (Throwable $e) {
            error_log('[laronclad] whitelist check failed: '.$e::class);

            return false;
        }
    }

    private function routeName(): ?string
    {
        /** @var mixed $request */
        $request = app('request');

        if (! $request instanceof Request) {
            return null;
        }

        /** @var mixed $route */
        $route = $request->route();

        if (! is_object($route) || ! method_exists($route, 'getName')) {
            return null;
        }

        $name = $route->getName();

        return is_string($name) && $name !== '' ? $name : null;
    }
}
