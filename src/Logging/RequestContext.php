<?php

declare(strict_types=1);

namespace Laronclad\Logging;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Http\Request;
use Throwable;

/**
 * Collects safe metadata about the current request for log lines.
 *
 * Only metadata is collected: client IP, HTTP method, route name
 * and authenticated user id. No request bodies, headers, query
 * strings or cookies are ever read.
 *
 * Fail-open: any failure yields fewer fields, never an exception.
 * Failures are reported by exception class only.
 *
 * The user id is read only if the guard already holds a user.
 * Resolving a user can run a database query, and this class is
 * called from inside the database hook. Triggering a query there
 * would re-enter the monitor.
 */
final readonly class RequestContext
{
    private const MAX_FIELD_LENGTH = 128;

    /**
     * @return array<string, int|string>
     */
    public function collect(): array
    {
        return array_merge($this->fromRequest(), $this->fromAuth());
    }

    /**
     * @return array<string, string>
     */
    private function fromRequest(): array
    {
        try {
            // Typed as mixed on purpose: the container can hold
            // anything under these keys, so the checks below are real.
            /** @var mixed $request */
            $request = app('request');

            if (! $request instanceof Request) {
                return [];
            }

            $context = [];

            $ip = $request->ip();

            if (is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP) !== false) {
                $context['ip'] = $ip;
            }

            // Console runs have no REQUEST_METHOD. Symfony would
            // report GET anyway, which would mislabel artisan and
            // queue work as web traffic.
            if ($request->server->has('REQUEST_METHOD')) {
                $context['method'] = $this->sanitizeMethod($request->method());
            }

            $route = $this->routeLabel($request);

            if ($route !== null) {
                $context['route'] = $route;
            }

            return $context;
        } catch (Throwable $e) {
            error_log('[laronclad] request context failed: '.$e::class);

            return [];
        }
    }

    /**
     * @return array<string, int|string>
     */
    private function fromAuth(): array
    {
        try {
            /** @var mixed $auth */
            $auth = app('auth');

            if (! $auth instanceof AuthFactory) {
                return [];
            }

            $guard = $auth->guard();

            if (! $guard->hasUser()) {
                return [];
            }

            $id = $guard->id();

            if (is_int($id)) {
                return ['user_id' => $id];
            }

            if (is_string($id) && $id !== '') {
                return ['user_id' => substr($id, 0, self::MAX_FIELD_LENGTH)];
            }

            return [];
        } catch (Throwable $e) {
            error_log('[laronclad] request context failed: '.$e::class);

            return [];
        }
    }

    /**
     * The HTTP method is client-controlled, so anything that is not
     * a short token of letters is reported as OTHER.
     */
    private function sanitizeMethod(string $method): string
    {
        $method = strtoupper($method);

        return preg_match('/^[A-Z]{1,16}$/', $method) === 1 ? $method : 'OTHER';
    }

    /**
     * Prefer the route name, fall back to the route's URI pattern
     * (for example "users/{id}"). Both are defined by the developer,
     * never taken from the raw request path.
     */
    private function routeLabel(Request $request): ?string
    {
        /** @var mixed $route */
        $route = $request->route();

        if (! is_object($route)) {
            return null;
        }

        $label = method_exists($route, 'getName') ? $route->getName() : null;

        if (! is_string($label) || $label === '') {
            $label = method_exists($route, 'uri') ? $route->uri() : null;
        }

        if (! is_string($label) || $label === '') {
            return null;
        }

        return substr($label, 0, self::MAX_FIELD_LENGTH);
    }
}
