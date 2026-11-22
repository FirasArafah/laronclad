<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Laronclad\Logging\RequestContext;
use Laronclad\Support\MonitoringScope;
use Laronclad\Support\Whitelist;

/**
 * Runs the callback and returns whatever it wrote to PHP's error log.
 */
function captureContextErrorLog(Closure $callback): string
{
    $file = (string) tempnam(sys_get_temp_dir(), 'laronclad');
    $previous = ini_set('error_log', $file);

    try {
        $callback();
    } finally {
        ini_set('error_log', (string) $previous);
    }

    $output = (string) file_get_contents($file);
    unlink($file);

    return $output;
}

/**
 * Binds a request that looks like it came from a web SAPI.
 */
function bindContextRequest(string $method = 'GET', ?Route $route = null): void
{
    $request = Request::create('/users/7', $method, [], [], [], [
        'REMOTE_ADDR' => '203.0.113.5',
    ]);

    if ($route !== null) {
        $request->setRouteResolver(static fn (): Route => $route);
    }

    app()->instance('request', $request);
}

it('collects ip, method and route name', function () {
    $route = (new Route('GET', 'users/{id}', static fn () => null))->name('users.show');
    bindContextRequest('GET', $route);

    expect((new RequestContext)->collect())->toBe([
        'ip' => '203.0.113.5',
        'method' => 'GET',
        'route' => 'users.show',
    ]);
});

it('falls back to the route uri pattern when the route has no name', function () {
    bindContextRequest('GET', new Route('GET', 'users/{id}', static fn () => null));

    expect((new RequestContext)->collect()['route'])->toBe('users/{id}');
});

it('omits request fields when the sapi supplied no request', function () {
    app()->instance('request', new Request);

    expect((new RequestContext)->collect())->toBe([]);
});

it('reports a non-standard method as OTHER', function () {
    bindContextRequest('FOO-BAR');

    expect((new RequestContext)->collect()['method'])->toBe('OTHER');
});

it('ignores a request binding that is not a request', function () {
    // instance() on an already-bound key fires Laravel's auth rebinding
    // handler, which calls setUserResolver() on the new value. Clear the
    // binding first so a plain object can stand in for the request.
    app()->offsetUnset('request');
    app()->bind('request', static fn (): stdClass => new stdClass);

    $context = [];

    // Laravel's session guard cannot be built with a non-request, so the
    // auth lookup fails too. That failure is swallowed and reported by
    // class only, which is captured here to keep the test run quiet.
    captureContextErrorLog(function () use (&$context) {
        $context = (new RequestContext)->collect();
    });

    expect($context)->toBe([]);
});

it('reports the user id when a user is already resolved', function () {
    bindContextRequest();
    Auth::setUser(new GenericUser(['id' => 42]));

    expect((new RequestContext)->collect()['user_id'])->toBe(42);
});

it('does not run queries to look up the user', function () {
    bindContextRequest();
    DB::enableQueryLog();

    $context = (new RequestContext)->collect();

    expect($context)->not->toHaveKey('user_id');
    expect(DB::getQueryLog())->toBe([]);
});

/**
 * Binds the placeholder request Laravel creates for console runs: GET
 * from 127.0.0.1, with no real client behind it.
 */
function bindConsolePlaceholderRequest(): void
{
    app()->instance('request', Request::create('http://localhost', 'GET'));
}

function contextScope(): MonitoringScope
{
    return new MonitoringScope(static fn (): Whitelist => new Whitelist);
}

it('reports the running command instead of the console placeholder request', function () {
    bindConsolePlaceholderRequest();

    $scope = contextScope();
    $scope->enterCommand('queue:work');

    expect((new RequestContext($scope))->collect())->toBe(['command' => 'queue:work']);
});

it('reports the innermost command when commands are nested', function () {
    bindConsolePlaceholderRequest();

    $scope = contextScope();
    $scope->enterCommand('schedule:run');
    $scope->enterCommand('reports:send');

    expect((new RequestContext($scope))->collect())->toBe(['command' => 'reports:send']);
});

it('keeps the user id inside a command', function () {
    bindConsolePlaceholderRequest();
    Auth::setUser(new GenericUser(['id' => 42]));

    $scope = contextScope();
    $scope->enterCommand('import:users');

    expect((new RequestContext($scope))->collect())->toBe([
        'command' => 'import:users',
        'user_id' => 42,
    ]);
});

it('reports request fields again once the command has finished', function () {
    bindContextRequest('POST');

    $scope = contextScope();
    $scope->enterCommand('queue:work');
    $scope->leaveCommand('queue:work');

    expect((new RequestContext($scope))->collect())->toBe([
        'ip' => '203.0.113.5',
        'method' => 'POST',
    ]);
});

it('reports request fields when no scope is given', function () {
    bindContextRequest('POST');

    expect((new RequestContext)->collect())->toBe([
        'ip' => '203.0.113.5',
        'method' => 'POST',
    ]);
});

it('caps the length of a command name', function () {
    bindConsolePlaceholderRequest();

    $scope = contextScope();
    $scope->enterCommand(str_repeat('a', 500));

    expect((new RequestContext($scope))->collect()['command'])->toHaveLength(128);
});

it('fails open and reports only the exception class', function () {
    bindContextRequest();
    app()->bind('auth', static fn () => throw new RuntimeException('secret-detail'));

    $context = [];

    $output = captureContextErrorLog(function () use (&$context) {
        $context = (new RequestContext)->collect();
    });

    expect($context)->not->toHaveKey('user_id');
    expect($context['ip'])->toBe('203.0.113.5');
    expect($output)->toContain('request context failed: RuntimeException');
    expect($output)->not->toContain('secret-detail');
});
