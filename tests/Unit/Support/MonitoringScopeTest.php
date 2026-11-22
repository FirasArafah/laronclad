<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Laronclad\Support\MonitoringScope;
use Laronclad\Support\Whitelist;

/**
 * @param  list<string>  $routes
 * @param  list<string>  $commands
 */
function scopeFor(array $routes = [], array $commands = []): MonitoringScope
{
    return new MonitoringScope(
        static fn (): Whitelist => new Whitelist(routes: $routes, commands: $commands),
    );
}

/**
 * Binds a request, optionally already routed to the given route.
 */
function bindScopeRequest(?Route $route = null): void
{
    $request = Request::create('/x');

    if ($route !== null) {
        $request->setRouteResolver(static fn (): Route => $route);
    }

    app()->instance('request', $request);
}

function scopeRoute(?string $name): Route
{
    $route = new Route('GET', 'x', static fn () => null);

    return $name === null ? $route : $route->name($name);
}

/**
 * Runs the callback and returns whatever it wrote to PHP's error log.
 */
function captureScopeErrorLog(Closure $callback): string
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

it('is not excluded when nothing is whitelisted', function () {
    bindScopeRequest(scopeRoute('admin.users'));

    expect(scopeFor()->isExcluded())->toBeFalse();
});

it('is excluded inside a whitelisted command', function () {
    $scope = scopeFor(commands: ['migrate']);

    expect($scope->isExcluded())->toBeFalse();

    $scope->enterCommand('migrate');

    expect($scope->isExcluded())->toBeTrue();

    $scope->leaveCommand('migrate');

    expect($scope->isExcluded())->toBeFalse();
});

it('is not excluded inside another command', function () {
    $scope = scopeFor(commands: ['migrate']);

    $scope->enterCommand('queue:work');

    expect($scope->isExcluded())->toBeFalse();
});

it('follows commands that call other commands', function () {
    $scope = scopeFor(commands: ['migrate']);

    $scope->enterCommand('migrate');
    $scope->enterCommand('other');

    expect($scope->isExcluded())->toBeFalse();

    $scope->leaveCommand('other');

    expect($scope->isExcluded())->toBeTrue();

    $scope->leaveCommand('migrate');

    expect($scope->isExcluded())->toBeFalse();
});

it('drops commands entered later when an earlier one finishes', function () {
    $scope = scopeFor(commands: ['inner']);

    $scope->enterCommand('outer');
    $scope->enterCommand('inner');

    expect($scope->isExcluded())->toBeTrue();

    $scope->leaveCommand('outer');

    expect($scope->isExcluded())->toBeFalse();
});

it('ignores a command that finishes without having started', function () {
    $scope = scopeFor(commands: ['migrate']);

    $scope->enterCommand('migrate');
    $scope->leaveCommand('never-started');

    expect($scope->isExcluded())->toBeTrue();
});

it('is excluded on a whitelisted route name', function () {
    bindScopeRequest(scopeRoute('admin.users.index'));

    expect(scopeFor(routes: ['admin.*'])->isExcluded())->toBeTrue();
});

it('is not excluded on another route', function () {
    bindScopeRequest(scopeRoute('public.home'));

    expect(scopeFor(routes: ['admin.*'])->isExcluded())->toBeFalse();
});

it('is not excluded on a route without a name', function () {
    bindScopeRequest(scopeRoute(null));

    expect(scopeFor(routes: ['admin.*'])->isExcluded())->toBeFalse();
});

it('is not excluded before a route is known', function () {
    bindScopeRequest();

    expect(scopeFor(routes: ['admin.*'])->isExcluded())->toBeFalse();
});

it('ignores a whitelist that would match everything', function () {
    bindScopeRequest(scopeRoute('admin.users'));

    $scope = scopeFor(routes: ['*'], commands: ['*']);
    $scope->enterCommand('migrate');

    expect($scope->isExcluded())->toBeFalse();
});

it('fails open and reports only the exception class', function () {
    $scope = new MonitoringScope(
        static fn (): Whitelist => throw new RuntimeException('secret-detail'),
    );

    $excluded = true;

    $output = captureScopeErrorLog(function () use ($scope, &$excluded) {
        $excluded = $scope->isExcluded();
    });

    // A check that breaks must never switch monitoring off.
    expect($excluded)->toBeFalse();
    expect($output)->toContain('whitelist check failed: RuntimeException');
    expect($output)->not->toContain('secret-detail');
});
