<?php

declare(strict_types=1);

use Laronclad\Support\Whitelist;

it('matches nothing when empty', function () {
    $whitelist = new Whitelist;

    expect($whitelist->matchesRoute('users.index'))->toBeFalse();
    expect($whitelist->matchesCommand('migrate'))->toBeFalse();
    expect($whitelist->isEmpty())->toBeTrue();
});

it('matches an exact route', function () {
    $whitelist = new Whitelist(routes: ['users.index']);

    expect($whitelist->matchesRoute('users.index'))->toBeTrue();
    expect($whitelist->matchesRoute('users.show'))->toBeFalse();
});

it('matches a route with a wildcard', function () {
    $whitelist = new Whitelist(routes: ['admin.*']);

    expect($whitelist->matchesRoute('admin.users.index'))->toBeTrue();
    expect($whitelist->matchesRoute('admin.posts.show'))->toBeTrue();
    expect($whitelist->matchesRoute('api.users.index'))->toBeFalse();
});

it('matches an Artisan command', function () {
    $whitelist = new Whitelist(commands: ['migrate', 'db:seed']);

    expect($whitelist->matchesCommand('migrate'))->toBeTrue();
    expect($whitelist->matchesCommand('db:seed'))->toBeTrue();
    expect($whitelist->matchesCommand('queue:work'))->toBeFalse();
});

it('handles null subjects', function () {
    $whitelist = new Whitelist(routes: ['users.*']);

    expect($whitelist->matchesRoute(null))->toBeFalse();
    expect($whitelist->matchesCommand(null))->toBeFalse();
});

it('is not empty when any pattern is present', function () {
    expect((new Whitelist(routes: ['x']))->isEmpty())->toBeFalse();
    expect((new Whitelist(commands: ['y']))->isEmpty())->toBeFalse();
});
