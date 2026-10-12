<?php

declare(strict_types=1);

it('reports when there is no log file', function () {
    $path = storage_path('logs/laronclad.log');

    if (file_exists($path)) {
        unlink($path);
    }

    $this->artisan('laronclad:clear-logs')
        ->expectsOutputToContain('No log file')
        ->assertSuccessful();
});

it('clears an existing log file', function () {
    $path = storage_path('logs/laronclad.log');

    if (! is_dir(dirname($path))) {
        mkdir(dirname($path), 0777, true);
    }

    file_put_contents($path, 'some content');

    $this->artisan('laronclad:clear-logs')
        ->assertSuccessful();

    expect(file_get_contents($path))->toBe('');
});

it('warns when a custom channel is configured', function () {
    config()->set('laronclad.logging.channel', 'stack');

    $this->artisan('laronclad:clear-logs')
        ->expectsOutputToContain('custom log channel')
        ->assertSuccessful();
});
