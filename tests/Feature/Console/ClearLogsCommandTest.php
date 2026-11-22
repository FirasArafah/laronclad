<?php

declare(strict_types=1);

/**
 * Points the application at a fresh storage directory and returns the
 * log file path inside it.
 *
 * These tests used to share storage/logs/laronclad.log with the rest
 * of the suite. Deleting a file that another test still has open
 * fails on Windows, so each test now works in a directory of its own.
 */
function freshLogPath(): string
{
    $root = sys_get_temp_dir().DIRECTORY_SEPARATOR.'laronclad-'.bin2hex(random_bytes(6));

    mkdir($root.DIRECTORY_SEPARATOR.'logs', 0777, true);

    app()->useStoragePath($root);

    return $root.DIRECTORY_SEPARATOR.'logs'.DIRECTORY_SEPARATOR.'laronclad.log';
}

function removeFreshLogPath(string $logPath): void
{
    if (file_exists($logPath)) {
        unlink($logPath);
    }

    $logs = dirname($logPath);

    rmdir($logs);
    rmdir(dirname($logs));
}

it('reports when there is no log file', function () {
    $logPath = freshLogPath();

    try {
        $this->artisan('laronclad:clear-logs')
            ->expectsOutputToContain('No log file')
            ->assertSuccessful();
    } finally {
        removeFreshLogPath($logPath);
    }
});

it('clears an existing log file', function () {
    $logPath = freshLogPath();

    try {
        file_put_contents($logPath, 'some content');

        $this->artisan('laronclad:clear-logs')
            ->assertSuccessful();

        expect(file_get_contents($logPath))->toBe('');
    } finally {
        removeFreshLogPath($logPath);
    }
});

it('warns when a custom channel is configured', function () {
    config()->set('laronclad.logging.channel', 'stack');

    $this->artisan('laronclad:clear-logs')
        ->expectsOutputToContain('custom log channel')
        ->assertSuccessful();
});
