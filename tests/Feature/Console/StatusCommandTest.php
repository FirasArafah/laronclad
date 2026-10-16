<?php

declare(strict_types=1);

it('prints the default status table', function () {
    $this->artisan('laronclad:status')
        ->expectsTable(['Key', 'Value'], [
            ['Enabled', 'yes'],
            ['Mode', 'dry-run'],
            ['Rules', '7'],
            ['Log channel', 'default (laronclad.log)'],
            ['Deduplication', '60s'],
        ])
        ->assertSuccessful();
});

it('lists every registered rule', function () {
    $this->artisan('laronclad:status')
        ->expectsOutput('Registered rules:')
        ->expectsOutputToContain('  - union_select')
        ->expectsOutputToContain('  - comment_injection')
        ->expectsOutputToContain('  - stacked_query')
        ->expectsOutputToContain('  - time_based')
        ->expectsOutputToContain('  - private_ip')
        ->expectsOutputToContain('  - metadata_endpoint')
        ->expectsOutputToContain('  - dangerous_command')
        ->assertSuccessful();
});

it('reflects the current configuration', function () {
    config()->set('laronclad.enabled', false);
    config()->set('laronclad.logging.channel', 'stack');
    config()->set('laronclad.logging.deduplication_window', 120);

    $this->artisan('laronclad:status')
        ->expectsTable(['Key', 'Value'], [
            ['Enabled', 'no'],
            ['Mode', 'dry-run'],
            ['Rules', '7'],
            ['Log channel', 'stack'],
            ['Deduplication', '120s'],
        ])
        ->assertSuccessful();
});

it('shows a disabled deduplication window as zero seconds', function () {
    config()->set('laronclad.logging.deduplication_window', 0);

    $this->artisan('laronclad:status')
        ->expectsOutputToContain('0s')
        ->assertSuccessful();
});
