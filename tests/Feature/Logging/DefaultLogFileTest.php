<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\ThreatMatch;
use Laronclad\Analysis\ThreatType;
use Laronclad\Logging\SafeLogger;

it('writes one json object per line to the default log file', function () {
    $path = storage_path('logs/laronclad.log');

    if (! is_dir(dirname($path))) {
        mkdir(dirname($path), 0777, true);
    }

    // Truncate instead of deleting. On Windows a file that another
    // handle in this run still holds open cannot be re-created after
    // unlink(), and earlier tests leave such handles behind.
    file_put_contents($path, '');

    // Different rules give different dedup keys, so both lines are written.
    Cache::flush();

    $logger = app(SafeLogger::class);

    $logger->log(new ThreatMatch(
        type: ThreatType::SqlInjection,
        confidence: ConfidenceLevel::Medium,
        rule: 'union_select',
        description: 'test match',
    ), ['query_length' => 12]);

    $logger->log(new ThreatMatch(
        type: ThreatType::Ssrf,
        confidence: ConfidenceLevel::High,
        rule: 'private_ip',
        description: 'test match',
    ), ['host' => '192.168.1.1']);

    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];

    file_put_contents($path, '');

    expect($lines)->toHaveCount(2);

    foreach ($lines as $line) {
        expect($line)->toStartWith('{');
        expect(json_decode($line, true))->toBeArray();
    }

    expect(json_decode($lines[0], true)['rule'])->toBe('union_select');
    expect(json_decode($lines[1], true)['rule'])->toBe('private_ip');
});
