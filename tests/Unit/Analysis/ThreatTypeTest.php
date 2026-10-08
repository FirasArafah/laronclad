<?php

declare(strict_types=1);

use Laronclad\Analysis\ThreatType;

it('exposes the expected cases', function () {
    expect(ThreatType::cases())->toHaveCount(3);
});

it('has a stable string value for each case', function () {
    // These values end up in logs and in user config. Changing them
    // is a breaking change, so the test pins them down.
    expect(ThreatType::SqlInjection->value)->toBe('sqli');
    expect(ThreatType::Ssrf->value)->toBe('ssrf');
    expect(ThreatType::ProcessExecution->value)->toBe('process');
});

it('can be created from its string value', function () {
    expect(ThreatType::from('sqli'))->toBe(ThreatType::SqlInjection);
    expect(ThreatType::from('ssrf'))->toBe(ThreatType::Ssrf);
    expect(ThreatType::from('process'))->toBe(ThreatType::ProcessExecution);
});

it('throws when the string value is unknown', function () {
    expect(fn () => ThreatType::from('unknown'))
        ->toThrow(ValueError::class);
});
