<?php

declare(strict_types=1);

use Laronclad\Analysis\ConfidenceLevel;

it('exposes the expected cases', function () {
    expect(ConfidenceLevel::cases())->toHaveCount(3);
});

it('has a stable string value for each case', function () {
    expect(ConfidenceLevel::Low->value)->toBe('low');
    expect(ConfidenceLevel::Medium->value)->toBe('medium');
    expect(ConfidenceLevel::High->value)->toBe('high');
});

it('only allows blocking at the High level', function () {
    expect(ConfidenceLevel::High->allowsBlocking())->toBeTrue();
    expect(ConfidenceLevel::Medium->allowsBlocking())->toBeFalse();
    expect(ConfidenceLevel::Low->allowsBlocking())->toBeFalse();
});
