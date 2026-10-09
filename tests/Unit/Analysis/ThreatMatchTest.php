<?php

declare(strict_types=1);

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\ThreatMatch;
use Laronclad\Analysis\ThreatType;

it('holds the values it was constructed with', function () {
    $match = new ThreatMatch(
        type: ThreatType::SqlInjection,
        confidence: ConfidenceLevel::High,
        rule: 'union_select',
        description: 'UNION SELECT in query',
        context: ['route' => 'users.index'],
    );

    expect($match->type)->toBe(ThreatType::SqlInjection);
    expect($match->confidence)->toBe(ConfidenceLevel::High);
    expect($match->rule)->toBe('union_select');
    expect($match->description)->toBe('UNION SELECT in query');
    expect($match->context)->toBe(['route' => 'users.index']);
});

it('defaults context to an empty array', function () {
    $match = new ThreatMatch(
        type: ThreatType::Ssrf,
        confidence: ConfidenceLevel::Medium,
        rule: 'private_ip',
        description: 'Request to private IP',
    );

    expect($match->context)->toBe([]);
});

it('is immutable', function () {
    $match = new ThreatMatch(
        type: ThreatType::Ssrf,
        confidence: ConfidenceLevel::Low,
        rule: 'test',
        description: 'test',
    );

    // Readonly properties throw on write. We test that on purpose,
    // so PHPStan's warning about assigning outside the class is
    // expected here.
    /** @phpstan-ignore-next-line property.readOnlyAssignOutOfClass */
    expect(fn () => $match->rule = 'other')
        ->toThrow(Error::class);
});
