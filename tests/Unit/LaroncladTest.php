<?php

declare(strict_types=1);

use Laronclad\Analysis\Rules\UnionSelectRule;
use Laronclad\Analysis\ThreatAnalyzer;
use Laronclad\Laronclad;

function makeLaronclad(): Laronclad
{
    return new Laronclad(new ThreatAnalyzer([new UnionSelectRule]));
}

it('reports enabled status from config', function () {
    config()->set('laronclad.enabled', true);

    expect(makeLaronclad()->status()['enabled'])->toBeTrue();
});

it('reports the configured mode', function () {
    config()->set('laronclad.mode', 'dry-run');

    expect(makeLaronclad()->status()['mode'])->toBe('dry-run');
});

it('reports the number of registered rules', function () {
    expect(makeLaronclad()->status()['rules_count'])->toBe(1);
});

it('reports rule names', function () {
    expect(makeLaronclad()->status()['rules'])->toBe(['union_select']);
});

it('exposes the rules directly', function () {
    expect(makeLaronclad()->rules())->toHaveCount(1);
});
