<?php

declare(strict_types=1);

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\Rules\CommentInjectionRule;
use Laronclad\Analysis\ThreatType;

function commentRule(): CommentInjectionRule
{
    return new CommentInjectionRule;
}

it('exposes its identity', function () {
    expect(commentRule()->name())->toBe('comment_injection');
    expect(commentRule()->type())->toBe(ThreatType::SqlInjection);
    expect(commentRule()->confidence())->toBe(ConfidenceLevel::Low);
});

it('matches a double-dash comment', function () {
    expect(commentRule()->matches('SELECT 1 -- comment'))->not->toBeNull();
});

it('matches a hash comment', function () {
    expect(commentRule()->matches('SELECT 1 # comment'))->not->toBeNull();
});

it('matches a block comment', function () {
    expect(commentRule()->matches('SELECT 1 /* comment */'))->not->toBeNull();
});

it('does not match a query without comments', function () {
    expect(commentRule()->matches('SELECT id FROM users'))->toBeNull();
});

it('does not match a hyphen inside a word', function () {
    expect(commentRule()->matches('SELECT first-name FROM users'))->toBeNull();
});
