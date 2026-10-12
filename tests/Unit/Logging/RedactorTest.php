<?php

declare(strict_types=1);

use Laronclad\Logging\Redactor;

function redactor(): Redactor
{
    return new Redactor;
}

it('passes through safe keys', function () {
    $input = ['route' => 'users.index', 'method' => 'GET'];
    expect(redactor()->redact($input))->toBe($input);
});

it('redacts a password key', function () {
    expect(redactor()->redact(['password' => 'hunter2']))
        ->toBe(['password' => '[REDACTED]']);
});

it('redacts case-insensitively', function () {
    expect(redactor()->redact(['PASSWORD' => 'x']))
        ->toBe(['PASSWORD' => '[REDACTED]']);
    expect(redactor()->redact(['Api_Key' => 'x']))
        ->toBe(['Api_Key' => '[REDACTED]']);
});

it('redacts when the sensitive word appears anywhere in the key', function () {
    expect(redactor()->redact(['user_password' => 'x']))
        ->toBe(['user_password' => '[REDACTED]']);
    expect(redactor()->redact(['auth_token_value' => 'x']))
        ->toBe(['auth_token_value' => '[REDACTED]']);
});

it('redacts nested keys recursively', function () {
    $input = [
        'user' => [
            'name' => 'Alice',
            'password' => 'hunter2',
        ],
    ];

    $expected = [
        'user' => [
            'name' => 'Alice',
            'password' => '[REDACTED]',
        ],
    ];

    expect(redactor()->redact($input))->toBe($expected);
});

it('redacts across multiple sensitive keys', function () {
    $input = [
        'password' => 'a',
        'api_key' => 'b',
        'route' => 'users.index',
    ];

    $expected = [
        'password' => '[REDACTED]',
        'api_key' => '[REDACTED]',
        'route' => 'users.index',
    ];

    expect(redactor()->redact($input))->toBe($expected);
});

it('handles an empty array', function () {
    expect(redactor()->redact([]))->toBe([]);
});
