<?php

declare(strict_types=1);

use Illuminate\Console\Events\CommandFinished;
use Illuminate\Console\Events\CommandStarting;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Laronclad\Analysis\Rules\DangerousCommandRule;
use Laronclad\Analysis\Rules\PrivateIpRule;
use Laronclad\Analysis\Rules\UnionSelectRule;
use Laronclad\Analysis\ThreatAnalyzer;
use Laronclad\Database\DatabaseInterceptor;
use Laronclad\Events\ThreatDetected;
use Laronclad\Http\HttpInterceptor;
use Laronclad\Logging\Redactor;
use Laronclad\Logging\SafeLogger;
use Laronclad\Process\ProcessGuard;
use Laronclad\Support\MonitoringScope;
use Laronclad\Support\Whitelist;
use Psr\Log\AbstractLogger;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\NullOutput;

final class WiringSpyLogger extends AbstractLogger
{
    /** @var list<string> */
    public array $messages = [];

    public function log($level, string|Stringable $message, array $context = []): void
    {
        $this->messages[] = (string) $message;
    }
}

/**
 * @param  list<string>  $routes
 * @param  list<string>  $commands
 */
function wiringScope(array $routes = [], array $commands = []): MonitoringScope
{
    return new MonitoringScope(
        static fn (): Whitelist => new Whitelist(routes: $routes, commands: $commands),
    );
}

function wiringLogger(WiringSpyLogger $spy): SafeLogger
{
    return new SafeLogger($spy, new Redactor, deduplicationWindow: 0, requestContext: null);
}

function bindWiringRequest(string $routeName): void
{
    $route = (new Route('GET', 'x', static fn () => null))->name($routeName);

    $request = Request::create('/x');
    $request->setRouteResolver(static fn (): Route => $route);

    app()->instance('request', $request);
}

/**
 * Starts collecting the rule of every ThreatDetected event.
 *
 * @return ArrayObject<int, string>
 */
function collectWiringRules(): ArrayObject
{
    // Deduplication state must not hide a finding from this test.
    Cache::flush();

    /** @var ArrayObject<int, string> $rules */
    $rules = new ArrayObject;

    Event::listen(ThreatDetected::class, function (ThreatDetected $event) use ($rules): void {
        $rules->append($event->match->rule);
    });

    return $rules;
}

it('skips database inspection inside a whitelisted command only', function () {
    $spy = new WiringSpyLogger;
    $scope = wiringScope(commands: ['migrate']);

    $interceptor = new DatabaseInterceptor(
        analyzer: new ThreatAnalyzer([new UnionSelectRule]),
        logger: wiringLogger($spy),
        scope: $scope,
    );

    $scope->enterCommand('migrate');
    $interceptor->inspect('SELECT 1 UNION SELECT 2');

    expect($spy->messages)->toBe([]);

    $scope->leaveCommand('migrate');
    $interceptor->inspect('SELECT 1 UNION SELECT 2');

    expect($spy->messages)->toHaveCount(1);
});

it('keeps inspecting queries inside a command that is not whitelisted', function () {
    $spy = new WiringSpyLogger;
    $scope = wiringScope(commands: ['migrate']);

    $interceptor = new DatabaseInterceptor(
        analyzer: new ThreatAnalyzer([new UnionSelectRule]),
        logger: wiringLogger($spy),
        scope: $scope,
    );

    $scope->enterCommand('queue:work');
    $interceptor->inspect('SELECT 1 UNION SELECT 2');

    expect($spy->messages)->toHaveCount(1);
});

it('skips outbound request inspection inside a whitelisted command only', function () {
    $spy = new WiringSpyLogger;
    $scope = wiringScope(commands: ['sync:remote']);

    $interceptor = new HttpInterceptor(
        analyzer: new ThreatAnalyzer([new PrivateIpRule]),
        logger: wiringLogger($spy),
        scope: $scope,
    );

    $scope->enterCommand('sync:remote');
    $interceptor->inspect('http://192.168.1.1/');

    expect($spy->messages)->toBe([]);

    $scope->leaveCommand('sync:remote');
    $interceptor->inspect('http://192.168.1.1/');

    expect($spy->messages)->toHaveCount(1);
});

it('skips process inspection inside a whitelisted command only', function () {
    $spy = new WiringSpyLogger;
    $scope = wiringScope(commands: ['cleanup']);

    $guard = new ProcessGuard(
        analyzer: new ThreatAnalyzer([new DangerousCommandRule]),
        logger: wiringLogger($spy),
        scope: $scope,
    );

    $scope->enterCommand('cleanup');
    $guard->inspect('rm -rf /');

    expect($spy->messages)->toBe([]);

    $scope->leaveCommand('cleanup');
    $guard->inspect('rm -rf /');

    expect($spy->messages)->toHaveCount(1);
});

it('tracks the running artisan command through the console events', function () {
    config()->set('laronclad.whitelist.commands', ['migrate']);

    $scope = app(MonitoringScope::class);
    $events = app(Dispatcher::class);

    expect($scope->isExcluded())->toBeFalse();

    $events->dispatch(new CommandStarting('migrate', new ArrayInput([]), new NullOutput));

    expect($scope->isExcluded())->toBeTrue();

    $events->dispatch(new CommandFinished('migrate', new ArrayInput([]), new NullOutput, 0));

    expect($scope->isExcluded())->toBeFalse();
});

it('applies whitelist changes made after the first check', function () {
    $scope = app(MonitoringScope::class);
    $scope->enterCommand('migrate');

    config()->set('laronclad.whitelist.commands', ['migrate']);
    expect($scope->isExcluded())->toBeTrue();

    config()->set('laronclad.whitelist.commands', []);
    expect($scope->isExcluded())->toBeFalse();

    config()->set('laronclad.whitelist.commands', ['other', 'migrate']);
    expect($scope->isExcluded())->toBeTrue();

    $scope->leaveCommand('migrate');
});

it('builds the whitelist once while its config is unchanged', function () {
    config()->set('laronclad.whitelist.commands', ['migrate']);

    $builds = 0;
    app()->bind(Whitelist::class, function () use (&$builds): Whitelist {
        $builds++;

        return new Whitelist(commands: ['migrate']);
    });

    $scope = app(MonitoringScope::class);

    for ($i = 0; $i < 5; $i++) {
        $scope->isExcluded();
    }

    expect($builds)->toBe(1);

    config()->set('laronclad.whitelist.commands', ['migrate', 'seed']);
    $scope->isExcluded();

    expect($builds)->toBe(2);
});

it('labels findings from an artisan command with the command, not the placeholder request', function () {
    Cache::flush();

    /** @var ArrayObject<int, array<array-key, mixed>> $contexts */
    $contexts = new ArrayObject;

    Event::listen(ThreatDetected::class, function (ThreatDetected $event) use ($contexts): void {
        $contexts->append($event->context);
    });

    // What Laravel binds for console runs.
    app()->instance('request', Request::create('http://localhost', 'GET'));

    $events = app(Dispatcher::class);
    $events->dispatch(new CommandStarting('queue:work', new ArrayInput([]), new NullOutput));

    Http::fake();
    Http::get('http://192.168.1.1/');

    $events->dispatch(new CommandFinished('queue:work', new ArrayInput([]), new NullOutput, 0));

    expect($contexts->getArrayCopy())->toBe([
        ['host' => '192.168.1.1', 'command' => 'queue:work'],
    ]);
});

it('does not inspect queries of a whitelisted route', function () {
    config()->set('laronclad.whitelist.routes', ['admin.*']);
    $rules = collectWiringRules();

    bindWiringRequest('admin.users.index');
    DB::select('select 1 union select 2');

    expect($rules->getArrayCopy())->toBe([]);

    bindWiringRequest('public.home');
    DB::select('select 1 union select 2');

    expect($rules->getArrayCopy())->toBe(['union_select']);
})->skip(! extension_loaded('pdo_sqlite'), 'pdo_sqlite is required');

it('does not inspect outbound requests of a whitelisted route', function () {
    config()->set('laronclad.whitelist.routes', ['admin.*']);
    $rules = collectWiringRules();

    Http::fake();

    bindWiringRequest('admin.sync');
    Http::get('http://192.168.1.1/');

    expect($rules->getArrayCopy())->toBe([]);

    bindWiringRequest('public.home');
    Http::get('http://192.168.1.1/');

    expect($rules->getArrayCopy())->toBe(['private_ip']);
});
