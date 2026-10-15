<?php

declare(strict_types=1);

namespace Laronclad;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\ServiceProvider;
use Laronclad\Analysis\RuleInterface;
use Laronclad\Analysis\Rules\CommentInjectionRule;
use Laronclad\Analysis\Rules\DangerousCommandRule;
use Laronclad\Analysis\Rules\MetadataEndpointRule;
use Laronclad\Analysis\Rules\PrivateIpRule;
use Laronclad\Analysis\Rules\StackedQueryRule;
use Laronclad\Analysis\Rules\TimeBasedRule;
use Laronclad\Analysis\Rules\UnionSelectRule;
use Laronclad\Analysis\ThreatAnalyzer;
use Laronclad\Console\ClearLogsCommand;
use Laronclad\Console\StatusCommand;
use Laronclad\Database\DatabaseInterceptor;
use Laronclad\Http\HttpInterceptor;
use Laronclad\Logging\Redactor;
use Laronclad\Logging\SafeLogger;
use Laronclad\Process\ProcessGuard;
use Laronclad\Support\Whitelist;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;
use Psr\Log\LoggerInterface;
use Throwable;

final class LaroncladServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/laronclad.php',
            'laronclad',
        );

        $this->app->singleton(Whitelist::class, function (): Whitelist {
            return new Whitelist(
                routes: $this->configList('laronclad.whitelist.routes'),
                commands: $this->configList('laronclad.whitelist.commands'),
            );
        });

        $this->app->singleton(ThreatAnalyzer::class, function (): ThreatAnalyzer {
            return new ThreatAnalyzer($this->defaultRules());
        });

        $this->app->singleton(Redactor::class);

        $this->app->singleton(SafeLogger::class, function ($app): SafeLogger {
            return new SafeLogger(
                logger: $this->resolveLogger(),
                redactor: $app->make(Redactor::class),
                events: $app->make(Dispatcher::class),
                deduplicationWindow: (int) config('laronclad.logging.deduplication_window', 60),
            );
        });

        $this->app->singleton(DatabaseInterceptor::class, function ($app): DatabaseInterceptor {
            return new DatabaseInterceptor(
                analyzer: $app->make(ThreatAnalyzer::class),
                logger: $app->make(SafeLogger::class),
                maxInputLength: (int) config('laronclad.database.max_input_length', 8192),
            );
        });

        $this->app->singleton(HttpInterceptor::class, function ($app): HttpInterceptor {
            return new HttpInterceptor(
                analyzer: $app->make(ThreatAnalyzer::class),
                logger: $app->make(SafeLogger::class),
            );
        });

        $this->app->singleton(ProcessGuard::class, function ($app): ProcessGuard {
            return new ProcessGuard(
                analyzer: $app->make(ThreatAnalyzer::class),
                logger: $app->make(SafeLogger::class),
            );
        });

        $this->app->singleton(Laronclad::class, function ($app): Laronclad {
            return new Laronclad($app->make(ThreatAnalyzer::class));
        });

        $this->app->alias(Laronclad::class, 'laronclad');
    }

    public function boot(): void
    {
        // Console tooling is registered before the enabled check on
        // purpose. A disabled install must still be able to run
        // laronclad:status and laronclad:clear-logs, and to publish
        // its config so it can be turned back on.
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/laronclad.php' => config_path('laronclad.php'),
            ], 'laronclad-config');

            $this->commands([
                StatusCommand::class,
                ClearLogsCommand::class,
            ]);
        }

        if (! config('laronclad.enabled', true)) {
            return;
        }

        if (config('laronclad.database.enabled', true)) {
            $this->installHook('database', function (): void {
                $this->app->make(DatabaseInterceptor::class)->register();
            });
        }

        if (config('laronclad.http.enabled', true)) {
            $this->installHook('http', function (): void {
                $this->app->make(HttpInterceptor::class)->register();
            });
        }
    }

    /**
     * Install one monitoring hook without letting a failure escape.
     *
     * Fail-open applies at boot too. If a hook cannot be attached
     * (for example the default database connection is misconfigured,
     * which DB::beforeExecuting resolves immediately), the app still
     * starts and the remaining hooks are still installed. Only the
     * exception class is reported, never its message.
     *
     * @param  callable(): void  $install
     */
    private function installHook(string $name, callable $install): void
    {
        try {
            $install();
        } catch (Throwable $e) {
            error_log('[laronclad] could not install the '.$name.' hook: '.$e::class);
        }
    }

    /**
     * @return list<RuleInterface>
     */
    private function defaultRules(): array
    {
        return [
            new UnionSelectRule,
            new CommentInjectionRule,
            new StackedQueryRule,
            new TimeBasedRule,
            new PrivateIpRule,
            new MetadataEndpointRule,
            new DangerousCommandRule,
        ];
    }

    /**
     * Read a config value and return it as a list of strings.
     *
     * Config may contain anything. This filters to strings so the
     * Whitelist always gets a proper list<string>.
     *
     * @return list<string>
     */
    private function configList(string $key): array
    {
        $value = config($key, []);

        if (! is_array($value)) {
            return [];
        }

        $result = [];

        foreach ($value as $item) {
            if (is_string($item)) {
                $result[] = $item;
            }
        }

        return $result;
    }

    private function resolveLogger(): LoggerInterface
    {
        $channel = config('laronclad.logging.channel');

        if (is_string($channel) && $channel !== '') {
            return $this->app->make('log')->channel($channel);
        }

        return new Logger('laronclad', [
            new StreamHandler(
                storage_path('logs/laronclad.log'),
                Logger::INFO,
            ),
        ]);
    }
}
