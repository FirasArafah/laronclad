<?php

declare(strict_types=1);

namespace Laronclad\Console;

use Illuminate\Console\Command;

/**
 * Truncates the default Laronclad log file.
 *
 * Custom channels are not cleared: we do not know how to talk to
 * them, and we do not want to guess.
 */
final class ClearLogsCommand extends Command
{
    /**
     * @var string
     */
    protected $signature = 'laronclad:clear-logs';

    /**
     * @var string
     */
    protected $description = 'Clear the Laronclad log file';

    public function handle(): int
    {
        $channel = config('laronclad.logging.channel');

        if (is_string($channel) && $channel !== '') {
            $this->warn('A custom log channel is configured ('.$channel.').');
            $this->warn('Clear it using the tools provided by that channel.');

            return self::SUCCESS;
        }

        $path = storage_path('logs/laronclad.log');

        if (! file_exists($path)) {
            $this->info('No log file found at '.$path);

            return self::SUCCESS;
        }

        if (file_put_contents($path, '') === false) {
            $this->error('Failed to clear the log file.');

            return self::FAILURE;
        }

        $this->info('Cleared: '.$path);

        return self::SUCCESS;
    }
}
