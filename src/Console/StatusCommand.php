<?php

declare(strict_types=1);

namespace Laronclad\Console;

use Illuminate\Console\Command;
use Laronclad\Laronclad;

/**
 * Prints the current Laronclad state.
 */
final class StatusCommand extends Command
{
    /**
     * @var string
     */
    protected $signature = 'laronclad:status';

    /**
     * @var string
     */
    protected $description = 'Show the current Laronclad status';

    public function handle(Laronclad $laronclad): int
    {
        $status = $laronclad->status();

        $this->table(
            ['Key', 'Value'],
            [
                ['Enabled', $status['enabled'] ? 'yes' : 'no'],
                ['Mode', $status['mode']],
                ['Rules', (string) $status['rules_count']],
                ['Log channel', (string) (config('laronclad.logging.channel') ?: 'default (laronclad.log)')],
                ['Deduplication', ((int) config('laronclad.logging.deduplication_window', 60)).'s'],
            ],
        );

        if ($status['rules'] !== []) {
            $this->newLine();
            $this->line('Registered rules:');

            foreach ($status['rules'] as $name) {
                $this->line('  - '.$name);
            }
        }

        return self::SUCCESS;
    }
}
