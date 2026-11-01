<?php

declare(strict_types=1);

namespace Laronclad\Logging;

use Monolog\Formatter\FormatterInterface;
use Monolog\LogRecord;

/**
 * Writes each record as its message and a newline, nothing else.
 *
 * SafeLogger already builds one JSON object per finding. Monolog's
 * default line format would wrap it in a timestamp, channel, level
 * and empty brackets, which breaks tools that expect one JSON
 * document per line.
 *
 * Deliberately not Monolog's LineFormatter: that class post-processes
 * the output with a pattern that removes %context.x% and %extra.x%
 * sequences, and the message can contain attacker-controlled text.
 * This formatter touches nothing except line breaks, which cannot
 * appear in json_encode() output but are removed anyway so the one
 * record per line guarantee holds for any message.
 */
final readonly class JsonLineFormatter implements FormatterInterface
{
    public function format(LogRecord $record): string
    {
        return str_replace(["\r", "\n"], ' ', $record->message)."\n";
    }

    /**
     * @param  list<LogRecord>  $records
     */
    public function formatBatch(array $records): string
    {
        $output = '';

        foreach ($records as $record) {
            $output .= $this->format($record);
        }

        return $output;
    }
}
