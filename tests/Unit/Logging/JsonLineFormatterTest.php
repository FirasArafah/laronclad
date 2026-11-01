<?php

declare(strict_types=1);

use Laronclad\Logging\JsonLineFormatter;
use Monolog\Level;
use Monolog\LogRecord;

function formatterRecord(string $message): LogRecord
{
    return new LogRecord(
        datetime: new DateTimeImmutable,
        channel: 'laronclad',
        level: Level::Info,
        message: $message,
    );
}

it('writes the message followed by a newline and nothing else', function () {
    $line = (new JsonLineFormatter)->format(formatterRecord('{"rule":"union_select"}'));

    expect($line)->toBe("{\"rule\":\"union_select\"}\n");
});

it('keeps one record per line even if the message has line breaks', function () {
    $line = (new JsonLineFormatter)->format(formatterRecord("a\r\nb\nc"));

    expect($line)->toBe("a  b c\n");
});

it('leaves percent sequences in the message untouched', function () {
    // Monolog's LineFormatter would strip the %context...% segment.
    $message = '{"host":"%context.x%","note":"50%"}';

    $line = (new JsonLineFormatter)->format(formatterRecord($message));

    expect($line)->toBe($message."\n");
});

it('formats a batch as consecutive lines', function () {
    $output = (new JsonLineFormatter)->formatBatch([
        formatterRecord('{"n":1}'),
        formatterRecord('{"n":2}'),
    ]);

    expect($output)->toBe("{\"n\":1}\n{\"n\":2}\n");
});