<?php

declare(strict_types=1);

/*
 * Laronclad benchmarks.
 *
 *     composer bench            (or: php benchmarks/run.php)
 *     php benchmarks/run.php --json
 *
 * Two parts:
 *
 * 1. Detectors: the cost of analysing one input with the default rules,
 *    exactly as the hooks call them (same size limits). No logging.
 *
 * 2. End to end: real Laravel queries (SQLite in memory) and HTTP client
 *    calls (faked, nothing leaves the machine), timed in a fresh process
 *    with Laronclad switched off and again with it on. The difference is
 *    what an application pays per query or request.
 *
 * Every number is the median of several rounds, in microseconds per
 * operation. Results depend on the machine; compare runs on one machine.
 */

use Composer\InstalledVersions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Laronclad\Analysis\InputLimit;
use Laronclad\Analysis\ThreatAnalyzer;
use Laronclad\Analysis\ThreatType;
use Laronclad\Database\DatabaseInterceptor;
use Laronclad\LaroncladServiceProvider;
use Laronclad\Process\ProcessGuard;
use Orchestra\Testbench\Foundation\Application;

require __DIR__.'/../vendor/autoload.php';

const ROUNDS = 7;
const ROUND_SECONDS = 0.05;

/**
 * Time a callable. Returns the median and the fastest round, in
 * microseconds per call.
 *
 * @return array{median: float, min: float}
 */
function measure(callable $operation): array
{
    // Warm up, then size each round to take about ROUND_SECONDS.
    $operation();
    $iterations = 1;

    while (true) {
        $start = hrtime(true);

        for ($i = 0; $i < $iterations; $i++) {
            $operation();
        }

        $elapsed = (hrtime(true) - $start) / 1e9;

        if ($elapsed >= ROUND_SECONDS / 4 || $iterations >= 1_000_000) {
            break;
        }

        $iterations *= 4;
    }

    $iterations = max(1, (int) ceil($iterations * (ROUND_SECONDS / max($elapsed, 1e-9))));

    $perCall = [];

    for ($round = 0; $round < ROUNDS; $round++) {
        $start = hrtime(true);

        for ($i = 0; $i < $iterations; $i++) {
            $operation();
        }

        $perCall[] = (hrtime(true) - $start) / 1e3 / $iterations;
    }

    sort($perCall);

    return ['median' => $perCall[intdiv(ROUNDS, 2)], 'min' => $perCall[0]];
}

/**
 * @return array<string, array{type: ThreatType, limit: int|null, input: string}>
 */
function detectorCases(): array
{
    $sql = DatabaseInterceptor::DEFAULT_MAX_INPUT_LENGTH;
    $cmd = ProcessGuard::DEFAULT_MAX_INPUT_LENGTH;

    $orm = 'select "orders".*, "customers"."name" from "orders" '
        .'inner join "customers" on "customers"."id" = "orders"."customer_id" '
        .'where "orders"."status" in ('.implode(', ', array_fill(0, 50, '?')).') '
        .'and "orders"."created_at" >= ? order by "orders"."created_at" desc limit 50 offset 0';

    $batchInsert = 'insert into "events" ("user_id", "type", "payload", "created_at") values '
        .implode(', ', array_fill(0, 500, '(?, ?, ?, ?)'));

    $blob = fn (int $bytes): string => "insert into \"files\" (\"data\") values ('".str_repeat('a', $bytes)."')";

    return [
        'SQL: primary key lookup' => ['type' => ThreatType::SqlInjection, 'limit' => $sql,
            'input' => 'select * from "users" where "id" = ? limit 1'],
        'SQL: ORM query with join, 50 bindings' => ['type' => ThreatType::SqlInjection, 'limit' => $sql,
            'input' => $orm],
        'SQL: batch insert, 500 rows' => ['type' => ThreatType::SqlInjection, 'limit' => $sql,
            'input' => $batchInsert],
        'SQL: UNION injection' => ['type' => ThreatType::SqlInjection, 'limit' => $sql,
            'input' => "select * from users where id = '1' union select username, password from admins -- '"],
        'SQL: time-based injection' => ['type' => ThreatType::SqlInjection, 'limit' => $sql,
            'input' => 'select * from users where id = 1 and sleep(5)'],
        'SQL: 64 KB literal' => ['type' => ThreatType::SqlInjection, 'limit' => $sql,
            'input' => $blob(65_536)],
        'SQL: 1 MB literal (at the limit)' => ['type' => ThreatType::SqlInjection, 'limit' => $sql,
            'input' => $blob($sql - 64)],
        'SQL: 8 MB literal (over the limit)' => ['type' => ThreatType::SqlInjection, 'limit' => $sql,
            'input' => $blob(8 * $sql)],
        'SQL: 1 MB of quotes and comment markers' => ['type' => ThreatType::SqlInjection, 'limit' => $sql,
            'input' => substr(str_repeat("' or '1'='1' /* -- # ", 60_000), 0, $sql)],
        'Host: public domain' => ['type' => ThreatType::Ssrf, 'limit' => null,
            'input' => 'api.stripe.com'],
        'Host: public IPv4' => ['type' => ThreatType::Ssrf, 'limit' => null,
            'input' => '93.184.216.34'],
        'Host: private IPv4' => ['type' => ThreatType::Ssrf, 'limit' => null,
            'input' => '10.0.0.5'],
        'Host: metadata, decimal form' => ['type' => ThreatType::Ssrf, 'limit' => null,
            'input' => '2852039166'],
        'Host: metadata, IPv4-in-IPv6' => ['type' => ThreatType::Ssrf, 'limit' => null,
            'input' => '[::ffff:169.254.169.254]'],
        'Host: 253-character name' => ['type' => ThreatType::Ssrf, 'limit' => null,
            'input' => implode('.', array_fill(0, 4, str_repeat('a', 62))).'.c'],
        'Command: git status' => ['type' => ThreatType::ProcessExecution, 'limit' => $cmd,
            'input' => 'git status --porcelain'],
        'Command: curl piped to sh' => ['type' => ThreatType::ProcessExecution, 'limit' => $cmd,
            'input' => 'curl -fsSL https://example.com/install.sh | sh'],
        'Command: 8 KB of arguments (at the limit)' => ['type' => ThreatType::ProcessExecution, 'limit' => $cmd,
            'input' => 'convert '.substr(str_repeat('image-0001.png ', 600), 0, $cmd - 8)],
        'Command: 1 MB (over the limit)' => ['type' => ThreatType::ProcessExecution, 'limit' => $cmd,
            'input' => 'convert '.str_repeat('image-0001.png ', 70_000)],
    ];
}

/**
 * @return list<array{case: string, bytes: int, findings: int, median: float, min: float}>
 */
function runDetectors(ThreatAnalyzer $analyzer): array
{
    $results = [];

    foreach (detectorCases() as $name => $case) {
        $run = $case['limit'] === null
            ? fn (): array => $analyzer->analyze($case['input'], $case['type'])
            : fn (): array => InputLimit::analyze($analyzer, $case['input'], $case['limit'], $case['type']);

        $timing = measure($run);

        $results[] = [
            'case' => $name,
            'bytes' => strlen($case['input']),
            'findings' => count($run()),
        ] + $timing;
    }

    return $results;
}

/**
 * Boot a minimal Laravel app with Laronclad on or off.
 */
function bootApp(bool $enabled): Illuminate\Foundation\Application
{
    $env = [
        'LARONCLAD_ENABLED' => $enabled ? 'true' : 'false',
        'DB_CONNECTION' => 'testing',
        // Benign operations produce no findings, so this only matters
        // for the attack case, which must pay for a log write each time.
        'LARONCLAD_LOG_DEDUP_WINDOW' => '0',
    ];

    // Laravel reads $_SERVER and $_ENV before getenv(), and a child
    // process inherits the parent's environment, so set all three.
    foreach ($env as $key => $value) {
        putenv("{$key}={$value}");
        $_ENV[$key] = $value;
        $_SERVER[$key] = $value;
    }

    return Application::create(options: [
        'extra' => ['providers' => [LaroncladServiceProvider::class], 'dont-discover' => ['*']],
    ]);
}

/**
 * Child process: time end-to-end operations with Laronclad on or off.
 *
 * @return array<string, array{median: float, min: float}>
 */
function runEndToEnd(bool $enabled): array
{
    $app = bootApp($enabled);

    // Findings go to the default JSON lines file of the Testbench app.
    // Start empty: the test suite writes to the same file.
    $log = storage_path('logs/laronclad.log');
    @unlink($log);

    DB::statement('create table "users" ("id" integer primary key, "name" text, "email" text)');

    for ($i = 1; $i <= 100; $i++) {
        DB::insert('insert into "users" ("id", "name", "email") values (?, ?, ?)', [$i, "user {$i}", "u{$i}@example.com"]);
    }

    Http::fake(['*' => Http::response('ok')]);

    $results = [
        'Raw query: select by id' => measure(fn () => DB::select('select * from "users" where "id" = ?', [42])),
        'Query builder: where + first' => measure(fn () => DB::table('users')->where('email', 'u42@example.com')->first()),
        'Query builder: insert' => measure(fn () => DB::table('users')->insert(['name' => 'n', 'email' => 'e'])),
        'HTTP client: GET (faked)' => measure(fn () => Http::get('https://api.example.com/v1/items')),
    ];

    // Worst case: every query is a finding, fires the event and is
    // written to the log (deduplication is off in this process).
    $results['Attack query, logged every time'] = measure(
        fn () => DB::select("select * from \"users\" where \"id\" = '1' union select 1, 2, 3"),
    );

    // Guard against measuring nothing: with Laronclad on, the attack
    // query must have been logged; with it off, nothing may be.
    $logged = is_file($log) ? count(file($log) ?: []) : 0;
    @unlink($log);

    if ($enabled !== ($logged > 0)) {
        fwrite(STDERR, 'Sanity check failed: Laronclad '.($enabled ? 'on' : 'off')." wrote {$logged} log lines.\n");
        exit(1);
    }

    return $results;
}

/**
 * Run the end-to-end child in a fresh PHP process, so the on and off
 * measurements never share state.
 *
 * @return array<string, array{median: float, min: float}>
 */
function spawnEndToEnd(bool $enabled): array
{
    $command = escapeshellarg(PHP_BINARY).' '.escapeshellarg(__FILE__).' --child='.($enabled ? 'on' : 'off');
    $output = shell_exec($command);
    $decoded = is_string($output) ? json_decode($output, true) : null;

    if (! is_array($decoded)) {
        fwrite(STDERR, "End-to-end child failed:\n".(string) $output."\n");
        exit(1);
    }

    return $decoded;
}

/**
 * @return array<string, string>
 */
function environment(): array
{
    $version = InstalledVersions::getPrettyVersion('firasarafah/laronclad') ?? 'unknown';
    $reference = InstalledVersions::getReference('firasarafah/laronclad');

    return [
        'Laronclad' => $version.($reference !== null ? ' ('.substr($reference, 0, 7).')' : ''),
        'PHP' => PHP_VERSION.' ('.PHP_OS_FAMILY.(PHP_ZTS ? ', ZTS' : ', NTS').')',
        'Laravel' => Illuminate\Foundation\Application::VERSION,
        'OPcache CLI' => (extension_loaded('Zend OPcache') && ini_get('opcache.enable_cli')) ? 'on' : 'off',
        'JIT' => (extension_loaded('Zend OPcache') && ini_get('opcache.jit') && ini_get('opcache.jit') !== 'disable') ? (string) ini_get('opcache.jit') : 'off',
        'Xdebug' => extension_loaded('xdebug') ? 'LOADED (numbers are not representative)' : 'off',
        'PCRE JIT' => ini_get('pcre.jit') ? 'on' : 'off',
    ];
}

function us(float $value): string
{
    return $value >= 1000 ? number_format($value / 1000, 2).' ms' : number_format($value, 1).' µs';
}

function bytes(int $value): string
{
    return match (true) {
        $value >= 1_048_576 => number_format($value / 1_048_576, 1).' MB',
        $value >= 1024 => number_format($value / 1024, 1).' KB',
        default => $value.' B',
    };
}

// Child mode.
foreach ($argv as $argument) {
    if (str_starts_with($argument, '--child=')) {
        echo json_encode(runEndToEnd($argument === '--child=on'), JSON_THROW_ON_ERROR);
        exit(0);
    }
}

$asJson = in_array('--json', $argv, true);

$analyzer = bootApp(true)->make(ThreatAnalyzer::class);
$detectors = runDetectors($analyzer);

// Alternate off and on twice, and keep the faster run of each, to damp
// noise from the machine.
$off = [spawnEndToEnd(false), spawnEndToEnd(false)];
$on = [spawnEndToEnd(true), spawnEndToEnd(true)];

$endToEnd = [];

foreach ($on[0] as $name => $_) {
    $onMedian = min($on[0][$name]['median'], $on[1][$name]['median']);
    $offMedian = isset($off[0][$name]) ? min($off[0][$name]['median'], $off[1][$name]['median']) : null;

    $endToEnd[] = [
        'case' => $name,
        'off' => $offMedian,
        'on' => $onMedian,
        'overhead' => $offMedian === null ? null : $onMedian - $offMedian,
    ];
}

if ($asJson) {
    echo json_encode([
        'environment' => environment(),
        'detectors' => $detectors,
        'end_to_end' => $endToEnd,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR).PHP_EOL;

    exit(0);
}

echo "## Environment\n\n";

foreach (environment() as $key => $value) {
    echo "- {$key}: {$value}\n";
}

echo "\n## Detectors (analysis only, per input)\n\n";
echo "| Input | Size | Findings | Median | Fastest |\n|---|--:|--:|--:|--:|\n";

foreach ($detectors as $row) {
    echo "| {$row['case']} | ".bytes($row['bytes'])." | {$row['findings']} | ".us($row['median']).' | '.us($row['min'])." |\n";
}

echo "\n## End to end (per operation, Laronclad off vs on)\n\n";
echo "| Operation | Off | On | Overhead |\n|---|--:|--:|--:|\n";

foreach ($endToEnd as $row) {
    $offText = $row['off'] === null ? 'n/a' : us($row['off']);
    $overhead = $row['overhead'] === null
        ? 'n/a'
        : us($row['overhead']).' ('.number_format($row['overhead'] / $row['off'] * 100, 0).'%)';

    echo "| {$row['case']} | {$offText} | ".us($row['on'])." | {$overhead} |\n";
}
