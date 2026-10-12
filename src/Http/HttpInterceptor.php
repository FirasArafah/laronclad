<?php

declare(strict_types=1);

namespace Laronclad\Http;

use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Laronclad\Analysis\ThreatAnalyzer;
use Laronclad\Analysis\ThreatType;
use Laronclad\Logging\SafeLogger;

/**
 * Observes outbound HTTP requests before they leave the app.
 *
 * Laravel's HTTP client fires a global request middleware for every
 * outgoing call. We inspect the host against the SSRF rules and
 * hand matches to the logger.
 *
 * Only the host is analyzed. Paths and query strings are not
 * checked here because they are usually application-controlled and
 * not attacker-controlled in an SSRF sense.
 */
final readonly class HttpInterceptor
{
    public function __construct(
        private ThreatAnalyzer $analyzer,
        private SafeLogger $logger,
    ) {}

    /**
     * Attach the interceptor to Laravel's HTTP client.
     */
    public function register(): void
    {
        Http::globalRequestMiddleware(function (Request $request) {
            $this->inspect($request->url());

            return $request;
        });
    }

    /**
     * Inspect a single URL. Public so tests can call it directly.
     */
    public function inspect(string $url): void
    {
        $host = parse_url($url, PHP_URL_HOST);

        if (! is_string($host) || $host === '') {
            return;
        }

        $matches = $this->analyzer->analyze($host, ThreatType::Ssrf);

        foreach ($matches as $match) {
            $this->logger->log($match, [
                'host' => $host,
            ]);
        }
    }
}
