<?php

declare(strict_types=1);

namespace Laronclad\Http;

use Illuminate\Support\Facades\Http;
use Laronclad\Analysis\InputLimit;
use Laronclad\Analysis\ThreatAnalyzer;
use Laronclad\Analysis\ThreatType;
use Laronclad\Logging\SafeLogger;
use Psr\Http\Message\RequestInterface;
use Throwable;

/**
 * Observes outbound HTTP requests before they leave the app.
 *
 * Laravel's HTTP client runs global request middleware for every
 * outgoing call. The middleware receives a PSR-7 request, not
 * Laravel's own Request wrapper. We inspect the host against the
 * SSRF rules and hand matches to the logger.
 *
 * Only the host is analyzed. Paths and query strings are not
 * checked here because they are usually application-controlled and
 * not attacker-controlled in an SSRF sense.
 *
 * A host longer than 255 characters cannot be a valid hostname or
 * IP literal, so it is reported as an "oversized_input" finding
 * instead of being matched. Only its length is logged.
 *
 * Fail-open: any failure inside inspection is swallowed. A
 * monitoring tool must never break the application's own requests.
 */
final readonly class HttpInterceptor
{
    private const MAX_HOST_LENGTH = 255;

    public function __construct(
        private ThreatAnalyzer $analyzer,
        private SafeLogger $logger,
    ) {}

    /**
     * Attach the interceptor to Laravel's HTTP client.
     */
    public function register(): void
    {
        Http::globalRequestMiddleware(function (RequestInterface $request): RequestInterface {
            $this->inspect((string) $request->getUri());

            return $request;
        });
    }

    /**
     * Inspect a single URL. Public so tests can call it directly.
     *
     * Never throws. Failures are reported to PHP's error log with
     * the exception class only, so no URL or input leaks into logs.
     */
    public function inspect(string $url): void
    {
        try {
            $host = parse_url($url, PHP_URL_HOST);

            if (! is_string($host) || $host === '') {
                return;
            }

            if (strlen($host) > self::MAX_HOST_LENGTH) {
                $this->logger->log(InputLimit::oversizedFinding(ThreatType::Ssrf), [
                    'host_length' => strlen($host),
                ]);

                return;
            }

            $matches = $this->analyzer->analyze($host, ThreatType::Ssrf);

            foreach ($matches as $match) {
                $this->logger->log($match, [
                    'host' => $host,
                ]);
            }
        } catch (Throwable $e) {
            error_log('[laronclad] http inspection failed: '.$e::class);
        }
    }
}
