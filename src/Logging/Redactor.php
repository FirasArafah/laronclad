<?php

declare(strict_types=1);

namespace Laronclad\Logging;

/**
 * Removes sensitive values from a context array before logging.
 *
 * The default policy redacts any value whose key contains a known
 * sensitive word (password, token, secret, etc.). This is a key-
 * based check, not a value-based one: we do not scan for JWT-like
 * strings or credit card numbers, because that leads to false
 * positives and higher CPU cost.
 *
 * The redactor operates recursively. Nested arrays are walked and
 * any sensitive key at any depth is replaced.
 *
 * This is defense in depth. Interceptors already avoid attaching
 * sensitive values to context. The redactor catches mistakes.
 */
final readonly class Redactor
{
    /**
     * Substrings that mark a key as sensitive. The check is
     * case-insensitive and matches anywhere in the key, so
     * "user_password", "auth_token", and "API_KEY" all match.
     *
     * @var list<string>
     */
    private const SENSITIVE_KEY_PARTS = [
        'password',
        'passwd',
        'secret',
        'token',
        'api_key',
        'apikey',
        'authorization',
        'cookie',
        'session',
        'csrf',
        'private_key',
        'credit_card',
    ];

    private const REPLACEMENT = '[REDACTED]';

    /**
     * @param  array<array-key, mixed>  $context
     * @return array<array-key, mixed>
     */
    public function redact(array $context): array
    {
        $redacted = [];

        foreach ($context as $key => $value) {
            if (is_string($key) && $this->isSensitiveKey($key)) {
                $redacted[$key] = self::REPLACEMENT;

                continue;
            }

            if (is_array($value)) {
                $redacted[$key] = $this->redact($value);

                continue;
            }

            $redacted[$key] = $value;
        }

        return $redacted;
    }

    private function isSensitiveKey(string $key): bool
    {
        $needle = strtolower($key);

        foreach (self::SENSITIVE_KEY_PARTS as $part) {
            if (str_contains($needle, $part)) {
                return true;
            }
        }

        return false;
    }
}
