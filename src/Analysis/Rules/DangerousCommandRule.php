<?php

declare(strict_types=1);

namespace Laronclad\Analysis\Rules;

use Laronclad\Analysis\ConfidenceLevel;
use Laronclad\Analysis\RuleInterface;
use Laronclad\Analysis\ThreatMatch;
use Laronclad\Analysis\ThreatType;

/**
 * Detects dangerous patterns in shell commands.
 *
 * This rule looks for common destructive or pivot patterns. It is
 * not exhaustive. Legitimate maintenance scripts might use some of
 * these; that is why confidence is Medium.
 *
 * Patterns covered:
 *   - recursive rm of the root or the home directory, in any option
 *     spelling (-rf, -fr, -r -f, --recursive) and any target spelling
 *     (/, /*, ~, $HOME), also behind sudo, a path, quotes or $( )
 *   - a download (curl or wget) piped into a shell or interpreter
 *     (sh, bash, python, perl, ruby, php, node, lua), also through
 *     sudo or env, or read through <( ), $( ) or backticks by
 *     bash, sh -c, eval or source
 *   - reverse shell markers (nc, ncat or netcat with -e, sh -i,
 *     /dev/tcp/ and /dev/udp/)
 *   - world-writable permissions (chmod 777, a+rwx, o+rwx)
 *
 * The rm check reads the command word by word, because no single
 * pattern can follow every order of options and targets. Words only
 * count within one command: a separator (; & | or a newline) ends
 * it, so "rm -r build; ls /" is not flagged.
 *
 * A pattern that fails stops the rule without trying the next one.
 * A later successful call would clear the PCRE error state, and the
 * analyzer reads that state to report that this input defeated the
 * matcher.
 */
final class DangerousCommandRule implements RuleInterface
{
    private const SHELLS = '(?:(?:ba|da|z|k|c|a)?sh)';

    private const INTERPRETERS = '(?:(?:ba|da|z|k|c|a)?sh|python[0-9.]*|perl|ruby|php|node(?:js)?|lua)';

    /**
     * @var list<string>
     */
    private const PATTERNS = [
        // A download piped into a shell or interpreter, also through sudo or env.
        '/\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+(?:\S+=\S+\s+)*)?(?:\S*\/)?'.self::INTERPRETERS.'(?![\w-])/i',
        // A shell reading a download through process or command substitution.
        '/(?<!\w)'.self::SHELLS.'\s+(?:-\w+\s+)*<\(\s*(?:curl|wget)\b/i',
        '/\b(?:eval|source)\s+["\']?(?:\$\(|`|<\()\s*(?:curl|wget)\b/i',
        '/(?<!\w)'.self::SHELLS.'\s+-c\s+["\']?(?:\$\(|`)\s*(?:curl|wget)\b/i',
        // Reverse shells.
        '/\b(?:nc|ncat|netcat)(?:\.\w+)?\b[^\n]*\s(?:-[a-z]*e|--exec|--sh-exec)\s/i',
        '/(?<!\w)'.self::SHELLS.'\s+-i\b/i',
        '/\/dev\/(?:tcp|udp)\//i',
        // World-writable permissions.
        '/\bchmod\s+(?:-\w+\s+)*(?:0?777|(?:[ugo]*[ao][ugo]*)?\+rwx)\b/i',
    ];

    public function matches(string $input): ?ThreatMatch
    {
        $segments = preg_split('/[;&|\n]+/', $input);

        if ($segments === false) {
            return null;
        }

        foreach ($segments as $segment) {
            if ($this->removesRootOrHome($segment)) {
                return $this->finding();
            }
        }

        foreach (self::PATTERNS as $pattern) {
            $result = preg_match($pattern, $input);

            if ($result === false) {
                return null;
            }

            if ($result === 1) {
                return $this->finding();
            }
        }

        return null;
    }

    public function name(): string
    {
        return 'dangerous_command';
    }

    public function type(): ThreatType
    {
        return ThreatType::ProcessExecution;
    }

    public function confidence(): ConfidenceLevel
    {
        return ConfidenceLevel::Medium;
    }

    private function finding(): ThreatMatch
    {
        return new ThreatMatch(
            type: $this->type(),
            confidence: $this->confidence(),
            rule: $this->name(),
            description: 'Dangerous command pattern found',
        );
    }

    /**
     * Whether one command (no separators) runs rm recursively on the
     * root or the home directory. One pass over the words, so the
     * cost grows with the length of the command and nothing else.
     */
    private function removesRootOrHome(string $segment): bool
    {
        $tokens = preg_split('/\s+/', trim($segment), -1, PREG_SPLIT_NO_EMPTY);

        if ($tokens === false) {
            return false;
        }

        $active = false;
        $recursive = false;
        $dangerousTarget = false;
        $optionsEnded = false;

        foreach ($tokens as $token) {
            if ($this->isRm($token)) {
                $active = true;
                $recursive = false;
                $dangerousTarget = false;
                $optionsEnded = false;

                continue;
            }

            if (! $active) {
                continue;
            }

            $argument = trim($token, "()`'\"");

            if (! $optionsEnded && $argument === '--') {
                $optionsEnded = true;

                continue;
            }

            if (! $optionsEnded && str_starts_with($argument, '-')) {
                if ($argument === '--recursive' || preg_match('/^-[a-z]*r/i', $argument) === 1) {
                    $recursive = true;
                }
            } elseif ($this->isRootOrHome($argument)) {
                $dangerousTarget = true;
            }

            if ($recursive && $dangerousTarget) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a word is the rm command: rm, /bin/rm, \rm, $(rm, "rm.
     */
    private function isRm(string $token): bool
    {
        $name = ltrim($token, "\$(`'\"\\");
        $slash = strrpos($name, '/');

        if ($slash !== false) {
            $name = substr($name, $slash + 1);
        }

        return strtolower($name) === 'rm';
    }

    private function isRootOrHome(string $target): bool
    {
        return preg_match('/^\/+\*?$/D', $target) === 1
            || preg_match('/^(?:~|\$HOME|\$\{HOME\})(?:\/+\*?)?$/D', $target) === 1;
    }
}
