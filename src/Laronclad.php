<?php

declare(strict_types=1);

namespace Laronclad;

use Laronclad\Analysis\RuleInterface;
use Laronclad\Analysis\ThreatAnalyzer;

/**
 * Public entry point for the package.
 *
 * Exposed through the Facade as Laronclad::status(). Reads config
 * at call time so users can override values at runtime.
 */
final readonly class Laronclad
{
    public function __construct(
        private ThreatAnalyzer $analyzer,
    ) {}

    /**
     * Return a snapshot of the current configuration and state.
     *
     * @return array{
     *     enabled: bool,
     *     mode: string,
     *     rules_count: int,
     *     rules: list<string>,
     * }
     */
    public function status(): array
    {
        return [
            'enabled' => (bool) config('laronclad.enabled', true),
            'mode' => (string) config('laronclad.mode', 'dry-run'),
            'rules_count' => count($this->analyzer->rules()),
            'rules' => array_map(
                static fn (RuleInterface $rule): string => $rule->name(),
                $this->analyzer->rules(),
            ),
        ];
    }

    /**
     * Return the rules currently loaded in the analyzer.
     *
     * @return list<RuleInterface>
     */
    public function rules(): array
    {
        return $this->analyzer->rules();
    }
}
