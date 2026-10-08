<?php

declare(strict_types=1);

/*
 * Pest configuration.
 *
 * Every test under tests/ uses the package TestCase, which boots
 * Orchestra Testbench with the Laronclad provider registered.
 */

use Laronclad\Tests\TestCase;

uses(TestCase::class)->in(__DIR__);
