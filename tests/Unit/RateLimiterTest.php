<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy\Tests\Unit;

use HetznerDnsapiProxy\RateLimiter;
use PHPUnit\Framework\TestCase;

class RateLimiterTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/rate_limit_test_' . uniqid() . '.json';
    }

    protected function tearDown(): void
    {
        if (file_exists($this->path)) {
            unlink($this->path);
        }
    }

    public function testNotBlockedInitially(): void
    {
        $rl = new RateLimiter($this->path);
        $this->assertFalse($rl->isBlocked('1.2.3.4'));
    }

    public function testNotBlockedAfterFewFailures(): void
    {
        $rl = new RateLimiter($this->path);
        for ($i = 0; $i < 9; $i++) {
            $this->assertFalse($rl->recordFailure('1.2.3.4'));
        }
        $this->assertFalse($rl->isBlocked('1.2.3.4'));
    }

    public function testBlockedAfterTenFailures(): void
    {
        $rl = new RateLimiter($this->path);
        for ($i = 0; $i < 9; $i++) {
            $this->assertFalse($rl->recordFailure('1.2.3.4'));
        }
        $this->assertTrue($rl->recordFailure('1.2.3.4'));
        $this->assertTrue($rl->isBlocked('1.2.3.4'));
    }

    public function testDifferentIpsAreIndependent(): void
    {
        $rl = new RateLimiter($this->path);
        for ($i = 0; $i < 10; $i++) {
            $rl->recordFailure('1.2.3.4');
        }
        $this->assertTrue($rl->isBlocked('1.2.3.4'));
        $this->assertFalse($rl->isBlocked('5.6.7.8'));
    }

    public function testResetClearsFailures(): void
    {
        $rl = new RateLimiter($this->path);
        for ($i = 0; $i < 5; $i++) {
            $rl->recordFailure('1.2.3.4');
        }
        $rl->reset('1.2.3.4');

        // Should need another 10 failures to trigger lockout
        for ($i = 0; $i < 9; $i++) {
            $rl->recordFailure('1.2.3.4');
        }
        $this->assertFalse($rl->isBlocked('1.2.3.4'));
    }

    public function testFileDeletedWhenEmpty(): void
    {
        $rl = new RateLimiter($this->path);
        $rl->recordFailure('1.2.3.4');
        $this->assertFileExists($this->path);

        $rl->reset('1.2.3.4');
        $this->assertFileDoesNotExist($this->path);
    }
}
