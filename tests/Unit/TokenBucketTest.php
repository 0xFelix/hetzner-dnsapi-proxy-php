<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy\Tests\Unit;

use HetznerDnsapiProxy\TokenBucket;
use PHPUnit\Framework\TestCase;

class TokenBucketTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/token_bucket_test_' . uniqid() . '.json';
    }

    protected function tearDown(): void
    {
        if (file_exists($this->path)) {
            unlink($this->path);
        }
    }

    public function testAllowsInitialRequest(): void
    {
        $tb = new TokenBucket($this->path);
        $this->assertTrue($tb->allow('1.2.3.4'));
    }

    public function testAllowsBurstRequests(): void
    {
        $tb = new TokenBucket($this->path, burst: 5);
        for ($i = 0; $i < 5; $i++) {
            $this->assertTrue($tb->allow('1.2.3.4'), "request $i should be allowed");
        }
    }

    public function testDeniesAfterBurstExhausted(): void
    {
        $tb = new TokenBucket($this->path, rps: 1.0, burst: 3);
        for ($i = 0; $i < 3; $i++) {
            $this->assertTrue($tb->allow('1.2.3.4'));
        }
        $this->assertFalse($tb->allow('1.2.3.4'));
    }

    public function testDifferentKeysAreIndependent(): void
    {
        $tb = new TokenBucket($this->path, rps: 1.0, burst: 2);
        $this->assertTrue($tb->allow('1.2.3.4'));
        $this->assertTrue($tb->allow('1.2.3.4'));
        $this->assertFalse($tb->allow('1.2.3.4'));

        $this->assertTrue($tb->allow('5.6.7.8'));
    }

    public function testRefillsOverTime(): void
    {
        $tb = new TokenBucket($this->path, rps: 100.0, burst: 2);
        $this->assertTrue($tb->allow('1.2.3.4'));
        $this->assertTrue($tb->allow('1.2.3.4'));
        $this->assertFalse($tb->allow('1.2.3.4'));

        usleep(50000); // 50ms at 100 rps = 5 tokens refilled

        $this->assertTrue($tb->allow('1.2.3.4'));
    }

    public function testIdleEntriesCleanedUp(): void
    {
        $tb = new TokenBucket($this->path, rps: 1.0, burst: 5, idleSeconds: 1);
        $tb->allow('1.2.3.4');

        sleep(2);

        $tb->allow('5.6.7.8');

        $data = json_decode((string) file_get_contents($this->path), true);
        $this->assertArrayNotHasKey('1.2.3.4', $data);
        $this->assertArrayHasKey('5.6.7.8', $data);
    }

    public function testFileDeletedWhenEmpty(): void
    {
        $tb = new TokenBucket($this->path, rps: 1.0, burst: 5, idleSeconds: 1);
        $tb->allow('1.2.3.4');
        $this->assertFileExists($this->path);

        sleep(2);

        // Allowing a key that will also become idle immediately won't work,
        // but we can verify cleanup by checking after idle expiry on next call
        $tb2 = new TokenBucket($this->path, rps: 1.0, burst: 5, idleSeconds: 0);
        $tb2->allow('5.6.7.8');

        // After cleanup of both idle entries the file should be removed
        $this->assertFileDoesNotExist($this->path);
    }
}
