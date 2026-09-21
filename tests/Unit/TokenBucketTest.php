<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy\Tests\Unit;

use HetznerDnsapiProxy\JsonStore;
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
        $this->assertIsArray($data);
        $this->assertArrayNotHasKey('1.2.3.4', $data);
        $this->assertArrayHasKey('5.6.7.8', $data);
    }

    public function testFileTruncatedWhenEmpty(): void
    {
        $tb = new TokenBucket($this->path, rps: 1.0, burst: 5, idleSeconds: 1);
        $tb->allow('1.2.3.4');
        $this->assertFileExists($this->path);

        sleep(2);

        $tb2 = new TokenBucket($this->path, rps: 1.0, burst: 5, idleSeconds: 0);
        $tb2->allow('5.6.7.8');

        // Both entries are idle and cleaned up, so the map is empty. The file is
        // kept and emptied, never unlinked - see JsonStore.
        $this->assertFileExists($this->path);
        $this->assertSame('', (string) file_get_contents($this->path));
    }

    public function testEvictsOldestEntriesOverCap(): void
    {
        $tb = new TokenBucket($this->path, rps: 1.0, burst: 5, idleSeconds: 3600);

        // Seed just over the cap, all recent enough to survive idle cleanup so
        // that the cap - not the idle policy - is what does the evicting.
        $now = microtime(true);
        $over = JsonStore::MAX_ENTRIES + 10;
        $entries = [];
        for ($i = 0; $i < $over; $i++) {
            $entries['10.0.' . intdiv($i, 256) . '.' . ($i % 256)] = [
                'tokens' => 5.0,
                'last' => $now - ($over - $i) * 0.001,
            ];
        }
        file_put_contents($this->path, (string) json_encode($entries));

        $tb->allow('192.0.2.1');

        $data = json_decode((string) file_get_contents($this->path), true);
        $this->assertIsArray($data);
        $this->assertCount(JsonStore::MAX_ENTRIES, $data);
        // Lowest 'last' values are dropped first; 192.0.2.1 has the newest.
        $this->assertArrayNotHasKey('10.0.0.0', $data);
        $this->assertArrayHasKey('192.0.2.1', $data);
    }

    public function testCorruptStateFileIsTolerated(): void
    {
        file_put_contents($this->path, 'not json at all');

        $tb = new TokenBucket($this->path, rps: 1.0, burst: 2);

        $this->assertTrue($tb->allow('1.2.3.4'));
    }

    public function testMalformedEntryIsDiscarded(): void
    {
        file_put_contents($this->path, (string) json_encode([
            '1.2.3.4' => ['tokens' => 'plenty', 'last' => null],
        ]));

        $tb = new TokenBucket($this->path, rps: 1.0, burst: 2);

        // The bogus entry is dropped and the client starts from a fresh bucket.
        $this->assertTrue($tb->allow('1.2.3.4'));
        $this->assertTrue($tb->allow('1.2.3.4'));
        $this->assertFalse($tb->allow('1.2.3.4'));
    }
}
