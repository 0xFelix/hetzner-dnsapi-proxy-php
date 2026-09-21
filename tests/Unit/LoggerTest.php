<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy\Tests\Unit;

use HetznerDnsapiProxy\Logger;
use PHPUnit\Framework\TestCase;

class LoggerTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/logger_test_' . uniqid() . '.log';
    }

    protected function tearDown(): void
    {
        foreach ([$this->path, $this->path . '.1'] as $file) {
            if (file_exists($file)) {
                unlink($file);
            }
        }
    }

    /** @return list<string> */
    private function lines(): array
    {
        return array_values(array_filter(explode("\n", (string) file_get_contents($this->path))));
    }

    public function testWritesSingleLine(): void
    {
        (new Logger($this->path, '127.0.0.1'))->info('plain message');

        $lines = $this->lines();
        $this->assertCount(1, $lines);
        $this->assertStringContainsString('[INFO] [127.0.0.1] plain message', $lines[0]);
    }

    public function testNewlineInMessageCannotForgeALogLine(): void
    {
        (new Logger($this->path, '127.0.0.1'))->info("auth failed for user: alice\n2000-01-01 00:00:00 [INFO] [1.2.3.4] forged");

        $lines = $this->lines();
        $this->assertCount(1, $lines);
        $this->assertStringContainsString('\n', $lines[0]);
        $this->assertStringNotContainsString("\n2000-01-01", (string) file_get_contents($this->path));
    }

    public function testControlCharactersInRemoteAddrAreEscaped(): void
    {
        (new Logger($this->path, "1.2.3.4\ninjected"))->error('boom');

        $this->assertCount(1, $this->lines());
    }

    public function testMissingClientIpFallsBackToDash(): void
    {
        (new Logger($this->path))->info('no ip');

        $this->assertStringContainsString('[-] no ip', $this->lines()[0]);
    }

    public function testErrorLevel(): void
    {
        (new Logger($this->path, '127.0.0.1'))->error('bad thing');

        $this->assertStringContainsString('[ERROR] [127.0.0.1] bad thing', $this->lines()[0]);
    }

    public function testUnwritablePathDoesNotThrowOrEmitOutput(): void
    {
        $logger = new Logger('/nonexistent-directory-' . uniqid() . '/app.log', '127.0.0.1');

        ob_start();
        $logger->info('message');
        $output = ob_get_clean();

        $this->assertSame('', $output);
    }

    public function testRotatesWhenOversized(): void
    {
        file_put_contents($this->path, str_repeat('x', 5 * 1024 * 1024));

        (new Logger($this->path, '127.0.0.1'))->info('after rotation');

        $this->assertFileExists($this->path . '.1');
        $this->assertCount(1, $this->lines());
    }

    public function testCollapsedIpv6IsLoggedAsGiven(): void
    {
        // ClientIp canonicalizes before the IP reaches the logger.
        (new Logger($this->path, '2001:db8:3c4d::1ff'))->info('hello');

        $this->assertStringContainsString('[2001:db8:3c4d::1ff] hello', $this->lines()[0]);
    }
}
