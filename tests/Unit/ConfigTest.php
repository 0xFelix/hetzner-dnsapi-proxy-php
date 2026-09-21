<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy\Tests\Unit;

use HetznerDnsapiProxy\Config;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class ConfigTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/hetzner-dnsapi-proxy-php-test-' . uniqid();
        mkdir($this->tmpDir);
    }

    protected function tearDown(): void
    {
        array_map('unlink', glob($this->tmpDir . '/*') ?: []);
        rmdir($this->tmpDir);
    }

    /** @param array<string, mixed> $config */
    private function writeConfig(array $config): string
    {
        $path = $this->tmpDir . '/config.php';
        file_put_contents($path, '<?php return ' . var_export($config, true) . ';');
        return $path;
    }

    public function testLoadValidConfig(): void
    {
        $path = $this->writeConfig([
            'token' => 'test-token',
            'record_ttl' => 120,
            'users' => [
                ['username' => 'alice', 'password' => 'secret', 'domains' => ['example.com']],
            ],
        ]);

        $config = Config::load($path);

        $this->assertSame('test-token', $config->token);
        $this->assertSame(120, $config->recordTtl);
        $this->assertCount(1, $config->users);
        $this->assertSame('alice', $config->users[0]['username']);
    }

    public function testDefaultTtl(): void
    {
        $path = $this->writeConfig([
            'token' => 'test-token',
            'users' => [
                ['username' => 'alice', 'password' => 'secret', 'domains' => ['example.com']],
            ],
        ]);

        $config = Config::load($path);
        $this->assertSame(60, $config->recordTtl);
    }

    public function testMissingFile(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Config::load('/nonexistent/config.php');
    }

    public function testMissingToken(): void
    {
        $path = $this->writeConfig([
            'users' => [
                ['username' => 'alice', 'password' => 'secret', 'domains' => ['example.com']],
            ],
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('token is required');
        Config::load($path);
    }

    public function testEmptyUsers(): void
    {
        $path = $this->writeConfig([
            'token' => 'test-token',
            'users' => [],
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('at least one user');
        Config::load($path);
    }

    public function testDefaultEndpoints(): void
    {
        $path = $this->writeConfig([
            'token' => 'test-token',
            'users' => [
                ['username' => 'alice', 'password' => 'secret', 'domains' => ['example.com']],
            ],
        ]);

        $config = Config::load($path);
        $this->assertSame(Config::ENDPOINTS, $config->endpoints);
    }

    public function testCustomEndpoints(): void
    {
        $path = $this->writeConfig([
            'token' => 'test-token',
            'endpoints' => ['plain'],
            'users' => [
                ['username' => 'alice', 'password' => 'secret', 'domains' => ['example.com']],
            ],
        ]);

        $config = Config::load($path);
        $this->assertSame(['plain'], $config->endpoints);
    }

    public function testInvalidEndpoint(): void
    {
        $path = $this->writeConfig([
            'token' => 'test-token',
            'endpoints' => ['plain', 'bogus'],
            'users' => [
                ['username' => 'alice', 'password' => 'secret', 'domains' => ['example.com']],
            ],
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('invalid endpoints');
        Config::load($path);
    }

    public function testInvalidUser(): void
    {
        $path = $this->writeConfig([
            'token' => 'test-token',
            'users' => [
                ['username' => 'alice'],
            ],
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('user at index 0');
        Config::load($path);
    }

    public function testDuplicateUsername(): void
    {
        $path = $this->writeConfig([
            'token' => 'test-token',
            'users' => [
                ['username' => 'alice', 'password' => 'secret', 'domains' => ['example.com']],
                ['username' => 'alice', 'password' => 'other', 'domains' => ['other.org']],
            ],
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('duplicate username');
        Config::load($path);
    }

    public function testZeroStringCredentialsAreAccepted(): void
    {
        // empty("0") is true, so a naive check would reject these as missing.
        $path = $this->writeConfig([
            'token' => '0',
            'users' => [
                ['username' => '0', 'password' => '0', 'domains' => ['example.com']],
            ],
        ]);

        $config = Config::load($path);

        $this->assertSame('0', $config->token);
        $this->assertSame('0', $config->users[0]['username']);
        $this->assertSame('0', $config->users[0]['password']);
    }

    public function testPlaceholderTokenIsRejected(): void
    {
        $path = $this->writeConfig([
            'token' => 'YOUR_HETZNER_CLOUD_API_TOKEN',
            'users' => [
                ['username' => 'alice', 'password' => 'secret', 'domains' => ['example.com']],
            ],
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('placeholder');
        Config::load($path);
    }

    public function testNonArrayEndpointsIsRejected(): void
    {
        $path = $this->writeConfig([
            'token' => 'test-token',
            'endpoints' => 'plain',
            'users' => [
                ['username' => 'alice', 'password' => 'secret', 'domains' => ['example.com']],
            ],
        ]);

        // Used to surface as a raw TypeError from array_diff(), i.e. a bare 500.
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('endpoints must be a list of strings');
        Config::load($path);
    }

    public function testNonStringDomainIsRejected(): void
    {
        $path = $this->writeConfig([
            'token' => 'test-token',
            'users' => [
                ['username' => 'alice', 'password' => 'secret', 'domains' => [123]],
            ],
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('non-string domain');
        Config::load($path);
    }

    public function testEmptyDomainsIsRejected(): void
    {
        $path = $this->writeConfig([
            'token' => 'test-token',
            'users' => [
                ['username' => 'alice', 'password' => 'secret', 'domains' => []],
            ],
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('non-empty domains list');
        Config::load($path);
    }

    public function testNonNumericRateLimitIsRejected(): void
    {
        $path = $this->writeConfig([
            'token' => 'test-token',
            'rate_limit_rps' => 'fast',
            'users' => [
                ['username' => 'alice', 'password' => 'secret', 'domains' => ['example.com']],
            ],
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('rate_limit_rps must be a number');
        Config::load($path);
    }

    public function testNegativeLockoutIsRejected(): void
    {
        $path = $this->writeConfig([
            'token' => 'test-token',
            'lockout_max_attempts' => 0,
            'users' => [
                ['username' => 'alice', 'password' => 'secret', 'domains' => ['example.com']],
            ],
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('lockout_max_attempts must be > 0');
        Config::load($path);
    }

    public function testConfiguredDomainsAreNormalized(): void
    {
        $path = $this->writeConfig([
            'token' => 'test-token',
            'users' => [
                ['username' => 'alice', 'password' => 'secret', 'domains' => ['Example.COM', '*.Example.COM']],
            ],
        ]);

        $config = Config::load($path);

        $this->assertSame(['example.com', '*.example.com'], $config->users[0]['domains']);
    }
}
