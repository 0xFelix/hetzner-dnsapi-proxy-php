<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy\Tests;

use HetznerDnsapiProxy\Auth;
use HetznerDnsapiProxy\Config;
use HetznerDnsapiProxy\Logger;
use HetznerDnsapiProxy\RateLimiter;
use PHPUnit\Framework\TestCase;

abstract class HandlerTestCase extends TestCase
{
    protected Auth $auth;
    protected MockDnsService $dns;
    protected Logger $log;
    protected RateLimiter $rateLimiter;
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/hetzner-dnsapi-proxy-php-test-' . uniqid();
        mkdir($this->tmpDir);

        $path = $this->tmpDir . '/config.php';
        file_put_contents($path, '<?php return ' . var_export([
            'token' => 'test-token',
            'record_ttl' => 60,
            'users' => [
                [
                    'username' => 'alice',
                    'password' => 'secret',
                    'domains' => ['example.com', '*.example.com'],
                ],
            ],
        ], true) . ';');

        $config = Config::load($path);
        $this->auth = new Auth($config);
        $this->dns = new MockDnsService();
        $this->log = new Logger($this->tmpDir . '/test.log');
        $this->rateLimiter = new RateLimiter($this->tmpDir . '/rate_limit.json');

        // Reset superglobals
        $_GET = [];
        $_SERVER['PHP_AUTH_USER'] = '';
        $_SERVER['PHP_AUTH_PW'] = '';
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        unset($_SERVER['HTTP_X_API_USER'], $_SERVER['HTTP_X_API_KEY']);
        unset($_SERVER['CONTENT_TYPE'], $_SERVER['HTTP_CONTENT_TYPE']);
    }

    protected function tearDown(): void
    {
        array_map('unlink', glob($this->tmpDir . '/*') ?: []);
        rmdir($this->tmpDir);
    }

    protected function setBasicAuth(string $username, string $password): void
    {
        $_SERVER['PHP_AUTH_USER'] = $username;
        $_SERVER['PHP_AUTH_PW'] = $password;
    }

    protected function setApiKeyAuth(string $user, string $key): void
    {
        $_SERVER['HTTP_X_API_USER'] = $user;
        $_SERVER['HTTP_X_API_KEY'] = $key;
    }

    protected function setContentType(string $type): void
    {
        $_SERVER['CONTENT_TYPE'] = $type;
    }

    /**
     * Capture handler output and return [statusCode, body].
     *
     * @return array{int, string}
     */
    protected function captureOutput(callable $handler): array
    {
        // Reset response code
        http_response_code(200);

        ob_start();
        $handler();
        $body = ob_get_clean();

        return [(int) http_response_code(), $body ?: ''];
    }
}
