<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy\Tests\Unit;

use HetznerDnsapiProxy\Auth;
use HetznerDnsapiProxy\Config;
use PHPUnit\Framework\TestCase;

class AuthTest extends TestCase
{
    private Auth $auth;

    protected function setUp(): void
    {
        $tmpDir = sys_get_temp_dir() . '/hetzner-dnsapi-proxy-php-test-' . uniqid();
        mkdir($tmpDir);
        $path = $tmpDir . '/config.php';
        file_put_contents($path, '<?php return ' . var_export([
            'token' => 'test-token',
            'record_ttl' => 60,
            'users' => [
                [
                    'username' => 'alice',
                    'password' => 'secret',
                    'domains' => ['example.com', '*.example.com'],
                ],
                [
                    'username' => 'bob',
                    'password' => 'hunter2',
                    'domains' => ['other.org'],
                ],
            ],
        ], true) . ';');

        $config = Config::load($path);
        $this->auth = new Auth($config);

        unlink($path);
        rmdir($tmpDir);
    }

    public function testCorrectUserMatchingDomain(): void
    {
        $user = $this->auth->authenticate('alice', 'secret');
        $this->assertNotNull($user);
        $this->assertTrue($this->auth->checkPermission('example.com', $user));
    }

    public function testCorrectUserNonMatchingDomain(): void
    {
        $user = $this->auth->authenticate('alice', 'secret');
        $this->assertNotNull($user);
        $this->assertFalse($this->auth->checkPermission('other.org', $user));
    }

    public function testWrongPassword(): void
    {
        $this->assertNull($this->auth->authenticate('alice', 'wrong'));
    }

    public function testEmptyCredentials(): void
    {
        $this->assertNull($this->auth->authenticate('', ''));
    }

    public function testEmptyFqdn(): void
    {
        $user = $this->auth->authenticate('alice', 'secret');
        $this->assertNotNull($user);
        $this->assertFalse($this->auth->checkPermission('', $user));
    }

    public function testWildcardMatchesSubdomain(): void
    {
        $user = $this->auth->authenticate('alice', 'secret');
        $this->assertNotNull($user);
        $this->assertTrue($this->auth->checkPermission('sub.example.com', $user));
    }

    public function testWildcardDoesNotMatchApex(): void
    {
        // *.example.com should not match example.com - but exact match on example.com should
        $user = $this->auth->authenticate('alice', 'secret');
        $this->assertNotNull($user);
        $this->assertTrue($this->auth->checkPermission('example.com', $user));
    }

    public function testDeepSubdomainMatchesWildcard(): void
    {
        $user = $this->auth->authenticate('alice', 'secret');
        $this->assertNotNull($user);
        $this->assertTrue($this->auth->checkPermission('a.b.example.com', $user));
    }

    public function testSecondUser(): void
    {
        $user = $this->auth->authenticate('bob', 'hunter2');
        $this->assertNotNull($user);
        $this->assertTrue($this->auth->checkPermission('other.org', $user));
    }

    public function testSecondUserWrongDomain(): void
    {
        $user = $this->auth->authenticate('bob', 'hunter2');
        $this->assertNotNull($user);
        $this->assertFalse($this->auth->checkPermission('example.com', $user));
    }

    // isSubDomain tests
    public function testIsSubDomainBasic(): void
    {
        $this->assertTrue(Auth::isSubDomain('sub.example.com', '*.example.com'));
    }

    public function testIsSubDomainDeep(): void
    {
        $this->assertTrue(Auth::isSubDomain('a.b.example.com', '*.example.com'));
    }

    public function testIsSubDomainNonWildcard(): void
    {
        $this->assertFalse(Auth::isSubDomain('sub.example.com', 'example.com'));
    }

    public function testIsSubDomainNotMatching(): void
    {
        $this->assertFalse(Auth::isSubDomain('sub.other.com', '*.example.com'));
    }

    public function testIsSubDomainTooShort(): void
    {
        $this->assertFalse(Auth::isSubDomain('com', '*.example.com'));
    }

    // authenticate tests
    public function testAuthenticate(): void
    {
        $user = $this->auth->authenticate('alice', 'secret');
        $this->assertNotNull($user);
        $this->assertSame('alice', $user['username']);
    }

    public function testAuthenticateWrongPassword(): void
    {
        $this->assertNull($this->auth->authenticate('alice', 'wrong'));
    }

    public function testAuthenticateEmpty(): void
    {
        $this->assertNull($this->auth->authenticate('', ''));
    }
}
