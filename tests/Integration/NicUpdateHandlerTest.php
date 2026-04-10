<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy\Tests\Integration;

use HetznerDnsapiProxy\Handler\NicUpdateHandler;
use HetznerDnsapiProxy\Tests\HandlerTestCase;

class NicUpdateHandlerTest extends HandlerTestCase
{
    private NicUpdateHandler $handler;

    protected function setUp(): void
    {
        parent::setUp();
        $this->handler = new NicUpdateHandler($this->auth, $this->dns, $this->log, $this->rateLimiter);
    }

    public function testValidARecord(): void
    {
        $_GET['hostname'] = 'sub.example.com';
        $_GET['myip'] = '1.2.3.4';
        $this->setBasicAuth('alice', 'secret');

        [$code, $body] = $this->captureOutput([$this->handler, 'handle']);

        $this->assertSame(200, $code);
        $this->assertSame('good 1.2.3.4', $body);
        $this->assertCount(1, $this->dns->updateCalls);
        $this->assertSame('sub', $this->dns->updateCalls[0]->name);
        $this->assertSame('example.com', $this->dns->updateCalls[0]->zone);
        $this->assertSame('A', $this->dns->updateCalls[0]->type);
    }

    public function testValidAAAARecord(): void
    {
        $_GET['hostname'] = 'sub.example.com';
        $_GET['myip'] = '2001:db8::1';
        $this->setBasicAuth('alice', 'secret');

        [$code, $body] = $this->captureOutput([$this->handler, 'handle']);

        $this->assertSame(200, $code);
        $this->assertSame('good 2001:db8::1', $body);
        $this->assertSame('AAAA', $this->dns->updateCalls[0]->type);
    }

    public function testNoAuth(): void
    {
        $_GET['hostname'] = 'sub.example.com';
        $_GET['myip'] = '1.2.3.4';

        [$code, $body] = $this->captureOutput([$this->handler, 'handle']);

        $this->assertSame(401, $code);
        $this->assertSame('badauth', $body);
    }

    public function testMissingHostname(): void
    {
        $_GET['myip'] = '1.2.3.4';
        $this->setBasicAuth('alice', 'secret');

        [$code, $body] = $this->captureOutput([$this->handler, 'handle']);

        $this->assertSame(200, $code);
        $this->assertSame('notfqdn', $body);
        $this->assertEmpty($this->dns->updateCalls);
    }

    public function testMissingIp(): void
    {
        $_GET['hostname'] = 'sub.example.com';
        $this->setBasicAuth('alice', 'secret');

        [$code, $body] = $this->captureOutput([$this->handler, 'handle']);

        $this->assertSame(200, $code);
        $this->assertSame('notfqdn', $body);
    }

    public function testInvalidIp(): void
    {
        $_GET['hostname'] = 'sub.example.com';
        $_GET['myip'] = 'not-an-ip';
        $this->setBasicAuth('alice', 'secret');

        [$code, $body] = $this->captureOutput([$this->handler, 'handle']);

        $this->assertSame(200, $code);
        $this->assertSame('notfqdn', $body);
    }

    public function testUnauthorizedDomain(): void
    {
        $_GET['hostname'] = 'sub.other.org';
        $_GET['myip'] = '1.2.3.4';
        $this->setBasicAuth('alice', 'secret');

        [$code, $body] = $this->captureOutput([$this->handler, 'handle']);

        $this->assertSame(200, $code);
        $this->assertSame('nohost', $body);
        $this->assertEmpty($this->dns->updateCalls);
    }

    public function testDnsError(): void
    {
        $_GET['hostname'] = 'sub.example.com';
        $_GET['myip'] = '1.2.3.4';
        $this->setBasicAuth('alice', 'secret');
        $this->dns->throwOnUpdate = true;

        [$code, $body] = $this->captureOutput([$this->handler, 'handle']);

        $this->assertSame(200, $code);
        $this->assertSame('dnserr', $body);
    }

    public function testWrongPassword(): void
    {
        $_GET['hostname'] = 'sub.example.com';
        $_GET['myip'] = '1.2.3.4';
        $this->setBasicAuth('alice', 'wrong');

        [$code, $body] = $this->captureOutput([$this->handler, 'handle']);

        $this->assertSame(401, $code);
        $this->assertSame('badauth', $body);
    }
}
