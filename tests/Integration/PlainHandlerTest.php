<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy\Tests\Integration;

use HetznerDnsapiProxy\Handler\PlainHandler;
use HetznerDnsapiProxy\Tests\HandlerTestCase;

class PlainHandlerTest extends HandlerTestCase
{
    private PlainHandler $handler;

    protected function setUp(): void
    {
        parent::setUp();
        $this->handler = new PlainHandler($this->auth, $this->dns, $this->log, $this->rateLimiter);
    }

    public function testValidARecord(): void
    {
        $_GET['hostname'] = 'sub.example.com';
        $_GET['ip'] = '1.2.3.4';
        $this->setBasicAuth('alice', 'secret');

        [$code, $body] = $this->captureOutput([$this->handler, 'handle']);

        $this->assertSame(200, $code);
        $this->assertCount(1, $this->dns->updateCalls);
        $this->assertSame('sub', $this->dns->updateCalls[0]->name);
        $this->assertSame('example.com', $this->dns->updateCalls[0]->zone);
        $this->assertSame('1.2.3.4', $this->dns->updateCalls[0]->value);
        $this->assertSame('A', $this->dns->updateCalls[0]->type);
    }

    public function testValidAAAARecord(): void
    {
        $_GET['hostname'] = 'sub.example.com';
        $_GET['ip'] = '::1';
        $this->setBasicAuth('alice', 'secret');

        [$code] = $this->captureOutput([$this->handler, 'handle']);

        $this->assertSame(200, $code);
        $this->assertSame('AAAA', $this->dns->updateCalls[0]->type);
    }

    public function testMissingHostname(): void
    {
        $_GET['ip'] = '1.2.3.4';
        $this->setBasicAuth('alice', 'secret');

        [$code, $body] = $this->captureOutput([$this->handler, 'handle']);

        $this->assertSame(400, $code);
        $this->assertStringContainsString('missing', $body);
        $this->assertEmpty($this->dns->updateCalls);
    }

    public function testInvalidIp(): void
    {
        $_GET['hostname'] = 'sub.example.com';
        $_GET['ip'] = 'not-an-ip';
        $this->setBasicAuth('alice', 'secret');

        [$code, $body] = $this->captureOutput([$this->handler, 'handle']);

        $this->assertSame(400, $code);
        $this->assertStringContainsString('invalid ip', $body);
    }

    public function testArrayQueryParamRejected(): void
    {
        $_GET['hostname'] = ['sub.example.com', 'other.example.com'];
        $_GET['ip'] = '1.2.3.4';
        $this->setBasicAuth('alice', 'secret');

        [$code, $body] = $this->captureOutput([$this->handler, 'handle']);

        $this->assertSame(400, $code);
        $this->assertStringContainsString('missing', $body);
        $this->assertEmpty($this->dns->updateCalls);
    }

    public function testAuthFailure(): void
    {
        $_GET['hostname'] = 'sub.example.com';
        $_GET['ip'] = '1.2.3.4';
        $this->setBasicAuth('alice', 'wrong');

        [$code] = $this->captureOutput([$this->handler, 'handle']);

        $this->assertSame(401, $code);
        $this->assertEmpty($this->dns->updateCalls);
    }

    public function testNoAuth(): void
    {
        $_GET['hostname'] = 'sub.example.com';
        $_GET['ip'] = '1.2.3.4';

        [$code] = $this->captureOutput([$this->handler, 'handle']);

        $this->assertSame(401, $code);
    }

    public function testDnsError(): void
    {
        $_GET['hostname'] = 'sub.example.com';
        $_GET['ip'] = '1.2.3.4';
        $this->setBasicAuth('alice', 'secret');
        $this->dns->throwOnUpdate = true;

        [$code, $body] = $this->captureOutput([$this->handler, 'handle']);

        $this->assertSame(500, $code);
        $this->assertSame('', $body);
    }

    public function testUnauthorizedDomain(): void
    {
        $_GET['hostname'] = 'sub.other.org';
        $_GET['ip'] = '1.2.3.4';
        $this->setBasicAuth('alice', 'secret');

        [$code] = $this->captureOutput([$this->handler, 'handle']);

        $this->assertSame(403, $code);
        $this->assertEmpty($this->dns->updateCalls);
    }
}
