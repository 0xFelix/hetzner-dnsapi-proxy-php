<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy\Tests\Integration;

use HetznerDnsapiProxy\Handler\DirectAdminHandler;
use HetznerDnsapiProxy\Tests\HandlerTestCase;

class DirectAdminHandlerTest extends HandlerTestCase
{
    private DirectAdminHandler $handler;

    protected function setUp(): void
    {
        parent::setUp();
        $this->handler = new DirectAdminHandler($this->auth, $this->dns, $this->log, $this->rateLimiter);
    }

    public function testShowDomains(): void
    {
        $this->setBasicAuth('alice', 'secret');

        [$code, $body] = $this->captureOutput([$this->handler, 'showDomains']);

        $this->assertSame(200, $code);
        $this->assertStringContainsString('list=', $body);
        $this->assertStringContainsString('example.com', $body);
    }

    public function testShowDomainsNoAuth(): void
    {
        [$code] = $this->captureOutput([$this->handler, 'showDomains']);

        $this->assertSame(401, $code);
    }

    public function testDnsControlAdd(): void
    {
        $_GET['domain'] = 'example.com';
        $_GET['action'] = 'add';
        $_GET['name'] = 'test';
        $_GET['type'] = 'A';
        $_GET['value'] = '1.2.3.4';
        $this->setBasicAuth('alice', 'secret');

        [$code, $body] = $this->captureOutput([$this->handler, 'dnsControl']);

        $this->assertSame(200, $code);
        $this->assertStringContainsString('error=0', $body);
        $this->assertCount(1, $this->dns->updateCalls);

        $call = $this->dns->updateCalls[0];
        $this->assertSame('test.example.com', $call->fullName);
        $this->assertSame('test', $call->name);
        $this->assertSame('A', $call->type);
        $this->assertSame('1.2.3.4', $call->value);
    }

    public function testDnsControlNonAddAction(): void
    {
        $_GET['domain'] = 'example.com';
        $_GET['action'] = 'delete';
        $this->setBasicAuth('alice', 'secret');

        [$code, $body] = $this->captureOutput([$this->handler, 'dnsControl']);

        $this->assertSame(200, $code);
        $this->assertStringContainsString('error=0', $body);
        $this->assertEmpty($this->dns->updateCalls);
    }

    public function testDnsControlInvalidType(): void
    {
        $_GET['domain'] = 'example.com';
        $_GET['action'] = 'add';
        $_GET['type'] = 'CNAME';
        $_GET['value'] = 'test';
        $this->setBasicAuth('alice', 'secret');

        [$code, $body] = $this->captureOutput([$this->handler, 'dnsControl']);

        $this->assertSame(400, $code);
        $this->assertStringContainsString('type can only be', $body);
    }

    public function testDnsControlInvalidIp(): void
    {
        $_GET['domain'] = 'example.com';
        $_GET['action'] = 'add';
        $_GET['type'] = 'A';
        $_GET['value'] = 'not-an-ip';
        $this->setBasicAuth('alice', 'secret');

        [$code, $body] = $this->captureOutput([$this->handler, 'dnsControl']);

        $this->assertSame(400, $code);
        $this->assertStringContainsString('invalid', $body);
    }

    public function testDomainPointer(): void
    {
        [$code] = $this->captureOutput([$this->handler, 'domainPointer']);
        $this->assertSame(200, $code);
    }

    public function testDnsControlAuthFailure(): void
    {
        $_GET['domain'] = 'example.com';
        $_GET['action'] = 'add';
        $_GET['type'] = 'A';
        $_GET['value'] = '1.2.3.4';
        $this->setBasicAuth('alice', 'wrong');

        [$code] = $this->captureOutput([$this->handler, 'dnsControl']);

        $this->assertSame(401, $code);
        $this->assertEmpty($this->dns->updateCalls);
    }
}
