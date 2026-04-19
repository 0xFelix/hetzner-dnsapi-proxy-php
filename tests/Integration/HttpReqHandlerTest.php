<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy\Tests\Integration;

use HetznerDnsapiProxy\Handler\HttpReqHandler;
use HetznerDnsapiProxy\Tests\HandlerTestCase;

class HttpReqHandlerTest extends HandlerTestCase
{
    private HttpReqHandler $handler;

    protected function setUp(): void
    {
        parent::setUp();
        $this->handler = new HttpReqHandler($this->auth, $this->dns, $this->log, $this->rateLimiter);
    }

    public function testPresentCreatesTxt(): void
    {
        $body = json_encode(['fqdn' => 'sub.example.com.', 'value' => 'test-val'], JSON_THROW_ON_ERROR);
        $this->setContentType('application/json');
        $this->setBasicAuth('alice', 'secret');

        [$code] = $this->captureOutput(fn() => $this->handler->handlePresent($body));

        $this->assertSame(200, $code);
        $this->assertCount(1, $this->dns->updateCalls);

        $call = $this->dns->updateCalls[0];
        $this->assertSame('sub.example.com', $call->fullName);
        $this->assertSame('sub', $call->name);
        $this->assertSame('TXT', $call->type);
        $this->assertSame('test-val', $call->value);
    }

    public function testCleanupCallsClean(): void
    {
        $body = json_encode(['fqdn' => 'sub.example.com.', 'value' => ''], JSON_THROW_ON_ERROR);
        $this->setContentType('application/json');
        $this->setBasicAuth('alice', 'secret');

        [$code] = $this->captureOutput(fn() => $this->handler->handleCleanup($body));

        $this->assertSame(200, $code);
        $this->assertEmpty($this->dns->updateCalls);
        $this->assertCount(1, $this->dns->cleanCalls);
    }

    public function testWrongContentType(): void
    {
        $body = json_encode(['fqdn' => 'sub.example.com.', 'value' => 'val'], JSON_THROW_ON_ERROR);
        $this->setContentType('text/plain');
        $this->setBasicAuth('alice', 'secret');

        [$code, $output] = $this->captureOutput(fn() => $this->handler->handlePresent($body));

        $this->assertSame(400, $code);
        $this->assertStringContainsString('Content-Type', $output);
    }

    public function testMissingValueOnPresent(): void
    {
        $body = json_encode(['fqdn' => 'sub.example.com.'], JSON_THROW_ON_ERROR);
        $this->setContentType('application/json');
        $this->setBasicAuth('alice', 'secret');

        [$code, $output] = $this->captureOutput(fn() => $this->handler->handlePresent($body));

        $this->assertSame(400, $code);
        $this->assertStringContainsString('missing', $output);
    }

    public function testAuthFailure(): void
    {
        $body = json_encode(['fqdn' => 'sub.example.com.', 'value' => 'val'], JSON_THROW_ON_ERROR);
        $this->setContentType('application/json');
        $this->setBasicAuth('alice', 'wrong');

        [$code] = $this->captureOutput(fn() => $this->handler->handlePresent($body));

        $this->assertSame(401, $code);
    }
}
