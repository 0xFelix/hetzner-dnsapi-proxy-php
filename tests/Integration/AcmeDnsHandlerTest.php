<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy\Tests\Integration;

use HetznerDnsapiProxy\Handler\AcmeDnsHandler;
use HetznerDnsapiProxy\Tests\HandlerTestCase;

class AcmeDnsHandlerTest extends HandlerTestCase
{
    private AcmeDnsHandler $handler;

    protected function setUp(): void
    {
        parent::setUp();
        $this->handler = new AcmeDnsHandler($this->auth, $this->dns, $this->log, $this->rateLimiter);
    }

    public function testValidTxtUpdate(): void
    {
        $body = json_encode(['subdomain' => 'example.com', 'txt' => 'challenge-value'], JSON_THROW_ON_ERROR);
        $this->setApiKeyAuth('alice', 'secret');

        [$code, $output] = $this->captureOutput(fn() => $this->handler->handle($body));

        $this->assertSame(200, $code);
        $this->assertCount(1, $this->dns->updateCalls);

        $call = $this->dns->updateCalls[0];
        $this->assertSame('_acme-challenge.example.com', $call->fullName);
        $this->assertSame('_acme-challenge.', $call->name);
        $this->assertSame('example.com', $call->zone);
        $this->assertSame('challenge-value', $call->value);
        $this->assertSame('TXT', $call->type);

        $decoded = json_decode($output, true);
        $this->assertSame('challenge-value', $decoded['txt']);
    }

    public function testPrefixAlreadyPresent(): void
    {
        $body = json_encode(['subdomain' => '_acme-challenge.example.com', 'txt' => 'val'], JSON_THROW_ON_ERROR);
        $this->setApiKeyAuth('alice', 'secret');

        [$code] = $this->captureOutput(fn() => $this->handler->handle($body));

        $this->assertSame(200, $code);
        $this->assertSame('_acme-challenge', $this->dns->updateCalls[0]->name);
    }

    public function testMissingFields(): void
    {
        $body = json_encode(['subdomain' => 'example.com'], JSON_THROW_ON_ERROR);
        $this->setApiKeyAuth('alice', 'secret');

        [$code, $output] = $this->captureOutput(fn() => $this->handler->handle($body));

        $this->assertSame(400, $code);
        $this->assertStringContainsString('missing', $output);
    }

    public function testAuthFailure(): void
    {
        $body = json_encode(['subdomain' => 'example.com', 'txt' => 'val'], JSON_THROW_ON_ERROR);
        $this->setApiKeyAuth('alice', 'wrong');

        [$code] = $this->captureOutput(fn() => $this->handler->handle($body));

        $this->assertSame(401, $code);
        $this->assertEmpty($this->dns->updateCalls);
    }

    public function testInvalidJson(): void
    {
        $this->setApiKeyAuth('alice', 'secret');

        [$code] = $this->captureOutput(fn() => $this->handler->handle('not json'));

        $this->assertSame(400, $code);
    }
}
