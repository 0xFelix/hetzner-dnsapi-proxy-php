<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy\Tests\Unit;

use HetznerDnsapiProxy\FqdnUtil;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class FqdnUtilTest extends TestCase
{
    public function testSimpleSubdomain(): void
    {
        [$name, $zone] = FqdnUtil::splitFqdn('sub.example.com');
        $this->assertSame('sub', $name);
        $this->assertSame('example.com', $zone);
    }

    public function testApexDomain(): void
    {
        [$name, $zone] = FqdnUtil::splitFqdn('example.com');
        $this->assertSame('', $name);
        $this->assertSame('example.com', $zone);
    }

    public function testDeepSubdomain(): void
    {
        [$name, $zone] = FqdnUtil::splitFqdn('deep.sub.example.com');
        $this->assertSame('deep.sub', $name);
        $this->assertSame('example.com', $zone);
    }

    public function testMultiPartTld(): void
    {
        [$name, $zone] = FqdnUtil::splitFqdn('sub.example.co.uk');
        $this->assertSame('sub', $name);
        $this->assertSame('example.co.uk', $zone);
    }

    public function testEmptyFqdn(): void
    {
        $this->expectException(InvalidArgumentException::class);
        FqdnUtil::splitFqdn('');
    }

    public function testTldOnly(): void
    {
        $this->expectException(InvalidArgumentException::class);
        FqdnUtil::splitFqdn('com');
    }
}
