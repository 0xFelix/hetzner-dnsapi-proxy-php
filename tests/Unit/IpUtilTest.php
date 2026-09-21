<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy\Tests\Unit;

use HetznerDnsapiProxy\IpUtil;
use PHPUnit\Framework\TestCase;

class IpUtilTest extends TestCase
{
    public function testCollapsesIpv6ZeroGroups(): void
    {
        $this->assertSame(
            '2001:db8:3c4d::1ff',
            IpUtil::canonicalize('2001:0db8:3c4d:0000:0000:0000:0000:01ff'),
        );
    }

    public function testLowercasesHexDigits(): void
    {
        $this->assertSame('2001:db8:3c4d::1ff', IpUtil::canonicalize('2001:0DB8:3C4D:0:0:0:0:1FF'));
    }

    public function testCollapsesLoopback(): void
    {
        $this->assertSame('::1', IpUtil::canonicalize('0000:0000:0000:0000:0000:0000:0000:0001'));
    }

    public function testIsIdempotent(): void
    {
        $once = IpUtil::canonicalize('2001:0db8:3c4d:0000:0000:0000:0000:01ff');
        $this->assertSame($once, IpUtil::canonicalize($once));
    }

    public function testLeavesIpv4Unchanged(): void
    {
        $this->assertSame('1.2.3.4', IpUtil::canonicalize('1.2.3.4'));
    }

    public function testLeavesIpv4MappedFormUnchanged(): void
    {
        $this->assertSame('::ffff:192.0.2.1', IpUtil::canonicalize('::ffff:192.0.2.1'));
    }

    public function testPassesNonAddressesThrough(): void
    {
        // Logger's '-' placeholder and anything else malformed must survive.
        $this->assertSame('-', IpUtil::canonicalize('-'));
        $this->assertSame('not an ip', IpUtil::canonicalize('not an ip'));
        $this->assertSame('', IpUtil::canonicalize(''));
    }
}
