<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy\Tests\Unit;

use HetznerDnsapiProxy\ClientIp;
use PHPUnit\Framework\TestCase;

class ClientIpTest extends TestCase
{
    public function testRemoteAddrIsCanonicalized(): void
    {
        $this->assertSame(
            '2001:db8:3c4d::1ff',
            ClientIp::resolve('2001:0db8:3c4d:0000:0000:0000:0000:01ff', null, [], ''),
        );
    }

    public function testForwardedCandidateIsCanonicalized(): void
    {
        $resolved = ClientIp::resolve(
            '10.0.0.1',
            'X-Forwarded-For',
            ['10.0.0.1'],
            '2001:0db8:3c4d:0000:0000:0000:0000:01ff',
        );

        $this->assertSame('2001:db8:3c4d::1ff', $resolved);
    }

    public function testUntrustedRemoteAddrIgnoresHeader(): void
    {
        $resolved = ClientIp::resolve('203.0.113.9', 'X-Forwarded-For', ['10.0.0.1'], '192.0.2.1');

        $this->assertSame('203.0.113.9', $resolved);
    }

    public function testIpv4IsUnchanged(): void
    {
        $this->assertSame('192.0.2.1', ClientIp::resolve('192.0.2.1', null, [], ''));
    }
}
