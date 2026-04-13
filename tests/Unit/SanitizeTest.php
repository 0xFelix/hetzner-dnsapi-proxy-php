<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy\Tests\Unit;

use HetznerDnsapiProxy\Sanitize;
use PHPUnit\Framework\TestCase;

class SanitizeTest extends TestCase
{
    public function testHasControlDetectsNewlines(): void
    {
        $this->assertTrue(Sanitize::hasControl("abc\ndef"));
        $this->assertTrue(Sanitize::hasControl("abc\rdef"));
        $this->assertTrue(Sanitize::hasControl("abc\x00def"));
    }

    public function testHasControlAcceptsNormal(): void
    {
        $this->assertFalse(Sanitize::hasControl('sub.example.com'));
        $this->assertFalse(Sanitize::hasControl('hello world'));
        $this->assertFalse(Sanitize::hasControl(''));
    }

    public function testValidateTxtAcceptsNormal(): void
    {
        $this->assertNull(Sanitize::validateTxt('dGVzdA=='));
        $this->assertNull(Sanitize::validateTxt('v=spf1 include:example.com ~all'));
    }

    public function testValidateTxtRejectsEmpty(): void
    {
        $this->assertNotNull(Sanitize::validateTxt(''));
    }

    public function testValidateTxtRejectsControlChars(): void
    {
        $this->assertNotNull(Sanitize::validateTxt("test\nvalue"));
        $this->assertNotNull(Sanitize::validateTxt("test\x00value"));
    }

    public function testValidateTxtRejectsTooLong(): void
    {
        $this->assertNull(Sanitize::validateTxt(str_repeat('a', 255)));
        $this->assertNotNull(Sanitize::validateTxt(str_repeat('a', 256)));
    }
}
