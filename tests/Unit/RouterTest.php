<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy\Tests\Unit;

use HetznerDnsapiProxy\Router;
use PHPUnit\Framework\TestCase;

class RouterTest extends TestCase
{
    public function testMatchingGetRoute(): void
    {
        $router = new Router();
        $called = false;
        $router->get('/test', function () use (&$called) {
            $called = true;
        });

        $router->dispatch('GET', '/test');
        $this->assertTrue($called);
    }

    public function testMatchingPostRoute(): void
    {
        $router = new Router();
        $called = false;
        $router->post('/test', function () use (&$called) {
            $called = true;
        });

        $router->dispatch('POST', '/test');
        $this->assertTrue($called);
    }

    public function testNonMatchingPath(): void
    {
        $router = new Router();
        $router->get('/test', function () {});

        $router->dispatch('GET', '/other');
        $this->assertSame(404, http_response_code());
    }

    public function testWrongMethod(): void
    {
        $router = new Router();
        $router->get('/test', function () {});

        $router->dispatch('POST', '/test');
        $this->assertSame(404, http_response_code());
    }
}
