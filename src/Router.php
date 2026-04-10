<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy;

class Router
{
    /** @var array<string, callable> */
    private array $routes = [];

    public function get(string $path, callable $handler): void
    {
        $this->routes['GET ' . $path] = $handler;
    }

    public function post(string $path, callable $handler): void
    {
        $this->routes['POST ' . $path] = $handler;
    }

    public function dispatch(string $method, string $path): void
    {
        $key = $method . ' ' . $path;
        if (isset($this->routes[$key])) {
            ($this->routes[$key])();
            return;
        }

        http_response_code(404);
    }
}
