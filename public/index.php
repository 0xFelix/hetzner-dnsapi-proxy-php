<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use HetznerDnsapiProxy\Auth;
use HetznerDnsapiProxy\Config;
use HetznerDnsapiProxy\DnsService;
use HetznerDnsapiProxy\Handler\NicUpdateHandler;
use HetznerDnsapiProxy\Handler\PlainHandler;
use HetznerDnsapiProxy\Logger;
use HetznerDnsapiProxy\RateLimiter;
use HetznerDnsapiProxy\Router;
use HetznerDnsapiProxy\TokenBucket;
use LKDev\HetznerCloud\HetznerAPIClient;

// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Content-Security-Policy: default-src \'none\'');
header('Cache-Control: no-store');

try {
    $config = Config::load(__DIR__ . '/../config.php');
} catch (\Throwable $e) {
    error_log('Config error: ' . $e->getMessage());
    http_response_code(500);
    exit;
}

$log = new Logger(__DIR__ . '/../data/app.log');
$hetzner = new HetznerAPIClient($config->token);
$dns = new DnsService($hetzner, $config);
$auth = new Auth($config);
$tokenBucket = new TokenBucket(
    __DIR__ . '/../data/token_bucket.json',
    $config->rateLimitRps,
    $config->rateLimitBurst,
    $config->rateLimitIdleSeconds,
);
$rateLimiter = new RateLimiter(
    __DIR__ . '/../data/rate_limit.json',
    $config->lockoutMaxAttempts,
    $config->lockoutDurationSeconds,
    $config->lockoutWindowSeconds,
);

$router = new Router();
$active = array_flip($config->endpoints);

if (isset($active['plain'])) {
    $plain = new PlainHandler($auth, $dns, $log, $rateLimiter);
    $router->get('/plain/update', [$plain, 'handle']);
}
if (isset($active['nicupdate'])) {
    $nic = new NicUpdateHandler($auth, $dns, $log, $rateLimiter);
    $router->get('/nic/update', [$nic, 'handle']);
}

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?: '/';
$ip = $_SERVER['REMOTE_ADDR'] ?? '';
if (!$tokenBucket->allow($ip)) {
    $log->info('rate limit exceeded for ' . $ip);
    if ($path === '/nic/update') {
        header('Content-Type: text/plain; charset=utf-8');
        echo 'abuse';
    } else {
        http_response_code(429);
    }
    exit;
}
$router->dispatch($_SERVER['REQUEST_METHOD'], $path);
