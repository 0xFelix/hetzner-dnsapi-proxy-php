<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy\Handler;

use HetznerDnsapiProxy\Auth;
use HetznerDnsapiProxy\DnsServiceInterface;
use HetznerDnsapiProxy\FqdnUtil;
use HetznerDnsapiProxy\Logger;
use HetznerDnsapiProxy\RateLimiter;
use HetznerDnsapiProxy\RequestData;
use HetznerDnsapiProxy\Sanitize;

class PlainHandler
{
    public function __construct(
        private readonly Auth $auth,
        private readonly DnsServiceInterface $dns,
        private readonly Logger $log,
        private readonly RateLimiter $rateLimiter,
        private readonly ?string $clientIp = null,
    ) {}

    public function handle(): void
    {
        $clientIp = $this->clientIp ?? ($_SERVER['REMOTE_ADDR'] ?? '');

        if ($this->rateLimiter->isBlocked($clientIp)) {
            $this->log->info('plain: blocked request from locked out IP ' . $clientIp);
            http_response_code(429);
            return;
        }

        $creds = $this->auth->extractBasicAuth();
        if ($creds === null) {
            header('WWW-Authenticate: Basic realm="Restricted"');
            http_response_code(401);
            return;
        }

        $user = $this->auth->authenticate($creds[0], $creds[1]);
        if ($user === null) {
            $locked = $this->rateLimiter->recordFailure($clientIp);
            $this->log->info('plain: auth failed for user: ' . $creds[0] . ' from ' . $clientIp);
            if ($locked) {
                $this->log->info('plain: locked out IP ' . $clientIp . ' after too many failures');
            }
            header('WWW-Authenticate: Basic realm="Restricted"');
            http_response_code(401);
            return;
        }

        $this->rateLimiter->reset($clientIp);

        $hostname = Sanitize::asString($_GET['hostname'] ?? null);
        $ip = Sanitize::asString($_GET['ip'] ?? null);

        if (Sanitize::hasControl($hostname) || Sanitize::hasControl($ip)) {
            http_response_code(400);
            echo 'invalid characters in input';
            return;
        }

        if ($hostname === '' || $ip === '') {
            http_response_code(400);
            echo 'hostname or ip address is missing';
            return;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            http_response_code(400);
            echo 'invalid ip address';
            return;
        }

        $type = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false ? 'A' : 'AAAA';

        try {
            [$name, $zone] = FqdnUtil::splitFqdn($hostname);
        } catch (\InvalidArgumentException) {
            http_response_code(400);
            echo 'invalid fqdn';
            return;
        }

        if (!$this->auth->checkPermission($hostname, $user)) {
            $this->log->info('plain: permission denied for user ' . $creds[0] . ' on ' . $hostname);
            http_response_code(403);
            return;
        }

        try {
            $this->dns->update(new RequestData($hostname, $name, $zone, $ip, $type));
        } catch (\Throwable $e) {
            $this->log->error('plain: DNS update failed for ' . $hostname . ': ' . $e->getMessage());
            http_response_code(500);
            return;
        }

        $this->log->info('plain: updated ' . $hostname . ' ' . $type . ' ' . $ip);
        http_response_code(200);
    }
}
