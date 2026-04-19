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

class NicUpdateHandler
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
        header('Content-Type: text/plain');

        $clientIp = $this->clientIp ?? ($_SERVER['REMOTE_ADDR'] ?? '');

        if ($this->rateLimiter->isBlocked($clientIp)) {
            $this->log->info('nic: blocked request from locked out IP ' . $clientIp);
            http_response_code(429);
            echo 'abuse';
            return;
        }

        $creds = $this->auth->extractBasicAuth();
        if ($creds === null) {
            header('WWW-Authenticate: Basic realm="Restricted"');
            http_response_code(401);
            echo 'badauth';
            return;
        }

        $user = $this->auth->authenticate($creds[0], $creds[1]);
        if ($user === null) {
            $locked = $this->rateLimiter->recordFailure($clientIp);
            $this->log->info('nic: auth failed for user: ' . $creds[0] . ' from ' . $clientIp);
            if ($locked) {
                $this->log->info('nic: locked out IP ' . $clientIp . ' after too many failures');
            }
            header('WWW-Authenticate: Basic realm="Restricted"');
            http_response_code(401);
            echo 'badauth';
            return;
        }

        $this->rateLimiter->reset($clientIp);

        $hostname = $_GET['hostname'] ?? '';
        if (Sanitize::hasControl($hostname)) {
            echo 'notfqdn';
            return;
        }
        if ($hostname === '') {
            echo 'notfqdn';
            return;
        }

        $ip = $_GET['myip'] ?? '';
        if (Sanitize::hasControl($ip)) {
            echo 'notfqdn';
            return;
        }
        if ($ip === '') {
            $ip = $clientIp;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            echo 'notfqdn';
            return;
        }

        $type = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false ? 'A' : 'AAAA';

        try {
            [$name, $zone] = FqdnUtil::splitFqdn($hostname);
        } catch (\InvalidArgumentException) {
            echo 'notfqdn';
            return;
        }

        if (!$this->auth->checkPermission($hostname, $user)) {
            $this->log->info('nic: permission denied for user ' . $creds[0] . ' on ' . $hostname);
            echo 'nohost';
            return;
        }

        try {
            $this->dns->update(new RequestData($hostname, $name, $zone, $ip, $type));
        } catch (\Throwable $e) {
            $this->log->error('nic: DNS update failed for ' . $hostname . ': ' . $e->getMessage());
            echo 'dnserr';
            return;
        }

        $this->log->info('nic: updated ' . $hostname . ' ' . $type . ' ' . $ip);
        http_response_code(200);
        echo 'good ' . $ip;
    }
}
