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
    use AuthenticatesRequests;

    private const RETRY_AFTER_SECONDS = 60;

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

        $clientIp = $this->resolveClientIp();

        $user = $this->authenticateRequest('nic', $clientIp);
        if ($user === null) {
            return;
        }

        $hostname = Sanitize::asString($_GET['hostname'] ?? null);
        if (Sanitize::hasControl($hostname)) {
            echo 'notfqdn';
            return;
        }
        if ($hostname === '') {
            echo 'notfqdn';
            return;
        }

        $ip = Sanitize::asString($_GET['myip'] ?? null);
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
            $this->log->info('nic: permission denied for user ' . $user['username'] . ' on ' . $hostname);
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

    /** DynDNS2 response for a throttled or locked-out client. Also used by the front controller. */
    public function rejectRateLimited(): void
    {
        header('Content-Type: text/plain; charset=utf-8');
        http_response_code(429);
        header('Retry-After: ' . self::RETRY_AFTER_SECONDS);
        echo 'abuse';
    }

    protected function rejectUnauthenticated(): void
    {
        header('WWW-Authenticate: Basic realm="Restricted"');
        http_response_code(401);
        echo 'badauth';
    }
}
