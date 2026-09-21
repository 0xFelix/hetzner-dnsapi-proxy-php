<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy\Handler;

use HetznerDnsapiProxy\Auth;
use HetznerDnsapiProxy\DnsServiceInterface;
use HetznerDnsapiProxy\FqdnUtil;
use HetznerDnsapiProxy\IpUtil;
use HetznerDnsapiProxy\Logger;
use HetznerDnsapiProxy\RateLimiter;
use HetznerDnsapiProxy\RequestData;
use HetznerDnsapiProxy\Sanitize;

class PlainHandler
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
        $clientIp = $this->resolveClientIp();

        $user = $this->authenticateRequest('plain', $clientIp);
        if ($user === null) {
            return;
        }

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
        $ip = IpUtil::canonicalize($ip);

        try {
            [$name, $zone] = FqdnUtil::splitFqdn($hostname);
        } catch (\InvalidArgumentException) {
            http_response_code(400);
            echo 'invalid fqdn';
            return;
        }

        if (!$this->auth->checkPermission($hostname, $user)) {
            $this->log->info('plain: permission denied for user ' . $user['username'] . ' on ' . $hostname);
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

    /** Response for a throttled or locked-out client. Also used by the front controller. */
    public function rejectRateLimited(): void
    {
        http_response_code(429);
        header('Retry-After: ' . self::RETRY_AFTER_SECONDS);
    }
}
