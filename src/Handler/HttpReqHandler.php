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

class HttpReqHandler
{
    use AuthenticatesRequests;

    private const RETRY_AFTER_SECONDS = 60;

    private const MAX_BODY_SIZE = 1024;

    public function __construct(
        private readonly Auth $auth,
        private readonly DnsServiceInterface $dns,
        private readonly Logger $log,
        private readonly RateLimiter $rateLimiter,
        private readonly ?string $clientIp = null,
    ) {}

    public function handlePresent(?string $rawBody = null): void
    {
        $this->handle(cleanup: false, rawBody: $rawBody);
    }

    public function handleCleanup(?string $rawBody = null): void
    {
        $this->handle(cleanup: true, rawBody: $rawBody);
    }

    private function handle(bool $cleanup, ?string $rawBody = null): void
    {
        $clientIp = $this->resolveClientIp();

        $user = $this->authenticateRequest('httpreq', $clientIp);
        if ($user === null) {
            return;
        }

        $contentType = $_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? '';
        if (stripos($contentType, 'application/json') === false) {
            http_response_code(400);
            echo 'Content-Type must be application/json';
            return;
        }

        $body = $rawBody ?? file_get_contents('php://input', false, null, 0, self::MAX_BODY_SIZE);
        $data = json_decode($body ?: '', true);

        if (!is_array($data)) {
            http_response_code(400);
            return;
        }

        $fqdn = $data['fqdn'] ?? '';
        $value = $data['value'] ?? '';

        if (!is_string($fqdn) || !is_string($value)) {
            http_response_code(400);
            echo 'fqdn and value must be strings';
            return;
        }

        if ($fqdn === '') {
            http_response_code(400);
            echo 'fqdn is missing';
            return;
        }

        if (Sanitize::hasControl($fqdn)) {
            http_response_code(400);
            echo 'invalid characters in fqdn';
            return;
        }

        if (!$cleanup && $value === '') {
            http_response_code(400);
            echo 'value is missing';
            return;
        }

        if (!$cleanup) {
            $txtError = Sanitize::validateTxt($value);
            if ($txtError !== null) {
                http_response_code(400);
                echo $txtError;
                return;
            }
        }

        // Trim trailing dot
        $fqdn = rtrim($fqdn, '.');

        try {
            [$name, $zone] = FqdnUtil::splitFqdn($fqdn);
        } catch (\InvalidArgumentException) {
            http_response_code(400);
            echo 'invalid fqdn';
            return;
        }

        if (!$this->auth->checkPermission($fqdn, $user)) {
            $this->log->info('httpreq: permission denied for user ' . $user['username'] . ' on ' . $fqdn);
            http_response_code(403);
            return;
        }

        try {
            $reqData = new RequestData($fqdn, $name, $zone, $value, 'TXT');
            if ($cleanup) {
                $this->dns->clean($reqData);
            } else {
                $this->dns->update($reqData);
            }
        } catch (\Throwable $e) {
            $this->log->error('httpreq: DNS operation failed for ' . $fqdn . ': ' . $e->getMessage());
            http_response_code(500);
            return;
        }

        $op = $cleanup ? 'cleaned' : 'updated';
        $this->log->info('httpreq: ' . $op . ' ' . $fqdn . ' TXT');
        http_response_code(200);
    }

    /** Response for a throttled or locked-out client. Also used by the front controller. */
    public function rejectRateLimited(): void
    {
        http_response_code(429);
        header('Retry-After: ' . self::RETRY_AFTER_SECONDS);
    }
}
