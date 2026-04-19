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
        $clientIp = $this->clientIp ?? ($_SERVER['REMOTE_ADDR'] ?? '');

        if ($this->rateLimiter->isBlocked($clientIp)) {
            $this->log->info('httpreq: blocked request from locked out IP ' . $clientIp);
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
            $this->log->info('httpreq: auth failed for user: ' . $creds[0] . ' from ' . $clientIp);
            if ($locked) {
                $this->log->info('httpreq: locked out IP ' . $clientIp . ' after too many failures');
            }
            header('WWW-Authenticate: Basic realm="Restricted"');
            http_response_code(401);
            return;
        }

        $this->rateLimiter->reset($clientIp);

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
            $this->log->info('httpreq: permission denied for user ' . $creds[0] . ' on ' . $fqdn);
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
}
