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

class AcmeDnsHandler
{
    private const MAX_BODY_SIZE = 1024;
    private const ACME_CHALLENGE_PREFIX = '_acme-challenge.';

    public function __construct(
        private readonly Auth $auth,
        private readonly DnsServiceInterface $dns,
        private readonly Logger $log,
        private readonly RateLimiter $rateLimiter,
        private readonly ?string $clientIp = null,
    ) {}

    public function handle(?string $rawBody = null): void
    {
        $clientIp = $this->clientIp ?? ($_SERVER['REMOTE_ADDR'] ?? '');

        if ($this->rateLimiter->isBlocked($clientIp)) {
            $this->log->info('acmedns: blocked request from locked out IP ' . $clientIp);
            http_response_code(429);
            return;
        }

        $creds = $this->auth->extractApiKeyAuth();
        if ($creds === null) {
            http_response_code(401);
            return;
        }

        $user = $this->auth->authenticate($creds[0], $creds[1]);
        if ($user === null) {
            $locked = $this->rateLimiter->recordFailure($clientIp);
            $this->log->info('acmedns: auth failed for user: ' . $creds[0] . ' from ' . $clientIp);
            if ($locked) {
                $this->log->info('acmedns: locked out IP ' . $clientIp . ' after too many failures');
            }
            http_response_code(401);
            return;
        }

        $this->rateLimiter->reset($clientIp);

        $body = $rawBody ?? file_get_contents('php://input', false, null, 0, self::MAX_BODY_SIZE);
        $data = json_decode($body ?: '', true);

        if (!is_array($data)) {
            http_response_code(400);
            return;
        }

        $subdomain = $data['subdomain'] ?? '';
        $txt = $data['txt'] ?? '';

        if ($subdomain === '' || $txt === '') {
            http_response_code(400);
            echo 'subdomain or txt is missing';
            return;
        }

        if (Sanitize::hasControl($subdomain)) {
            http_response_code(400);
            echo 'invalid characters in subdomain';
            return;
        }

        $txtError = Sanitize::validateTxt($txt);
        if ($txtError !== null) {
            http_response_code(400);
            echo $txtError;
            return;
        }

        try {
            [$name, $zone] = FqdnUtil::splitFqdn($subdomain);
        } catch (\InvalidArgumentException $e) {
            http_response_code(400);
            echo 'invalid fqdn';
            return;
        }

        if (!$this->auth->checkPermission($subdomain, $user)) {
            $this->log->info('acmedns: permission denied for user ' . $creds[0] . ' on ' . $subdomain);
            http_response_code(403);
            return;
        }

        // Prepend _acme-challenge. prefix if not already present
        if (!str_starts_with($subdomain, self::ACME_CHALLENGE_PREFIX)) {
            $subdomain = self::ACME_CHALLENGE_PREFIX . $subdomain;
            $name = self::ACME_CHALLENGE_PREFIX . $name;
        }

        try {
            $this->dns->update(new RequestData($subdomain, $name, $zone, $txt, 'TXT'));
        } catch (\Throwable $e) {
            $this->log->error('acmedns: DNS update failed for ' . $subdomain . ': ' . $e->getMessage());
            http_response_code(500);
            return;
        }

        $this->log->info('acmedns: updated ' . $subdomain . ' TXT');
        header('Content-Type: application/json');
        echo json_encode(['txt' => $txt], JSON_THROW_ON_ERROR);
    }
}
