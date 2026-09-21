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
    use AuthenticatesRequests;

    private const RETRY_AFTER_SECONDS = 60;

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
        $clientIp = $this->resolveClientIp();

        $user = $this->authenticateRequest('acmedns', $clientIp);
        if ($user === null) {
            return;
        }

        $body = $rawBody ?? file_get_contents('php://input', false, null, 0, self::MAX_BODY_SIZE);
        $data = json_decode($body ?: '', true);

        if (!is_array($data)) {
            http_response_code(400);
            return;
        }

        $subdomain = $data['subdomain'] ?? '';
        $txt = $data['txt'] ?? '';

        if (!is_string($subdomain) || !is_string($txt)) {
            http_response_code(400);
            echo 'subdomain and txt must be strings';
            return;
        }

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
            $this->log->info('acmedns: permission denied for user ' . $user['username'] . ' on ' . $subdomain);
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

    /** Response for a throttled or locked-out client. Also used by the front controller. */
    public function rejectRateLimited(): void
    {
        http_response_code(429);
        header('Retry-After: ' . self::RETRY_AFTER_SECONDS);
    }

    /**
     * acme-dns sends credentials in X-Api-User / X-Api-Key, not Basic Auth.
     *
     * @return array{string, string}|null
     */
    protected function extractCredentials(): ?array
    {
        return $this->auth->extractApiKeyAuth();
    }

    protected function rejectUnauthenticated(): void
    {
        http_response_code(401);
    }
}
