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

class DirectAdminHandler
{
    public function __construct(
        private readonly Auth $auth,
        private readonly DnsServiceInterface $dns,
        private readonly Logger $log,
        private readonly RateLimiter $rateLimiter,
        private readonly ?string $clientIp = null,
    ) {}

    public function showDomains(): void
    {
        $clientIp = $this->clientIp ?? ($_SERVER['REMOTE_ADDR'] ?? '');

        if ($this->rateLimiter->isBlocked($clientIp)) {
            $this->log->info('directadmin: blocked request from locked out IP ' . $clientIp);
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
            $this->log->info('directadmin: auth failed for user: ' . $creds[0] . ' from ' . $clientIp);
            if ($locked) {
                $this->log->info('directadmin: locked out IP ' . $clientIp . ' after too many failures');
            }
            header('WWW-Authenticate: Basic realm="Restricted"');
            http_response_code(401);
            return;
        }

        $this->rateLimiter->reset($clientIp);

        $domains = $this->auth->getDomains($user);

        header('Content-Type: application/x-www-form-urlencoded');
        // Build URL-encoded list=domain1&list=domain2 format
        $pairs = [];
        foreach ($domains as $domain) {
            $pairs[] = 'list=' . urlencode($domain);
        }
        echo implode('&', $pairs);
    }

    public function dnsControl(): void
    {
        $clientIp = $this->clientIp ?? ($_SERVER['REMOTE_ADDR'] ?? '');

        if ($this->rateLimiter->isBlocked($clientIp)) {
            $this->log->info('directadmin: blocked request from locked out IP ' . $clientIp);
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
            $this->log->info('directadmin: auth failed for user: ' . $creds[0] . ' from ' . $clientIp);
            if ($locked) {
                $this->log->info('directadmin: locked out IP ' . $clientIp . ' after too many failures');
            }
            header('WWW-Authenticate: Basic realm="Restricted"');
            http_response_code(401);
            return;
        }

        $this->rateLimiter->reset($clientIp);

        $domain = Sanitize::asString($_GET['domain'] ?? null);
        $action = Sanitize::asString($_GET['action'] ?? null);
        $name = Sanitize::asString($_GET['name'] ?? null);
        $value = Sanitize::asString($_GET['value'] ?? null);

        if (Sanitize::hasControl($domain) || Sanitize::hasControl($name) || Sanitize::hasControl($value)) {
            http_response_code(400);
            echo 'invalid characters in input';
            return;
        }

        if ($domain === '' || $action === '') {
            http_response_code(400);
            echo 'domain or action is missing';
            return;
        }

        if ($action !== 'add') {
            $this->respondOk();
            return;
        }

        $recordType = Sanitize::asString($_GET['type'] ?? null);
        if ($recordType !== 'A' && $recordType !== 'AAAA' && $recordType !== 'TXT') {
            http_response_code(400);
            echo 'type can only be A, AAAA or TXT';
            return;
        }

        $error = self::validateValue($value, $recordType);
        if ($error !== null) {
            http_response_code(400);
            echo $error;
            return;
        }

        $fqdn = $name !== '' ? $name . '.' . $domain : $domain;

        try {
            [$recordName, $zone] = FqdnUtil::splitFqdn($fqdn);
        } catch (\InvalidArgumentException) {
            http_response_code(400);
            echo 'invalid fqdn';
            return;
        }

        if (!$this->auth->checkPermission($fqdn, $user)) {
            $this->log->info('directadmin: permission denied for user ' . $creds[0] . ' on ' . $fqdn);
            http_response_code(403);
            return;
        }

        try {
            $this->dns->update(new RequestData($fqdn, $recordName, $zone, $value, $recordType));
        } catch (\Throwable $e) {
            $this->log->error('directadmin: DNS update failed for ' . $fqdn . ': ' . $e->getMessage());
            http_response_code(500);
            return;
        }

        $this->log->info('directadmin: updated ' . $fqdn . ' ' . $recordType . ' ' . $value);
        $this->respondOk();
    }

    public function domainPointer(): void
    {
        http_response_code(200);
    }

    private function respondOk(): void
    {
        header('Content-Type: application/x-www-form-urlencoded');
        echo http_build_query(['error' => '0', 'text' => 'OK']);
    }

    private static function validateValue(string $value, string $recordType): ?string
    {
        if ($recordType === 'A' && filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return 'invalid ipv4 address';
        }
        if ($recordType === 'AAAA' && filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
            return 'invalid ipv6 address';
        }
        if ($recordType === 'TXT') {
            return Sanitize::validateTxt($value);
        }

        return null;
    }
}
