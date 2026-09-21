<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy\Handler;

use HetznerDnsapiProxy\Sanitize;

/**
 * Shared request preamble: lockout check, credential extraction, auth and
 * failure accounting.
 *
 * Handlers differ only in how they read credentials and what they write when
 * rejecting, so those are overridable rather than duplicated.
 */
trait AuthenticatesRequests
{
    /**
     * Returns the authenticated user, or null once a rejection response has
     * already been written - callers just need a guard clause.
     *
     * @return array{username: string, domains: string[]}|null
     */
    private function authenticateRequest(string $tag, string $clientIp): ?array
    {
        if ($this->rateLimiter->isBlocked($clientIp)) {
            $this->log->info($tag . ': blocked request from locked out IP ' . $clientIp);
            $this->rejectRateLimited();

            return null;
        }

        $creds = $this->extractCredentials();
        if ($creds === null) {
            $this->rejectUnauthenticated();

            return null;
        }

        $user = $this->auth->authenticate($creds[0], $creds[1]);
        if ($user === null) {
            $locked = $this->rateLimiter->recordFailure($clientIp);
            $this->log->info($tag . ': auth failed for user: ' . $creds[0] . ' from ' . $clientIp);
            if ($locked) {
                $this->log->info($tag . ': locked out IP ' . $clientIp . ' after too many failures');
            }
            $this->rejectUnauthenticated();

            return null;
        }

        $this->rateLimiter->reset($clientIp);

        return $user;
    }

    protected function resolveClientIp(): string
    {
        return $this->clientIp ?? Sanitize::asString($_SERVER['REMOTE_ADDR'] ?? null);
    }

    /** @return array{string, string}|null */
    protected function extractCredentials(): ?array
    {
        return $this->auth->extractBasicAuth();
    }

    protected function rejectUnauthenticated(): void
    {
        header('WWW-Authenticate: Basic realm="Restricted"');
        http_response_code(401);
    }

    abstract public function rejectRateLimited(): void;
}
