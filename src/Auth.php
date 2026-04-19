<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy;

class Auth
{
    private Config $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * Extract credentials from Basic Auth headers.
     *
     * @return array{string, string}|null [username, password] or null
     */
    public function extractBasicAuth(): ?array
    {
        $username = $_SERVER['PHP_AUTH_USER'] ?? '';
        $password = $_SERVER['PHP_AUTH_PW'] ?? '';

        if ($username === '' || $password === '') {
            return null;
        }

        // Reject credentials with control characters to prevent log injection
        // and other misuse; real usernames/passwords should never contain them.
        if (Sanitize::hasControl($username) || Sanitize::hasControl($password)) {
            return null;
        }

        return [$username, $password];
    }

    /**
     * Extract credentials from X-Api-User / X-Api-Key headers.
     *
     * @return array{string, string}|null [username, password] or null
     */
    public function extractApiKeyAuth(): ?array
    {
        $username = $_SERVER['HTTP_X_API_USER'] ?? '';
        $password = $_SERVER['HTTP_X_API_KEY'] ?? '';

        if ($username === '' || $password === '') {
            return null;
        }

        if (Sanitize::hasControl($username) || Sanitize::hasControl($password)) {
            return null;
        }

        return [$username, $password];
    }

    /**
     * Authenticate a user by username and password.
     *
     * @return array{username: string, domains: string[]}|null
     */
    public function authenticate(string $username, string $password): ?array
    {
        if ($username === '' || $password === '') {
            return null;
        }

        return $this->findUser($username, $password);
    }

    /**
     * Check if the given user is permitted to update the given FQDN.
     *
     * @param array{username: string, domains: string[]} $user
     */
    public function checkPermission(string $fqdn, array $user): bool
    {
        if ($fqdn === '') {
            return false;
        }

        // DNS is case-insensitive; configured domains are normalized to lowercase.
        $fqdn = strtolower($fqdn);

        // Reject FQDNs with empty labels (leading/trailing dot, double dot).
        if (in_array('', explode('.', $fqdn), true)) {
            return false;
        }

        foreach ($user['domains'] as $domain) {
            if ($fqdn === $domain || self::isSubDomain($fqdn, $domain)) {
                return true;
            }
        }

        return false;
    }

    /**
     * List the domains a user can manage, with wildcard prefixes stripped.
     *
     * @param array{username: string, domains: string[]} $user
     * @return string[]
     */
    public function getDomains(array $user): array
    {
        $domains = [];
        foreach ($user['domains'] as $domain) {
            $domains[] = str_starts_with($domain, '*.') ? substr($domain, 2) : $domain;
        }

        return array_values(array_unique($domains));
    }

    /**
     * Find a user by username and password.
     *
     * @return array{username: string, domains: string[]}|null
     */
    private function findUser(string $username, string $password): ?array
    {
        $match = null;
        foreach ($this->config->users as $user) {
            $userMatch = hash_equals($user['username'], $username);
            $passMatch = hash_equals($user['password'], $password);
            if ($userMatch && $passMatch) {
                unset($user['password']);
                $match = $user;
            }
        }
        return $match;
    }

    /**
     * Check if $sub is a subdomain matching wildcard $parent.
     * Parent must start with "*." (e.g. "*.example.com").
     */
    public static function isSubDomain(string $sub, string $parent): bool
    {
        $subParts = explode('.', $sub);
        $parentParts = explode('.', $parent);

        // Parent domain must be a wildcard domain
        // The subdomain must have at least the same amount of parts as the parent domain
        if ($parentParts[0] !== '*' || count($subParts) < count($parentParts)) {
            return false;
        }

        // All domain parts up to the asterisk must match
        $parentSuffix = array_slice($parentParts, 1);
        $offset = count($subParts) - count($parentSuffix);

        return array_slice($subParts, $offset) === $parentSuffix;
    }
}
