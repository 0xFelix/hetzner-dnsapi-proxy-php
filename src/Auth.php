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

        if ($username !== '' && $password !== '') {
            return [$username, $password];
        }

        return null;
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

        foreach ($user['domains'] as $domain) {
            if ($fqdn === $domain || self::isSubDomain($fqdn, $domain)) {
                return true;
            }
        }

        return false;
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
