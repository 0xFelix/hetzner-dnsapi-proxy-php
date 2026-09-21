<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy;

use InvalidArgumentException;

class Config
{
    public const ENDPOINTS = ['plain', 'nic', 'acmedns', 'httpreq', 'directadmin'];

    private const PLACEHOLDER_TOKEN = 'YOUR_HETZNER_CLOUD_API_TOKEN';

    /**
     * @param array<array{username: string, password: string, domains: string[]}> $users
     * @param string[] $endpoints
     * @param string[] $trustedProxies
     */
    private function __construct(
        public readonly string $token,
        public readonly int $recordTtl,
        public readonly array $users,
        public readonly array $endpoints,
        public readonly float $rateLimitRps,
        public readonly int $rateLimitBurst,
        public readonly int $rateLimitIdleSeconds,
        public readonly int $lockoutMaxAttempts,
        public readonly int $lockoutDurationSeconds,
        public readonly int $lockoutWindowSeconds,
        public readonly array $trustedProxies,
        public readonly ?string $clientIpHeader,
    ) {}

    public static function load(string $path): self
    {
        if (!file_exists($path)) {
            throw new InvalidArgumentException('Config file not found: ' . basename($path));
        }

        $config = require $path;
        if (!is_array($config)) {
            throw new InvalidArgumentException('Config file must return an array');
        }

        $trustedProxies = self::trustedProxies($config);

        return new self(
            self::token($config),
            self::positiveInt($config, 'record_ttl', 60),
            self::users($config),
            self::endpoints($config),
            self::positiveFloat($config, 'rate_limit_rps', 5.0),
            self::positiveInt($config, 'rate_limit_burst', 10),
            self::positiveInt($config, 'rate_limit_idle_seconds', 600),
            self::positiveInt($config, 'lockout_max_attempts', 10),
            self::positiveInt($config, 'lockout_duration_seconds', 3600),
            self::positiveInt($config, 'lockout_window_seconds', 900),
            $trustedProxies,
            self::clientIpHeader($config, $trustedProxies),
        );
    }

    /** @param array<mixed> $config */
    private static function token(array $config): string
    {
        $token = $config['token'] ?? '';
        if (!is_string($token) || $token === '') {
            throw new InvalidArgumentException('Config: token is required');
        }
        if ($token === self::PLACEHOLDER_TOKEN) {
            throw new InvalidArgumentException('Config: token is still the placeholder value');
        }

        return $token;
    }

    /**
     * @param array<mixed> $config
     * @return array<array{username: string, password: string, domains: string[]}>
     */
    private static function users(array $config): array
    {
        $users = $config['users'] ?? [];
        if (!is_array($users) || $users === []) {
            throw new InvalidArgumentException('Config: at least one user is required');
        }

        $result = [];
        $seen = [];
        foreach ($users as $i => $user) {
            $where = 'Config: user at index ' . $i;

            if (!is_array($user)) {
                throw new InvalidArgumentException($where . ' must be an array');
            }

            // Explicit string checks rather than empty(), which rejects "0".
            $username = $user['username'] ?? null;
            $password = $user['password'] ?? null;
            if (!is_string($username) || $username === '' || !is_string($password) || $password === '') {
                throw new InvalidArgumentException(
                    $where . ' must have a non-empty username and password',
                );
            }

            if (isset($seen[$username])) {
                throw new InvalidArgumentException('Config: duplicate username: ' . $username);
            }
            $seen[$username] = true;

            $result[] = [
                'username' => $username,
                'password' => $password,
                'domains' => self::domains($user['domains'] ?? null, $where),
            ];
        }

        return $result;
    }

    /** @return string[] */
    private static function domains(mixed $domains, string $where): array
    {
        if (!is_array($domains) || $domains === []) {
            throw new InvalidArgumentException($where . ' must have a non-empty domains list');
        }

        $result = [];
        foreach ($domains as $domain) {
            if (!is_string($domain) || $domain === '') {
                throw new InvalidArgumentException($where . ' has a non-string domain');
            }
            // Normalize domains to lowercase so checks match DNS's case-insensitive semantics.
            $result[] = strtolower($domain);
        }

        return $result;
    }

    /**
     * @param array<mixed> $config
     * @return string[]
     */
    private static function endpoints(array $config): array
    {
        $endpoints = $config['endpoints'] ?? self::ENDPOINTS;
        if (!is_array($endpoints)) {
            throw new InvalidArgumentException('Config: endpoints must be a list of strings');
        }

        foreach ($endpoints as $endpoint) {
            if (!is_string($endpoint)) {
                throw new InvalidArgumentException('Config: endpoints must be a list of strings');
            }
        }

        /** @var string[] $endpoints */
        $invalid = array_diff($endpoints, self::ENDPOINTS);
        if ($invalid !== []) {
            throw new InvalidArgumentException(
                'Config: invalid endpoints: ' . implode(', ', $invalid),
            );
        }

        return array_values($endpoints);
    }

    /**
     * @param array<mixed> $config
     * @return string[]
     */
    private static function trustedProxies(array $config): array
    {
        $trustedProxies = $config['trusted_proxies'] ?? [];
        if (!is_array($trustedProxies)) {
            throw new InvalidArgumentException('Config: trusted_proxies must be an array of IP strings');
        }

        $result = [];
        foreach ($trustedProxies as $proxy) {
            if (!is_string($proxy) || filter_var($proxy, FILTER_VALIDATE_IP) === false) {
                throw new InvalidArgumentException('Config: trusted_proxies contains an invalid IP');
            }
            $result[] = $proxy;
        }

        return $result;
    }

    /**
     * @param array<mixed> $config
     * @param string[] $trustedProxies
     */
    private static function clientIpHeader(array $config, array $trustedProxies): ?string
    {
        $clientIpHeader = $config['client_ip_header'] ?? null;
        if ($clientIpHeader === null) {
            return null;
        }

        if (!is_string($clientIpHeader) || $clientIpHeader === '') {
            throw new InvalidArgumentException('Config: client_ip_header must be a non-empty string');
        }
        if (!preg_match('/^[A-Za-z0-9-]+$/', $clientIpHeader)) {
            throw new InvalidArgumentException(
                'Config: client_ip_header must only contain letters, digits, and dashes',
            );
        }
        if ($trustedProxies === []) {
            throw new InvalidArgumentException(
                'Config: client_ip_header requires at least one trusted_proxies entry',
            );
        }

        return $clientIpHeader;
    }

    /** @param array<mixed> $config */
    private static function positiveInt(array $config, string $key, int $default): int
    {
        $value = isset($config[$key]) ? (int) self::numeric($config, $key) : $default;
        if ($value <= 0) {
            throw new InvalidArgumentException('Config: ' . $key . ' must be > 0');
        }

        return $value;
    }

    /** @param array<mixed> $config */
    private static function positiveFloat(array $config, string $key, float $default): float
    {
        $value = isset($config[$key]) ? (float) self::numeric($config, $key) : $default;
        if ($value <= 0) {
            throw new InvalidArgumentException('Config: ' . $key . ' must be > 0');
        }

        return $value;
    }

    /** @param array<mixed> $config */
    private static function numeric(array $config, string $key): int|float
    {
        $value = $config[$key];
        if (!is_numeric($value)) {
            throw new InvalidArgumentException('Config: ' . $key . ' must be a number');
        }

        return $value + 0;
    }
}
