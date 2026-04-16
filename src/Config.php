<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy;

use InvalidArgumentException;

class Config
{
    public const ENDPOINTS = ['plain', 'nicupdate'];

    /** @var array<array{username: string, password: string, domains: string[]}> */
    public readonly array $users;

    public readonly string $token;

    public readonly int $recordTtl;

    /** @var string[] */
    public readonly array $endpoints;

    public readonly float $rateLimitRps;

    public readonly int $rateLimitBurst;

    public readonly int $rateLimitIdleSeconds;

    public readonly int $lockoutMaxAttempts;

    public readonly int $lockoutDurationSeconds;

    public readonly int $lockoutWindowSeconds;

    /**
     * @param array<array{username: string, password: string, domains: string[]}> $users
     * @param string[] $endpoints
     */
    private function __construct(
        string $token,
        int $recordTtl,
        array $users,
        array $endpoints,
        float $rateLimitRps,
        int $rateLimitBurst,
        int $rateLimitIdleSeconds,
        int $lockoutMaxAttempts,
        int $lockoutDurationSeconds,
        int $lockoutWindowSeconds,
    ) {
        $this->token = $token;
        $this->recordTtl = $recordTtl;
        $this->users = $users;
        $this->endpoints = $endpoints;
        $this->rateLimitRps = $rateLimitRps;
        $this->rateLimitBurst = $rateLimitBurst;
        $this->rateLimitIdleSeconds = $rateLimitIdleSeconds;
        $this->lockoutMaxAttempts = $lockoutMaxAttempts;
        $this->lockoutDurationSeconds = $lockoutDurationSeconds;
        $this->lockoutWindowSeconds = $lockoutWindowSeconds;
    }

    public static function load(string $path): self
    {
        if (!file_exists($path)) {
            throw new InvalidArgumentException('Config file not found: ' . basename($path));
        }

        $config = require $path;
        if (!is_array($config)) {
            throw new InvalidArgumentException('Config file must return an array');
        }

        $token = $config['token'] ?? '';
        if ($token === '') {
            throw new InvalidArgumentException('Config: token is required');
        }

        $recordTtl = (int) ($config['record_ttl'] ?? 60);

        $users = $config['users'] ?? [];
        if (empty($users)) {
            throw new InvalidArgumentException('Config: at least one user is required');
        }

        $seen = [];
        foreach ($users as $i => $user) {
            if (empty($user['username']) || empty($user['password']) || empty($user['domains'])) {
                throw new InvalidArgumentException(
                    'Config: user at index ' . $i . ' must have username, password, and domains'
                );
            }
            if (isset($seen[$user['username']])) {
                throw new InvalidArgumentException(
                    'Config: duplicate username: ' . $user['username']
                );
            }
            $seen[$user['username']] = true;
        }

        $endpoints = $config['endpoints'] ?? self::ENDPOINTS;
        $invalid = array_diff($endpoints, self::ENDPOINTS);
        if (!empty($invalid)) {
            throw new InvalidArgumentException(
                'Config: invalid endpoints: ' . implode(', ', $invalid)
            );
        }

        $rateLimitRps = (float) ($config['rate_limit_rps'] ?? 5.0);
        if ($rateLimitRps <= 0) {
            throw new InvalidArgumentException('Config: rate_limit_rps must be > 0');
        }
        $rateLimitBurst = (int) ($config['rate_limit_burst'] ?? 10);
        if ($rateLimitBurst <= 0) {
            throw new InvalidArgumentException('Config: rate_limit_burst must be > 0');
        }
        $rateLimitIdleSeconds = (int) ($config['rate_limit_idle_seconds'] ?? 600);
        if ($rateLimitIdleSeconds <= 0) {
            throw new InvalidArgumentException('Config: rate_limit_idle_seconds must be > 0');
        }

        $lockoutMaxAttempts = (int) ($config['lockout_max_attempts'] ?? 10);
        if ($lockoutMaxAttempts <= 0) {
            throw new InvalidArgumentException('Config: lockout_max_attempts must be > 0');
        }
        $lockoutDurationSeconds = (int) ($config['lockout_duration_seconds'] ?? 3600);
        if ($lockoutDurationSeconds <= 0) {
            throw new InvalidArgumentException('Config: lockout_duration_seconds must be > 0');
        }
        $lockoutWindowSeconds = (int) ($config['lockout_window_seconds'] ?? 900);
        if ($lockoutWindowSeconds <= 0) {
            throw new InvalidArgumentException('Config: lockout_window_seconds must be > 0');
        }

        return new self(
            $token,
            $recordTtl,
            $users,
            $endpoints,
            $rateLimitRps,
            $rateLimitBurst,
            $rateLimitIdleSeconds,
            $lockoutMaxAttempts,
            $lockoutDurationSeconds,
            $lockoutWindowSeconds,
        );
    }
}
