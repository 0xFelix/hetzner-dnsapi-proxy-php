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

    /**
     * @param array<array{username: string, password: string, domains: string[]}> $users
     * @param string[] $endpoints
     */
    private function __construct(string $token, int $recordTtl, array $users, array $endpoints)
    {
        $this->token = $token;
        $this->recordTtl = $recordTtl;
        $this->users = $users;
        $this->endpoints = $endpoints;
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

        return new self($token, $recordTtl, $users, $endpoints);
    }
}
