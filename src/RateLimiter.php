<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy;

class RateLimiter
{
    private const MAX_ATTEMPTS = 10;
    private const LOCKOUT_SECONDS = 86400; // 24 hours

    public function __construct(
        private readonly string $path,
    ) {}

    public function isBlocked(string $ip): bool
    {
        $entry = $this->loadEntry($ip);
        if ($entry === null) {
            return false;
        }

        if (($entry['locked_until'] ?? 0) > time()) {
            return true;
        }

        // Lockout expired, reset
        if (isset($entry['locked_until'])) {
            $this->removeEntry($ip);
        }

        return false;
    }

    /**
     * Record a failed attempt. Returns true if this failure triggered a lockout.
     */
    public function recordFailure(string $ip): bool
    {
        $data = $this->load();
        $entry = $data[$ip] ?? ['count' => 0];

        // Previously locked out and expired, reset
        if (isset($entry['locked_until']) && $entry['locked_until'] <= time()) {
            $entry = ['count' => 0];
        }

        $entry['count']++;
        $locked = false;

        if ($entry['count'] >= self::MAX_ATTEMPTS && !isset($entry['locked_until'])) {
            $entry['locked_until'] = time() + self::LOCKOUT_SECONDS;
            $locked = true;
        }

        $data[$ip] = $entry;
        $this->cleanup($data);
        $this->save($data);

        return $locked;
    }

    public function reset(string $ip): void
    {
        $this->removeEntry($ip);
    }

    private function loadEntry(string $ip): ?array
    {
        $data = $this->load();
        return $data[$ip] ?? null;
    }

    private function removeEntry(string $ip): void
    {
        $data = $this->load();
        unset($data[$ip]);
        $this->save($data);
    }

    private function load(): array
    {
        if (!file_exists($this->path)) {
            return [];
        }
        $json = file_get_contents($this->path);
        return json_decode($json ?: '{}', true) ?: [];
    }

    private function save(array $data): void
    {
        if (empty($data)) {
            if (file_exists($this->path)) {
                unlink($this->path);
            }
            return;
        }
        file_put_contents($this->path, json_encode($data), LOCK_EX);
    }

    /** Remove expired lockout entries. */
    private function cleanup(array &$data): void
    {
        $now = time();
        foreach ($data as $ip => $entry) {
            if (isset($entry['locked_until']) && $entry['locked_until'] <= $now) {
                unset($data[$ip]);
            }
        }
    }
}
