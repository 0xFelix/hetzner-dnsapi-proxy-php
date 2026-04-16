<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy;

class RateLimiter
{
    public function __construct(
        private readonly string $path,
        private readonly int $maxAttempts = 10,
        private readonly int $durationSeconds = 3600,
        private readonly int $windowSeconds = 900,
    ) {}

    public function isBlocked(string $ip): bool
    {
        return $this->withLock(function (array &$data) use ($ip): bool {
            $entry = $data[$ip] ?? null;
            if ($entry === null) {
                return false;
            }

            if (($entry['locked_until'] ?? 0) > time()) {
                return true;
            }

            if ($this->isStale($entry)) {
                unset($data[$ip]);
            }

            return false;
        });
    }

    /** Record a failed attempt. Returns true if this failure triggered a lockout. */
    public function recordFailure(string $ip): bool
    {
        return $this->withLock(function (array &$data) use ($ip): bool {
            $now = time();
            $entry = $data[$ip] ?? null;

            if ($entry === null || $this->isStale($entry)) {
                $entry = ['count' => 0, 'last_attempt' => $now];
            }

            $entry['count']++;
            $entry['last_attempt'] = $now;
            $locked = false;

            if ($entry['count'] >= $this->maxAttempts && !isset($entry['locked_until'])) {
                $entry['locked_until'] = $now + $this->durationSeconds;
                $locked = true;
            }

            $data[$ip] = $entry;
            $this->cleanup($data);

            return $locked;
        });
    }

    public function reset(string $ip): void
    {
        $this->withLock(function (array &$data) use ($ip): bool {
            unset($data[$ip]);
            return false;
        });
    }

    /** @param callable(array<string, mixed>&): bool $fn */
    private function withLock(callable $fn): bool
    {
        $fh = fopen($this->path, 'c+');
        if ($fh === false) {
            return false;
        }

        $data = [];
        try {
            flock($fh, LOCK_EX);
            $json = stream_get_contents($fh);
            $data = json_decode($json ?: '{}', true) ?: [];

            $result = $fn($data);

            fseek($fh, 0);
            ftruncate($fh, 0);
            if (!empty($data)) {
                fwrite($fh, (string) json_encode($data));
            }

            return $result;
        } finally {
            flock($fh, LOCK_UN);
            fclose($fh);

            if (empty($data) && file_exists($this->path)) {
                @unlink($this->path);
            }
        }
    }

    /** @param array{count: int, locked_until?: int, last_attempt?: int} $entry */
    private function isStale(array $entry): bool
    {
        if (isset($entry['locked_until'])) {
            return $entry['locked_until'] <= time();
        }

        return (time() - ($entry['last_attempt'] ?? 0)) >= $this->windowSeconds;
    }

    /** @param array<string, array{count: int, locked_until?: int, last_attempt?: int}> $data */
    private function cleanup(array &$data): void
    {
        foreach ($data as $ip => $entry) {
            if ($this->isStale($entry)) {
                unset($data[$ip]);
            }
        }
    }
}
