<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy;

class RateLimiter
{
    private readonly JsonStore $store;

    public function __construct(
        string $path,
        private readonly int $maxAttempts = 10,
        private readonly int $durationSeconds = 3600,
        private readonly int $windowSeconds = 900,
    ) {
        $this->store = new JsonStore($path, 'RateLimiter');
    }

    public function isBlocked(string $ip): bool
    {
        // Fail closed: if the state file can't be opened, treat every IP as
        // blocked rather than silently disabling lockout.
        return $this->withLock(true, function (array &$data) use ($ip): bool {
            $entry = self::entry($data[$ip] ?? null);
            if ($entry === null) {
                unset($data[$ip]);

                return false;
            }

            if ($entry['locked_until'] > time()) {
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
        // If the store is broken we can't tell whether this triggered a
        // lockout; report false. isBlocked() will already be denying requests.
        return $this->withLock(false, function (array &$data) use ($ip): bool {
            $now = time();
            $entry = self::entry($data[$ip] ?? null);

            if ($entry === null || $this->isStale($entry)) {
                $entry = ['count' => 0, 'last_attempt' => $now, 'locked_until' => 0];
            }

            $entry['count']++;
            $entry['last_attempt'] = $now;
            $locked = false;

            if ($entry['count'] >= $this->maxAttempts && $entry['locked_until'] === 0) {
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
        $this->withLock(false, function (array &$data) use ($ip): bool {
            unset($data[$ip]);

            return false;
        });
    }

    /**
     * Narrow a stored entry, or null if it is missing or malformed.
     *
     * The state file can be corrupt or hand-edited, so nothing read back from
     * it is assumed to have the right shape. A locked_until of 0 means "not
     * locked", which replaces the previous isset() checks on an optional key.
     *
     * @return array{count: int, last_attempt: int, locked_until: int}|null
     */
    private static function entry(mixed $raw): ?array
    {
        if (!is_array($raw) || !isset($raw['count']) || !is_numeric($raw['count'])) {
            return null;
        }

        $lastAttempt = $raw['last_attempt'] ?? 0;
        $lockedUntil = $raw['locked_until'] ?? 0;

        return [
            'count' => (int) $raw['count'],
            'last_attempt' => is_numeric($lastAttempt) ? (int) $lastAttempt : 0,
            'locked_until' => is_numeric($lockedUntil) ? (int) $lockedUntil : 0,
        ];
    }

    /** @param array{count: int, last_attempt: int, locked_until: int} $entry */
    private function isStale(array $entry): bool
    {
        if ($entry['locked_until'] > 0) {
            return $entry['locked_until'] <= time();
        }

        return (time() - $entry['last_attempt']) >= $this->windowSeconds;
    }

    /** @param array<string, mixed> $data */
    private function cleanup(array &$data): void
    {
        foreach ($data as $ip => $raw) {
            $entry = self::entry($raw);
            if ($entry === null || $this->isStale($entry)) {
                unset($data[$ip]);
            }
        }
    }

    /** @param callable(array<string, mixed>&): bool $fn */
    private function withLock(bool $failResult, callable $fn): bool
    {
        return $this->store->mutate(
            $failResult,
            $fn,
            static fn (mixed $entry): float => (float) (self::entry($entry)['last_attempt'] ?? 0),
        );
    }
}
