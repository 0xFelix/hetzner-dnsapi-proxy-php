<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy;

class TokenBucket
{
    private readonly JsonStore $store;

    public function __construct(
        string $path,
        private readonly float $rps = 5.0,
        private readonly int $burst = 10,
        private readonly int $idleSeconds = 600,
    ) {
        $this->store = new JsonStore($path, 'TokenBucket');
    }

    public function allow(string $key): bool
    {
        // Fail closed (deny) if the state file can't be opened - rate limiting
        // is a security control and a broken store shouldn't silently disable it.
        return $this->withLock(false, function (array &$data) use ($key): bool {
            $now = microtime(true);
            $entry = self::entry($data[$key] ?? null);

            if ($entry === null) {
                $tokens = $this->burst - 1.0;
                $allowed = true;
            } else {
                $elapsed = $now - $entry['last'];
                $tokens = min($this->burst, $entry['tokens'] + $elapsed * $this->rps);
                $allowed = $tokens >= 1.0;
                if ($allowed) {
                    $tokens -= 1.0;
                }
            }

            $data[$key] = ['tokens' => $tokens, 'last' => $now];
            $this->cleanup($data, $now);

            return $allowed;
        });
    }

    /**
     * Narrow a stored entry, or null if it is missing or malformed.
     *
     * The state file can be corrupt or hand-edited, so nothing read back from
     * it is assumed to have the right shape.
     *
     * @return array{tokens: float, last: float}|null
     */
    private static function entry(mixed $raw): ?array
    {
        if (!is_array($raw) || !isset($raw['tokens'], $raw['last'])) {
            return null;
        }
        if (!is_numeric($raw['tokens']) || !is_numeric($raw['last'])) {
            return null;
        }

        return ['tokens' => (float) $raw['tokens'], 'last' => (float) $raw['last']];
    }

    /** @param array<string, mixed> $data */
    private function cleanup(array &$data, float $now): void
    {
        foreach ($data as $key => $raw) {
            $entry = self::entry($raw);
            if ($entry === null || ($now - $entry['last']) >= $this->idleSeconds) {
                unset($data[$key]);
            }
        }
    }

    /** @param callable(array<string, mixed>&): bool $fn */
    private function withLock(bool $failResult, callable $fn): bool
    {
        return $this->store->mutate(
            $failResult,
            $fn,
            static fn (mixed $entry): float => self::entry($entry)['last'] ?? 0.0,
        );
    }
}
