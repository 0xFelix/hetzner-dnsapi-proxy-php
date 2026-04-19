<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy;

class TokenBucket
{
    public function __construct(
        private readonly string $path,
        private readonly float $rps = 5.0,
        private readonly int $burst = 10,
        private readonly int $idleSeconds = 600,
    ) {}

    public function allow(string $key): bool
    {
        // Fail closed (deny) if the state file can't be opened — rate limiting
        // is a security control and a broken store shouldn't silently disable it.
        return $this->withLock(false, function (array &$data) use ($key): bool {
            $now = microtime(true);
            $entry = $data[$key] ?? null;

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

    /** @param array<string, array{tokens: float, last: float}> $data */
    private function cleanup(array &$data, float $now): void
    {
        foreach ($data as $key => $entry) {
            if (($now - $entry['last']) >= $this->idleSeconds) {
                unset($data[$key]);
            }
        }
    }

    /** @param callable(array<string, mixed>&): bool $fn */
    private function withLock(bool $failResult, callable $fn): bool
    {
        $fh = @fopen($this->path, 'c+');
        if ($fh === false) {
            error_log('TokenBucket: failed to open ' . $this->path);
            return $failResult;
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
            } else {
                // Unlink while the lock is held so a racing writer can't
                // have its data silently deleted after we release.
                @unlink($this->path);
            }

            return $result;
        } finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
    }
}
