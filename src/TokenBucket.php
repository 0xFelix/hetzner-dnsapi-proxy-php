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
        return $this->withLock(function (array &$data) use ($key): bool {
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
    private function withLock(callable $fn): bool
    {
        $fh = fopen($this->path, 'c+');
        if ($fh === false) {
            return true;
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
}
