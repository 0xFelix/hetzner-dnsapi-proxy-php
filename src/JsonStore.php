<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy;

/**
 * File-backed JSON map guarded by an exclusive lock.
 *
 * The file is never unlinked. Deleting it ends the lock's protection: a
 * process that opened the path before the unlink and takes the lock after it
 * operates on an orphaned inode, while a newcomer locks a fresh one, so both
 * mutate state at once and updates are lost. Unlinking under the lock narrows
 * that window but does not close it. An empty map is stored as a 0-byte file
 * instead, which removes the failure mode entirely.
 */
class JsonStore
{
    /** Hard cap on entries, so a spray of distinct keys cannot grow the file without bound. */
    public const MAX_ENTRIES = 10000;

    public function __construct(
        private readonly string $path,
        private readonly string $label,
    ) {}

    /**
     * Read the map, hand it to $fn for mutation, write it back under the lock.
     *
     * @param bool $failResult returned when the file cannot be opened at all
     * @param callable(array<string, mixed>&): bool $fn
     * @param callable(mixed): float $timestampOf orders entries for eviction
     */
    public function mutate(bool $failResult, callable $fn, callable $timestampOf): bool
    {
        $fh = @fopen($this->path, 'c+');
        if ($fh === false) {
            error_log($this->label . ': failed to open ' . $this->path);

            return $failResult;
        }

        try {
            flock($fh, LOCK_EX);

            $json = stream_get_contents($fh);
            $data = self::decode($json === false ? '' : $json);

            $result = $fn($data);

            $map = self::asMap($data);
            $this->evictOverflow($map, $timestampOf);

            fseek($fh, 0);
            ftruncate($fh, 0);
            if ($map !== []) {
                fwrite($fh, (string) json_encode($map));
            }

            return $result;
        } finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
    }

    /**
     * Decode the stored map, dropping anything malformed.
     *
     * The file can be corrupt, truncated or hand-edited, so entries are not
     * trusted to have any particular shape - the callers narrow them.
     *
     * @return array<string, mixed>
     */
    private static function decode(string $json): array
    {
        return self::asMap(json_decode($json === '' ? '{}' : $json, true));
    }

    /**
     * Narrow anything to a string-keyed map, dropping the rest.
     *
     * @return array<string, mixed>
     */
    private static function asMap(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        $map = [];
        foreach ($value as $key => $item) {
            if (is_string($key)) {
                $map[$key] = $item;
            }
        }

        return $map;
    }

    /**
     * Drop the oldest entries once MAX_ENTRIES is exceeded.
     *
     * @param array<string, mixed> $data
     * @param callable(mixed): float $timestampOf
     */
    private function evictOverflow(array &$data, callable $timestampOf): void
    {
        $excess = count($data) - self::MAX_ENTRIES;
        if ($excess <= 0) {
            return;
        }

        $timestamps = array_map($timestampOf, $data);
        asort($timestamps);

        foreach (array_slice(array_keys($timestamps), 0, $excess) as $key) {
            unset($data[$key]);
        }
    }
}
