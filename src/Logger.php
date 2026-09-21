<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy;

class Logger
{
    /** Rotate once the log passes this size, so it cannot grow without bound. */
    private const MAX_BYTES = 5 * 1024 * 1024;

    public function __construct(
        private readonly string $path,
        private readonly ?string $clientIp = null,
    ) {}

    public function info(string $message): void
    {
        $this->write('INFO', $message);
    }

    public function error(string $message): void
    {
        $this->write('ERROR', $message);
    }

    private function write(string $level, string $message): void
    {
        $ip = $this->clientIp ?? '-';
        $line = date('Y-m-d H:i:s') . ' [' . $level . '] [' . self::escape($ip) . '] '
            . self::escape($message) . "\n";

        $this->rotate();

        // Suppressed: an unwritable data/ must not emit a warning into the
        // response body, which would corrupt the text/plain protocol replies.
        @file_put_contents($this->path, $line, FILE_APPEND | LOCK_EX);
    }

    /**
     * Escape control characters so one log entry stays on one line.
     *
     * Credentials are rejected upstream if they contain control characters, so
     * this is not the only guard, but other logged values - API error messages
     * in particular - can still be multi-line.
     */
    private static function escape(string $value): string
    {
        return addcslashes($value, "\0..\37\177\\");
    }

    private function rotate(): void
    {
        if (!file_exists($this->path) || (int) @filesize($this->path) < self::MAX_BYTES) {
            return;
        }

        @rename($this->path, $this->path . '.1');
    }
}
