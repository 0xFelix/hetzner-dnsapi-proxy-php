<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy;

class Logger
{
    public function __construct(
        private readonly string $path,
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
        $ip = $_SERVER['REMOTE_ADDR'] ?? '-';
        $line = date('Y-m-d H:i:s') . ' [' . $level . '] [' . $ip . '] ' . $message . "\n";
        file_put_contents($this->path, $line, FILE_APPEND | LOCK_EX);
    }
}
