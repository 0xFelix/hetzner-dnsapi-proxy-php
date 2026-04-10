<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy\Tests;

use HetznerDnsapiProxy\DnsServiceInterface;
use HetznerDnsapiProxy\RequestData;

class MockDnsService implements DnsServiceInterface
{
    /** @var RequestData[] */
    public array $updateCalls = [];

    public bool $throwOnUpdate = false;

    public function update(RequestData $data): void
    {
        if ($this->throwOnUpdate) {
            throw new \RuntimeException('API error');
        }
        $this->updateCalls[] = $data;
    }
}
