<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy;

interface DnsServiceInterface
{
    public function update(RequestData $data): void;
}
