<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy;

class RequestData
{
    public function __construct(
        public readonly string $fullName,
        public readonly string $name,
        public readonly string $zone,
        public readonly string $value,
        public readonly string $type,
    ) {}
}
