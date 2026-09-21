<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy;

class IpUtil
{
    /**
     * Rewrite an address into its canonical form (RFC 5952), collapsing
     * IPv6 zero groups and lowercasing hex digits:
     *
     *   2001:0db8:3c4d:0000:0000:0000:0000:01ff -> 2001:db8:3c4d::1ff
     *
     * IPv4 is returned unchanged, as is anything that is not an address, so
     * this is safe to apply to a value before it has been validated. The
     * operation is idempotent.
     */
    public static function canonicalize(string $ip): string
    {
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return $ip;
        }

        $canonical = @inet_ntop($packed);

        return $canonical === false ? $ip : $canonical;
    }
}
