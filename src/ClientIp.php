<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy;

class ClientIp
{
    /**
     * Resolve the client IP, optionally honoring a forwarded-for header
     * from trusted proxies.
     *
     * @param string[] $trustedProxies list of proxy IPs whose forwarded
     *                                  headers should be believed
     */
    public static function resolve(
        string $remoteAddr,
        ?string $headerName,
        array $trustedProxies,
        string $headerValue,
    ): string {
        if ($remoteAddr === '' || $headerName === null || $trustedProxies === []) {
            return $remoteAddr;
        }

        if (!in_array($remoteAddr, $trustedProxies, true)) {
            return $remoteAddr;
        }

        if ($headerValue === '') {
            return $remoteAddr;
        }

        // Walk from rightmost (closest to us) backward; skip any IP that
        // is itself a trusted proxy. First non-proxy IP is the client.
        $parts = array_reverse(array_map('trim', explode(',', $headerValue)));
        foreach ($parts as $candidate) {
            if ($candidate === '') {
                continue;
            }
            if (filter_var($candidate, FILTER_VALIDATE_IP) === false) {
                return $remoteAddr;
            }
            if (!in_array($candidate, $trustedProxies, true)) {
                return $candidate;
            }
        }

        return $remoteAddr;
    }

    /**
     * Resolve using $_SERVER and the config options.
     *
     * @param string[] $trustedProxies
     */
    public static function fromServer(?string $headerName, array $trustedProxies): string
    {
        $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '';
        $headerValue = '';
        if ($headerName !== null) {
            $key = 'HTTP_' . strtoupper(str_replace('-', '_', $headerName));
            $headerValue = (string) ($_SERVER[$key] ?? '');
        }
        return self::resolve($remoteAddr, $headerName, $trustedProxies, $headerValue);
    }
}
