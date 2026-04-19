<?php

return [
    // Hetzner Cloud API token
    'token' => 'YOUR_HETZNER_CLOUD_API_TOKEN',

    // TTL for created/updated DNS records (seconds)
    'record_ttl' => 60,

    // Active endpoint groups (omit to enable all)
    // Available: 'plain', 'nic', 'acmedns', 'httpreq', 'directadmin'
    // Only enable what you actually use - fewer endpoints is less attack surface.
    // 'endpoints' => ['plain', 'nic'],

    // Per-client-IP token-bucket rate limiting
    // 'rate_limit_rps' => 5.0,
    // 'rate_limit_burst' => 10,
    // 'rate_limit_idle_seconds' => 600,

    // Auth-failure lockout: lock out an IP after max_attempts failures
    // within window_seconds for duration_seconds
    // 'lockout_max_attempts' => 10,
    // 'lockout_duration_seconds' => 3600,
    // 'lockout_window_seconds' => 900,

    // If requests arrive via a reverse proxy (CDN, shared hosting front-end),
    // list its IP(s) here and name the header it uses to forward the real
    // client IP. Only set client_ip_header when trusted_proxies is populated;
    // otherwise the header can be spoofed to bypass rate limits and lockout.
    // 'trusted_proxies' => ['203.0.113.10'],
    // 'client_ip_header' => 'X-Forwarded-For',

    // Users with username/password and list of allowed domains
    // Wildcard domains (*.example.com) allow all subdomains
    'users' => [
        [
            'username' => 'alice',
            'password' => 'your-password',
            'domains' => ['example.com', '*.example.com'],
        ],
    ],
];
