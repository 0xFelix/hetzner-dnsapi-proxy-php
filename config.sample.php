<?php

return [
    // Hetzner Cloud API token
    'token' => 'YOUR_HETZNER_CLOUD_API_TOKEN',

    // TTL for created/updated DNS records (seconds)
    'record_ttl' => 60,

    // Active endpoint groups (omit to enable all)
    // Available: 'plain', 'nicupdate'
    // See extra/ for additional handlers (acmedns, httpreq, directadmin)
    // 'endpoints' => ['plain', 'nicupdate'],

    // Per-client-IP token-bucket rate limiting
    // 'rate_limit_rps' => 5.0,
    // 'rate_limit_burst' => 10,
    // 'rate_limit_idle_seconds' => 600,

    // Auth-failure lockout: lock out an IP after max_attempts failures
    // within window_seconds for duration_seconds
    // 'lockout_max_attempts' => 10,
    // 'lockout_duration_seconds' => 3600,
    // 'lockout_window_seconds' => 900,

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
