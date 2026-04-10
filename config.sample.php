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
