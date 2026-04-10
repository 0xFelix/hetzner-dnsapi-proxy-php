# Instructions

- Always sign off git commits with `-s` (e.g. `git commit -s -m "..."`)
- Use plain ASCII characters only - no em dashes, smart quotes, smileys, or other Unicode punctuation. Prefer single dashes (`-`) over em dashes.
- Prefer conciseness and brevity in code comments, commit messages, and prose as long as it does not sacrifice clarity or context.

# Project

PHP DNS API proxy for Hetzner Cloud DNS, compatible with [hetzner-dnsapi-proxy](https://github.com/0xFelix/hetzner-dnsapi-proxy) endpoints. Designed for deployment on shared webhosting.

## Stack

- PHP >= 8.3
- `lkdevelopment/hetzner-cloud-php-sdk` v3 for Hetzner Cloud API
- `jeremykendall/php-domain-parser` v6 for FQDN splitting
- PHPUnit 13 for testing

## Layout

- `src/` - Application code (PSR-4 namespace `HetznerDnsapiProxy\`)
- `src/Handler/` - Endpoint handlers (Plain, NicUpdate)
- `tests/Unit/` - Unit tests (no network calls)
- `tests/Integration/` - Integration tests with mock DNS service
- `public/` - Web root (index.php entry point, .htaccess)
- `config.php` - Runtime config (gitignored, see config.sample.php)
- `data/` - Downloaded public suffix list (auto-fetched by composer)

## Commands

- `composer install` - Install dependencies and download public suffix list
- `vendor/bin/phpunit` - Run all tests
- `vendor/bin/phpunit --testsuite Unit` - Run unit tests only
- `vendor/bin/phpunit --testsuite Integration` - Run integration tests only
- `php -S localhost:8080 -t public/` - Start dev server

## Auth

Passwords are stored as plaintext in config.php.
