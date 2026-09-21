# Instructions

- Always sign off git commits with `-s` (e.g. `git commit -s -m "..."`)
- Use plain ASCII characters only - no em dashes, smart quotes, smileys, or other Unicode punctuation. Prefer single dashes (`-`) over em dashes.
- Prefer conciseness and brevity in code comments, commit messages, and prose as long as it does not sacrifice clarity or context.

# Project

PHP DNS API proxy for Hetzner Cloud DNS, compatible with [hetzner-dnsapi-proxy](https://github.com/0xFelix/hetzner-dnsapi-proxy) endpoints. Designed for deployment on shared webhosting.

## Stack

- PHP >= 8.4
- `lkdevelopment/hetzner-cloud-php-sdk` v3 for Hetzner Cloud API
- `jeremykendall/php-domain-parser` v6 for FQDN splitting
- PHPUnit 13 for testing
- PHPStan for static analysis

## Layout

- `src/` - Application code (PSR-4 namespace `HetznerDnsapiProxy\`)
- `src/Handler/` - Endpoint handlers (Plain, NicUpdate, AcmeDns, HttpReq,
  DirectAdmin). All are wired in `public/index.php`; each is gated on its
  name being listed in the `endpoints` config option.
- `bin/` - Maintenance scripts (public suffix list download)
- `tests/Unit/` - Unit tests (no network calls)
- `tests/Integration/` - Integration tests with mock DNS service
- `public/` - Web root (index.php entry point, .htaccess)
- `config.php` - Runtime config (gitignored, see config.sample.php)
- `data/` - Downloaded public suffix list (auto-fetched by composer),
  plus runtime state files (app.log, token_bucket.json, rate_limit.json).
  Protected by `data/.htaccess` (`Require all denied`).

## Commands

- `composer install` - Install dependencies and download public suffix list
- `composer test` - Run all tests (PHPUnit)
- `composer lint` - Code style check (php-cs-fixer) + static analysis (PHPStan)
- `composer fmt` - Apply code style fixes
- `composer audit` - Check dependencies for security advisories
- `vendor/bin/phpunit --testsuite Unit` - Run unit tests only
- `vendor/bin/phpunit --testsuite Integration` - Run integration tests only
- `php -S localhost:8080 -t public/` - Start dev server

Always run `composer lint` and `composer test` before submitting changes.
PHPStan runs at level `max`; do not lower it or add a baseline.

The public suffix list is fetched by composer's install hook. It is skipped
when the local copy is under 30 days old, and a failed download does not fail
the install when a copy already exists. Force a refresh with
`composer update-psl-force`.

## Request handling

Handlers share the `Handler\AuthenticatesRequests` trait, which owns the
lockout check, credential extraction, authentication and failure accounting.
A handler overrides `extractCredentials()` (acme-dns uses API-key headers) or
`rejectUnauthenticated()` (DynDNS2 adds `badauth`) where it differs, and
supplies `rejectRateLimited()`, which the front controller also calls for the
global token-bucket rejection so both paths cannot drift.

Read superglobals through `Sanitize::asString()`, never directly: PHP decodes
`?hostname[]=x` into an array, and handing that to a string-typed validator
raises a TypeError.

All log output goes through `Logger`, which escapes control characters so one
entry stays on one line.

## Rate limiting and lockout

Per-client-IP token-bucket rate limiting (`TokenBucket`) and auth-failure
lockout (`RateLimiter`) are always enabled. Both store state via `JsonStore`,
which holds `flock(LOCK_EX)` across the whole read-modify-write and **fails
closed** if the state file cannot be opened. Configuration is in `config.php`
(see `config.sample.php` for available options and defaults).

`JsonStore` never unlinks its file; an empty map is a 0-byte file. Deleting it
ends the lock's protection, because a process that opened the path before the
unlink and takes the lock after it operates on an orphaned inode while a
newcomer locks a fresh one. Entries are narrowed on read, so a corrupt state
file degrades instead of crashing, and the map is capped at
`JsonStore::MAX_ENTRIES`.

## Client IP resolution

`ClientIp::fromServer()` returns `REMOTE_ADDR` by default. If
`client_ip_header` is configured, the forwarded header is only honored
when `REMOTE_ADDR` is listed in `trusted_proxies` - otherwise it is
ignored so clients cannot spoof the header to bypass rate limiting or
lockout. The resolved IP is passed to handlers and the logger.
