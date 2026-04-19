# hetzner-dnsapi-proxy-php

PHP DNS API proxy for Hetzner Cloud DNS. Compatible with
[hetzner-dnsapi-proxy](https://github.com/0xFelix/hetzner-dnsapi-proxy)
endpoints. Designed for deployment on shared webhosting with Apache and
mod_rewrite.

## Endpoints

| Method | Path | Auth | Protocol |
|--------|------|------|----------|
| GET | `/plain/update` | Basic Auth | Custom |
| GET | `/nic/update` | Basic Auth | DynDNS2 |

Additional handlers (acme-dns, lego httpreq, DirectAdmin) are available in the
`extra/` directory. See `extra/README.md` for instructions.

Endpoints can be selectively enabled via the `endpoints` config option.

## Requirements

- PHP >= 8.4
- Apache with mod_rewrite
- Composer

## Setup

```sh
git clone https://github.com/0xFelix/hetzner-dnsapi-proxy-php.git
cd hetzner-dnsapi-proxy-php
composer install --no-dev
```

## Configuration

Copy the sample config and edit it:

```sh
cp config.sample.php config.php
```

### API token

Set `token` to your Hetzner Cloud API token. Treat this as a secret - it
grants full DNS control over your Hetzner Cloud project.

### Passwords

Passwords are stored as plaintext in config.php. Since the file also contains
the Hetzner API token, it must be kept secret regardless - see the security
checklist below.

### Endpoint selection

By default both endpoints (`plain` and `nicupdate`) are enabled. To restrict:

```php
'endpoints' => ['plain'],
```

Only enable the endpoints you actually use. Fewer endpoints means less attack
surface.

### Rate limiting and auth-failure lockout

Both features are always enabled and work per client IP.

**Token-bucket rate limiting** throttles all requests. Excess requests get
HTTP 429 (or the DynDNS2 `abuse` token on `/nic/update`).

| Option | Default | Description |
|--------|---------|-------------|
| `rate_limit_rps` | `5.0` | Tokens refilled per second |
| `rate_limit_burst` | `10` | Maximum burst size |
| `rate_limit_idle_seconds` | `600` | Seconds before idle bucket is removed |

**Auth-failure lockout** locks out a client IP after repeated auth failures.
A successful auth clears the counter.

| Option | Default | Description |
|--------|---------|-------------|
| `lockout_max_attempts` | `10` | Failures before lockout |
| `lockout_duration_seconds` | `3600` | Lockout duration |
| `lockout_window_seconds` | `900` | Window for counting failures |

### Reverse proxy / forwarded client IP

If requests reach the proxy via a CDN or shared-hosting front-end, set
`trusted_proxies` to the IP(s) of the front-end and `client_ip_header` to
the header they use. The forwarded header is only honored when
`REMOTE_ADDR` is in `trusted_proxies`; otherwise it is ignored so clients
cannot spoof it to bypass rate limiting or lockout.

```php
'trusted_proxies' => ['203.0.113.10'],
'client_ip_header' => 'X-Forwarded-For',
```

### Example config

```php
<?php

return [
    'token' => 'your-hetzner-cloud-api-token',
    'record_ttl' => 60,
    'endpoints' => ['plain'],
    'users' => [
        [
            'username' => 'alice',
            'password' => 'alices-password',
            'domains' => ['example.com', '*.example.com'],
        ],
    ],
];
```

## Deployment

### Security checklist

Before deploying, verify:

- [ ] `config.php` uses a real API token (not the placeholder)
- [ ] Only needed endpoints are enabled
- [ ] `config.php` is not committed to version control
- [ ] The webserver does not serve `config.php` directly (the `.htaccess`
      files handle this for Apache)

### Deploy via rclone

The included `deploy.sh` script uses rclone to sync production files to a
remote host.

Prerequisites:
- [rclone](https://rclone.org/) installed locally
- A configured rclone remote (e.g. SFTP)
- `composer install --no-dev` run locally

```sh
./deploy.sh <rclone-remote> <remote-path>
```

Example:

```sh
./deploy.sh myhost /home/user/dnsapi
```

The script validates your config before uploading:
- Rejects placeholder token
- Checks that vendor/ and the public suffix list exist

Only production files are synced (src/, public/, vendor/, data/, config.php,
.htaccess). No tests, dev dependencies, or git history are uploaded.

### Manual deployment

1. Run `composer install --no-dev` locally
2. Upload these files/directories to your webspace:
   - `.htaccess` (root)
   - `config.php`
   - `data/`
   - `public/`
   - `src/`
   - `vendor/`
3. Do **not** upload: `tests/`, `phpunit.xml`, `composer.json`,
   `composer.lock`, `.git/`, `.claude/`, `AGENTS.md`, `CLAUDE.md`,
   `deploy.sh`

### Webserver setup

**Document root points to project root (most shared hosting):**
The root `.htaccess` rewrites all requests into `public/`. This keeps
`config.php`, `src/`, and `vendor/` outside the webroot.

**Document root points to `public/` (if configurable):**
Preferred. Point your domain's document root directly to the `public/`
directory. The root `.htaccess` is then not needed.

**CGI/FastCGI (common on shared hosting):**
The `public/.htaccess` includes `CGIPassAuth On` to pass Basic Auth headers
through to PHP. This is required on most shared hosting where PHP runs as
CGI/FastCGI.

### Post-deployment verification

Test with curl (adjust URL and credentials):

```sh
# Plain update
curl -u alice:yourpassword "https://dns.example.com/plain/update?hostname=test.example.com&ip=1.2.3.4"

# DynDNS2 update
curl -u alice:yourpassword "https://dns.example.com/nic/update?hostname=test.example.com&myip=1.2.3.4"
```

Expected responses:
- `200` with no body (plain) or `good 1.2.3.4` (nic/update) on success
- `401` on auth failure
- `403` on domain permission failure

## Development

```sh
composer install
composer lint    # PHPStan static analysis
composer test    # PHPUnit tests
php -S localhost:8080 -t public/
```

## License

MIT
