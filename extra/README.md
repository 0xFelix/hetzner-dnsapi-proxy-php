# Extra handlers

This directory contains handlers that are not active by default. To re-enable
one or more of them:

## 1. Move handler files back

```sh
mv extra/Handler/AcmeDnsHandler.php src/Handler/
mv extra/Handler/HttpReqHandler.php src/Handler/
mv extra/Handler/DirectAdminHandler.php src/Handler/
```

## 2. Move test files back

```sh
mv extra/AcmeDnsHandlerTest.php tests/Integration/
mv extra/HttpReqHandlerTest.php tests/Integration/
mv extra/DirectAdminHandlerTest.php tests/Integration/
```

## 3. Register endpoints in Config.php

Add the endpoint names to the `ENDPOINTS` constant:

```php
public const ENDPOINTS = ['plain', 'nicupdate', 'acmedns', 'httpreq', 'directadmin'];
```

## 4. Restore methods in Auth.php

AcmeDnsHandler needs `extractApiKeyAuth()`, DirectAdminHandler needs
`getDomains()`. Add these methods to `Auth`:

```php
/**
 * Extract credentials from X-Api-User / X-Api-Key headers.
 *
 * @return array{string, string}|null [username, password] or null
 */
public function extractApiKeyAuth(): ?array
{
    $username = $_SERVER['HTTP_X_API_USER'] ?? '';
    $password = $_SERVER['HTTP_X_API_KEY'] ?? '';

    if ($username !== '' && $password !== '') {
        return [$username, $password];
    }

    return null;
}

/**
 * Get domains accessible by the given user.
 *
 * @return string[]
 */
/**
 * @param array{username: string, domains: string[]} $user
 */
public function getDomains(array $user): array
{
    $domains = [];
    foreach ($user['domains'] as $domain) {
        $domains[] = str_starts_with($domain, '*.') ? substr($domain, 2) : $domain;
    }

    return array_unique($domains);
}
```

## 5. Restore `clean()` in DnsServiceInterface and DnsService

HttpReqHandler needs the `clean()` method. Add to `DnsServiceInterface`:

```php
public function clean(RequestData $data): void;
```

Add to `DnsService`:

```php
public function clean(RequestData $data): void
{
    $zone = $this->client->zones()->getByName($data->zone);
    if ($zone === null) {
        throw new \RuntimeException('Zone not found: ' . $data->zone);
    }

    $rrSets = $zone->allRRSets(new RRSetRequestOpts($data->name, $data->type));
    if (empty($rrSets)) {
        return;
    }

    $rrSets[0]->removeRecords($rrSets[0]->records);
}
```

Also add `clean()` to `tests/MockDnsService.php`:

```php
/** @var RequestData[] */
public array $cleanCalls = [];

public function clean(RequestData $data): void
{
    $this->cleanCalls[] = $data;
}
```

## 6. Restore test helpers in HandlerTestCase

AcmeDnsHandler and HttpReqHandler tests need these helpers in
`tests/HandlerTestCase.php`:

```php
protected function setApiKeyAuth(string $user, string $key): void
{
    $_SERVER['HTTP_X_API_USER'] = $user;
    $_SERVER['HTTP_X_API_KEY'] = $key;
}

protected function setContentType(string $type): void
{
    $_SERVER['CONTENT_TYPE'] = $type;
}
```

Also add these resets to `setUp()`:

```php
unset($_SERVER['HTTP_X_API_USER'], $_SERVER['HTTP_X_API_KEY']);
unset($_SERVER['CONTENT_TYPE'], $_SERVER['HTTP_CONTENT_TYPE']);
```

## 7. Register routes in public/index.php

Add the use statements:

```php
use HetznerDnsapiProxy\Handler\AcmeDnsHandler;
use HetznerDnsapiProxy\Handler\DirectAdminHandler;
use HetznerDnsapiProxy\Handler\HttpReqHandler;
```

Add the route blocks after the existing ones:

```php
if (isset($active['acmedns'])) {
    $acme = new AcmeDnsHandler($auth, $dns, $log, $rateLimiter, $clientIp);
    $router->post('/acmedns/update', [$acme, 'handle']);
}
if (isset($active['httpreq'])) {
    $httpreq = new HttpReqHandler($auth, $dns, $log, $rateLimiter, $clientIp);
    $router->post('/httpreq/present', [$httpreq, 'handlePresent']);
    $router->post('/httpreq/cleanup', [$httpreq, 'handleCleanup']);
}
if (isset($active['directadmin'])) {
    $da = new DirectAdminHandler($auth, $dns, $log, $rateLimiter, $clientIp);
    $router->get('/directadmin/CMD_API_SHOW_DOMAINS', [$da, 'showDomains']);
    $router->get('/directadmin/CMD_API_DNS_CONTROL', [$da, 'dnsControl']);
    $router->get('/directadmin/CMD_API_DOMAIN_POINTER', [$da, 'domainPointer']);
}
```

## 8. Update config.sample.php

Add the endpoint names to the available list comment and the endpoints array.

## 9. Run tests

```sh
vendor/bin/phpunit
```
