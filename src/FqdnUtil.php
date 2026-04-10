<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy;

use InvalidArgumentException;
use Pdp\Rules;

class FqdnUtil
{
    private static ?Rules $rules = null;

    /**
     * Split an FQDN into record name and zone.
     *
     * @return array{string, string} [name, zone]
     */
    public static function splitFqdn(string $fqdn): array
    {
        if ($fqdn === '') {
            throw new InvalidArgumentException('Invalid fqdn: empty');
        }

        $rules = self::getRules();
        $result = $rules->resolve($fqdn);
        $registrableDomain = $result->registrableDomain();

        if ($registrableDomain->toString() === '') {
            throw new InvalidArgumentException('Invalid fqdn');
        }

        $zone = $registrableDomain->toString();

        if ($fqdn === $zone) {
            return ['', $zone];
        }

        $name = rtrim(substr($fqdn, 0, -(strlen($zone) + 1)), '.');

        return [$name, $zone];
    }

    private static function getRules(): Rules
    {
        if (self::$rules === null) {
            $path = dirname(__DIR__) . '/data/public_suffix_list.dat';
            if (!file_exists($path)) {
                throw new \RuntimeException(
                    'Public suffix list not found. Run: composer run-script update-psl'
                );
            }
            self::$rules = Rules::fromPath($path);
        }

        return self::$rules;
    }
}
