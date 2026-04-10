<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy;

class Sanitize
{
    private const MAX_TXT_LENGTH = 255;

    /** Check if a string contains control characters (0x00-0x1F, 0x7F). */
    public static function hasControl(string $input): bool
    {
        return (bool) preg_match('/[\x00-\x1F\x7F]/', $input);
    }

    /** Strip control characters (0x00-0x1F, 0x7F) from a string. */
    public static function stripControl(string $input): string
    {
        return preg_replace('/[\x00-\x1F\x7F]/', '', $input);
    }

    /** Validate a TXT record value. Returns null on success, error message on failure. */
    public static function validateTxt(string $value): ?string
    {
        if ($value === '') {
            return 'txt value is empty';
        }

        if (strlen($value) > self::MAX_TXT_LENGTH) {
            return 'txt value exceeds ' . self::MAX_TXT_LENGTH . ' characters';
        }

        if (preg_match('/[\x00-\x1F\x7F]/', $value)) {
            return 'txt value contains control characters';
        }

        return null;
    }
}
