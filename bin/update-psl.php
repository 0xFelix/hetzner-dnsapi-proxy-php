<?php

/**
 * Download the public suffix list into data/.
 *
 * Runs from composer's install/update hooks, so it must not fail the install
 * when publicsuffix.org is unreachable and a usable copy is already on disk.
 * Pass --force to re-download regardless of age.
 */

declare(strict_types=1);

const URL = 'https://publicsuffix.org/list/public_suffix_list.dat';
const MAX_AGE_SECONDS = 30 * 24 * 60 * 60;

$path = dirname(__DIR__) . '/data/public_suffix_list.dat';
$force = in_array('--force', $argv, true);
$exists = file_exists($path) && filesize($path) > 0;

if (!$force && $exists && (time() - (int) filemtime($path)) < MAX_AGE_SECONDS) {
    fwrite(STDOUT, "Public suffix list is up to date.\n");
    exit(0);
}

$context = stream_context_create(['http' => ['timeout' => 30, 'ignore_errors' => false]]);
$list = @file_get_contents(URL, false, $context);

if ($list === false || !str_contains($list, '// ===BEGIN ICANN DOMAINS===')) {
    if ($exists) {
        fwrite(STDERR, "Warning: could not refresh the public suffix list, keeping the existing copy.\n");
        exit(0);
    }

    fwrite(STDERR, 'Error: could not download the public suffix list from ' . URL . "\n");
    exit(1);
}

file_put_contents($path, $list);
fwrite(STDOUT, 'Public suffix list updated (' . strlen($list) . " bytes).\n");
