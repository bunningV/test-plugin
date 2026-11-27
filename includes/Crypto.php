<?php

namespace CaltechSecurity;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Encrypts authenticator secrets at rest.
 *
 * The key is derived from the site's secret keys and salts, which live in wp-config.php and not in the
 * database — so a database dump alone does not reveal anyone's authenticator secret. The flip side:
 * rotating the salts makes stored secrets unreadable, and those users must set 2FA up again (the
 * wp-config.php escape hatches in the readme cover the admin who needs back in).
 *
 * Uses libsodium when present (WordPress bundles a polyfill), otherwise AES-256-GCM through OpenSSL.
 * With neither, {@see available()} is false and callers fail closed.
 */
final class Crypto
{
    private const SODIUM = 's1';

    private const OPENSSL = 'o1';

    public static function available(): bool
    {
        return function_exists('sodium_crypto_secretbox') || function_exists('openssl_encrypt');
    }

    public static function encrypt(string $plain): string
    {
        $key = self::key();

        if (function_exists('sodium_crypto_secretbox')) {
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

            return self::SODIUM . ':' . base64_encode($nonce . sodium_crypto_secretbox($plain, $nonce, $key));
        }

        $iv = random_bytes(12);
        $tag = '';
        $cipher = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($cipher === false) {
            throw new \RuntimeException('Encryption failed.');
        }

        return self::OPENSSL . ':' . base64_encode($iv . $tag . $cipher);
    }

    /** Returns null for anything that does not decrypt: wrong key, tampering, or garbage. */
    public static function decrypt(string $stored): ?string
    {
        if (strpos($stored, ':') === false) {
            return null;
        }

        [$scheme, $encoded] = explode(':', $stored, 2);
        $raw = base64_decode($encoded, true);
        if ($raw === false) {
            return null;
        }

        $key = self::key();

        if ($scheme === self::SODIUM && function_exists('sodium_crypto_secretbox_open')) {
            if (strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
                return null;
            }
            $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $plain = sodium_crypto_secretbox_open(substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), $nonce, $key);

            return $plain === false ? null : $plain;
        }

        if ($scheme === self::OPENSSL && function_exists('openssl_decrypt')) {
            if (strlen($raw) <= 28) {
                return null;
            }
            $plain = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16));

            return $plain === false ? null : $plain;
        }

        return null;
    }

    private static function key(): string
    {
        return hash('sha256', 'caltech-security|' . wp_salt('auth') . '|' . wp_salt('secure_auth'), true);
    }
}
