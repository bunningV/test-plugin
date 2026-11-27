<?php

namespace CaltechSecurity;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * RFC 6238 time-based one-time passwords (HMAC-SHA1, 6 digits, 30 second step) — the profile every
 * authenticator app supports. No WordPress dependencies, so it can be tested on its own.
 */
final class Totp
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public const STEP_SECONDS = 30;

    public const DIGITS = 6;

    /** 160 bits of entropy, as recommended by RFC 4226. Returned as base32, which is what apps import. */
    public static function generateSecret(): string
    {
        return self::base32Encode(random_bytes(20));
    }

    public static function currentStep(?int $time = null): int
    {
        return intdiv($time ?? time(), self::STEP_SECONDS);
    }

    public static function code(string $secret, int $step): string
    {
        $key = self::base32Decode($secret);
        $counter = pack('N2', ($step >> 32) & 0xFFFFFFFF, $step & 0xFFFFFFFF);
        $hash = hash_hmac('sha1', $counter, $key, true);

        $offset = ord($hash[19]) & 0x0F;
        $binary = ((ord($hash[$offset]) & 0x7F) << 24)
            | ((ord($hash[$offset + 1]) & 0xFF) << 16)
            | ((ord($hash[$offset + 2]) & 0xFF) << 8)
            | (ord($hash[$offset + 3]) & 0xFF);

        return str_pad((string) ($binary % (10 ** self::DIGITS)), self::DIGITS, '0', STR_PAD_LEFT);
    }

    /**
     * Check a code against the current step and `$window` steps either side (clock drift).
     *
     * A step at or before `$afterStep` is refused, so a code that was already accepted cannot be
     * replayed within its validity window. On success, `$matchedStep` is the step it matched.
     */
    public static function verify(string $secret, string $code, ?int &$matchedStep = null, int $afterStep = 0, int $window = 1, ?int $time = null): bool
    {
        $matchedStep = null;
        if (! preg_match('/^\d{' . self::DIGITS . '}$/', $code)) {
            return false;
        }

        $current = self::currentStep($time);
        $found = null;

        // Walk every candidate rather than returning at the first hit, so timing does not reveal
        // which offset matched.
        for ($offset = -$window; $offset <= $window; $offset++) {
            $step = $current + $offset;
            if ($step > $afterStep && hash_equals(self::code($secret, $step), $code) && $found === null) {
                $found = $step;
            }
        }

        if ($found === null) {
            return false;
        }

        $matchedStep = $found;

        return true;
    }

    public static function otpauthUri(string $secret, string $account, string $issuer): string
    {
        return sprintf(
            'otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d',
            rawurlencode($issuer . ':' . $account),
            $secret,
            rawurlencode($issuer),
            self::DIGITS,
            self::STEP_SECONDS
        );
    }

    /** Groups of four for reading aloud / typing: "ABCD EFGH …". */
    public static function formatSecret(string $secret): string
    {
        return trim(chunk_split($secret, 4, ' '));
    }

    public static function base32Encode(string $binary): string
    {
        $bits = '';
        foreach (str_split($binary) as $char) {
            $bits .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }

        $out = '';
        foreach (str_split($bits, 5) as $chunk) {
            $out .= self::ALPHABET[bindec(str_pad($chunk, 5, '0', STR_PAD_RIGHT))];
        }

        return $out;
    }

    public static function base32Decode(string $encoded): string
    {
        $encoded = strtoupper(preg_replace('/[^A-Za-z2-7]/', '', $encoded) ?? '');

        $bits = '';
        foreach (str_split($encoded) as $char) {
            $position = strpos(self::ALPHABET, $char);
            if ($position === false) {
                continue;
            }
            $bits .= str_pad(decbin($position), 5, '0', STR_PAD_LEFT);
        }

        $out = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $out .= chr(bindec($byte));
            }
        }

        return $out;
    }
}
