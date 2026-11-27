<?php

namespace CaltechSecurity;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * The half-signed-in state between "password accepted" and "code accepted".
 *
 * It is not a session and grants nothing: no WordPress auth cookie exists while a challenge is open.
 * The state lives on the server (a transient keyed by the hash of a random token); the browser only
 * holds that token, in an HttpOnly cookie. A challenge is short-lived and allows a handful of wrong
 * codes before it is thrown away and the user must start again with their password.
 */
final class Challenge
{
    public const COOKIE = 'caltech_sec_challenge';

    public const TTL = 600;

    public const MAX_ATTEMPTS = 5;

    /**
     * @param  array<string, mixed>  $data
     */
    public static function create(array $data): string
    {
        $token = bin2hex(random_bytes(24));
        $data['attempts'] = 0;
        set_transient(self::key($token), $data, self::TTL);
        self::sendCookie($token, time() + self::TTL);

        return $token;
    }

    /** @return array{0: string, 1: array<string, mixed>}|null  [token, data] for the challenge this browser holds */
    public static function current(): ?array
    {
        $token = isset($_COOKIE[self::COOKIE]) ? (string) wp_unslash($_COOKIE[self::COOKIE]) : '';
        if (! preg_match('/^[a-f0-9]{48}$/', $token)) {
            return null;
        }

        $data = get_transient(self::key($token));

        return is_array($data) && ! empty($data['user']) ? [$token, $data] : null;
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public static function save(string $token, array $data): void
    {
        set_transient(self::key($token), $data, self::TTL);
    }

    public static function destroy(string $token): void
    {
        delete_transient(self::key($token));
        self::sendCookie('', time() - YEAR_IN_SECONDS);
        unset($_COOKIE[self::COOKIE]);
    }

    private static function key(string $token): string
    {
        return 'caltech_sec_ch_' . hash('sha256', $token);
    }

    private static function sendCookie(string $value, int $expires): void
    {
        if (headers_sent()) {
            return;
        }

        setcookie(self::COOKIE, $value, [
            'expires' => $expires,
            'path' => defined('COOKIEPATH') && COOKIEPATH ? COOKIEPATH : '/',
            'domain' => defined('COOKIE_DOMAIN') && COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
            'secure' => Plugin::secureCookies(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);

        if ($value !== '') {
            $_COOKIE[self::COOKIE] = $value;
        }
    }
}
