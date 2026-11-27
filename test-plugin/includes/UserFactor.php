<?php

namespace CaltechSecurity;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Everything stored about one user's second factor, behind one door.
 *
 * User meta: the encrypted TOTP secret, the last accepted time step (replay guard), and the hashed
 * recovery codes. A secret that is stored but not yet confirmed with a code lives under a separate
 * "pending" key, so half-finished setup never counts as being enrolled.
 */
final class UserFactor
{
    public const META_SECRET = 'caltech_security_totp_secret';

    public const META_ENROLLED_AT = 'caltech_security_totp_enrolled_at';

    public const META_LAST_STEP = 'caltech_security_totp_last_step';

    public const META_RECOVERY = 'caltech_security_recovery_codes';

    public const META_PENDING = 'caltech_security_totp_pending';

    public const RECOVERY_COUNT = 10;

    /** Wrong codes allowed per user inside {@see LOCK_SECONDS} before 2FA entry is refused for a while. */
    private const MAX_FAILURES = 10;

    private const LOCK_SECONDS = 900;

    public static function isEnrolled(int $userId): bool
    {
        return (int) get_user_meta($userId, self::META_ENROLLED_AT, true) > 0
            && (string) get_user_meta($userId, self::META_SECRET, true) !== '';
    }

    public static function secret(int $userId): ?string
    {
        $stored = (string) get_user_meta($userId, self::META_SECRET, true);

        return $stored === '' ? null : Crypto::decrypt($stored);
    }

    /** Check a six-digit code against the stored secret; on success the step is recorded so it cannot be reused. */
    public static function verifyTotp(int $userId, string $code): bool
    {
        $secret = self::secret($userId);
        if ($secret === null || $secret === '') {
            return false;
        }

        $last = (int) get_user_meta($userId, self::META_LAST_STEP, true);
        if (! Totp::verify($secret, $code, $step, $last)) {
            return false;
        }

        // Compare-and-swap: only one request may advance this exact previous step. Without the
        // condition, two parallel POSTs can both verify the same six-digit code before either writes,
        // and both would create a session.
        return self::compareAndSwapMeta($userId, self::META_LAST_STEP, $last, $step);
    }

    /**
     * Save a confirmed secret and issue a fresh set of recovery codes.
     *
     * @return list<string> The recovery codes in plain text. This is the only time they exist in that form.
     */
    public static function enroll(int $userId, string $secret, int $confirmedStep): array
    {
        update_user_meta($userId, self::META_SECRET, Crypto::encrypt($secret));
        update_user_meta($userId, self::META_ENROLLED_AT, time());
        update_user_meta($userId, self::META_LAST_STEP, $confirmedStep);
        delete_user_meta($userId, self::META_PENDING);
        self::clearFailures($userId);

        return self::regenerateRecoveryCodes($userId);
    }

    /** @return list<string> */
    public static function regenerateRecoveryCodes(int $userId): array
    {
        $plain = [];
        $hashes = [];
        for ($i = 0; $i < self::RECOVERY_COUNT; $i++) {
            $code = self::randomRecoveryCode();
            $plain[] = $code;
            $hashes[] = wp_hash_password(self::normalizeRecovery($code));
        }

        update_user_meta($userId, self::META_RECOVERY, $hashes);

        return $plain;
    }

    public static function recoveryRemaining(int $userId): int
    {
        $hashes = get_user_meta($userId, self::META_RECOVERY, true);

        return is_array($hashes) ? count($hashes) : 0;
    }

    /** Accepts a recovery code once: a matching code is removed so it cannot be used again. */
    public static function consumeRecovery(int $userId, string $input): bool
    {
        $candidate = self::normalizeRecovery($input);
        if (strlen($candidate) !== 10) {
            return false;
        }

        $hashes = get_user_meta($userId, self::META_RECOVERY, true);
        if (! is_array($hashes) || $hashes === []) {
            return false;
        }
        $originalHashes = $hashes;

        foreach ($hashes as $index => $hash) {
            if (is_string($hash) && wp_check_password($candidate, $hash)) {
                unset($hashes[$index]);

                // Atomic single-use: replace only while the complete stored list is still the list we
                // read. A parallel request consuming this or another code changes that value first,
                // so this request fails instead of authenticating against stale data.
                return self::compareAndSwapMeta(
                    $userId,
                    self::META_RECOVERY,
                    $originalHashes,
                    array_values($hashes)
                );
            }
        }

        return false;
    }

    /** Forget the user's second factor entirely. At their next sign-in they are asked to set it up again. */
    public static function reset(int $userId): void
    {
        foreach ([self::META_SECRET, self::META_ENROLLED_AT, self::META_LAST_STEP, self::META_RECOVERY, self::META_PENDING] as $key) {
            delete_user_meta($userId, $key);
        }
        self::clearFailures($userId);

        // Whatever was signed in as this user is no longer verified against anything.
        $manager = \WP_Session_Tokens::get_instance($userId);
        $manager->destroy_all();
    }

    // ── Pending (unconfirmed) setup from the profile screen ─────────────────

    public static function startPending(int $userId): string
    {
        $secret = Totp::generateSecret();
        update_user_meta($userId, self::META_PENDING, Crypto::encrypt($secret));

        return $secret;
    }

    public static function pendingSecret(int $userId): ?string
    {
        $stored = (string) get_user_meta($userId, self::META_PENDING, true);

        return $stored === '' ? null : Crypto::decrypt($stored);
    }

    public static function clearPending(int $userId): void
    {
        delete_user_meta($userId, self::META_PENDING);
    }

    // ── Failure throttle ────────────────────────────────────────────────────

    public static function locked(int $userId): bool
    {
        return (int) get_transient(self::failureKey($userId)) >= self::MAX_FAILURES;
    }

    public static function registerFailure(int $userId): void
    {
        $key = self::failureKey($userId);
        set_transient($key, (int) get_transient($key) + 1, self::LOCK_SECONDS);
    }

    public static function clearFailures(int $userId): void
    {
        delete_transient(self::failureKey($userId));
    }

    // ── Recovery code format ────────────────────────────────────────────────

    /** Ten characters from an alphabet without look-alikes, shown as XXXXX-XXXXX. */
    private static function randomRecoveryCode(): string
    {
        $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $code = '';
        for ($i = 0; $i < 10; $i++) {
            $code .= $alphabet[random_int(0, strlen($alphabet) - 1)];
        }

        return substr($code, 0, 5) . '-' . substr($code, 5);
    }

    public static function normalizeRecovery(string $input): string
    {
        return strtoupper(preg_replace('/[^A-Za-z0-9]/', '', $input) ?? '');
    }

    private static function failureKey(int $userId): string
    {
        return 'caltech_sec_fail_' . $userId;
    }

    /**
     * Atomically replace one user-meta value if it still equals what this request read.
     *
     * update_user_meta($id, $key, $new, $previous) looks like compare-and-swap, but WordPress treats
     * empty previous values (notably TOTP step 0) as "no condition". The database update below keeps
     * the old serialized value in the WHERE clause in every case, so exactly the first contender
     * wins. User-meta cache invalidation preserves normal WordPress read behaviour afterwards.
     *
     * @param  mixed  $expected
     * @param  mixed  $replacement
     */
    private static function compareAndSwapMeta(int $userId, string $key, $expected, $replacement): bool
    {
        global $wpdb;

        /**
         * Fires immediately before the atomic factor update. Useful to observability integrations;
         * changing the value here causes this request to lose the comparison safely.
         */
        do_action('caltech_security_before_factor_compare_and_swap', $userId, $key, $replacement, $expected);

        $updated = $wpdb->update(
            $wpdb->usermeta,
            ['meta_value' => maybe_serialize($replacement)],
            [
                'user_id' => $userId,
                'meta_key' => $key,
                'meta_value' => maybe_serialize($expected),
            ],
            ['%s'],
            ['%d', '%s', '%s']
        );

        if (is_int($updated) && $updated > 0) {
            wp_cache_delete($userId, 'user_meta');

            return true;
        }

        return false;
    }
}
