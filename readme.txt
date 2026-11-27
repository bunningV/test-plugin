=== Caltech WP Security ===
Contributors: caltechhosting
Tags: security, login, two-factor, 2fa, totp
Requires at least: 5.8
Requires PHP: 8.0
Stable tag: 1.0.1
License: GPLv2 or later

Custom login URL and mandatory two-factor authentication, managed from one settings page.

== Description ==

* **Custom login URL.** Moves the login from /wp-login.php to a path you choose, such as /wp-login88.
  The original address, /wp-register.php, and /wp-admin for signed-out visitors answer "404 Not Found"
  rather than redirecting, so nothing points at the new address.
* **Mandatory two-factor authentication.** After the password, every account must enter a code from an
  authenticator app (Google Authenticator, Authy, 1Password, ...) or a one-time recovery code. Enforced on
  the server for every role: no dashboard, REST, AJAX or admin-post access without a verified session.
  Accounts without 2FA are walked through setting it up at their next sign-in.
* **One settings page**, "Caltech Security" in the admin menu: the login path, the 2FA switch, who has set
  up 2FA, and a reset button for people who lost their device and codes.

= How 2FA is enforced =

Once an account has set up an authenticator, that account is asked for a code at every later sign-in,
even while the site-wide switch is off. The switch is what also forces the accounts that have not set
one up. A correct password does not finish those sign-ins: it opens a short-lived challenge and no
WordPress cookie is issued. When a code is accepted the session is stamped as verified, server-side. Any
signed-in user who is required to have a stamp, and whose session has none, is treated as signed out on
every request, so a cookie created by anything else (another plugin, an old session, an edited cookie)
gives no access. XML-RPC and front-end login forms are refused. Application passwords sign in with no
screen to ask for a code, so they are off for enrolled accounts and for everyone while the switch is on.
The current-user guard runs after other authenticators and REST checks independently, so a JWT/OAuth/Bearer
plugin cannot establish an unstamped user later in the request. Such integrations need an explicit trust hook.

TOTP steps and recovery codes are consumed atomically: two concurrent requests cannot both spend the same
code. Cookie security also follows the configured HTTPS site URL, so Secure is preserved behind nginx,
Cloudflare or another TLS-terminating proxy even when PHP's is_ssl() cannot see the original HTTPS request.

== Installation ==

1. Upload the plugin and activate it.
2. Open **Caltech Security** in the admin menu.
3. Open **Set up two-factor authentication** and pair your own account first.
4. Choose a login path, tick **Require for everyone**, save, and write the new login address down.

Turning enforcement on signs everyone else out; they set up 2FA at their next sign-in.

== Locked out? ==

Add one of these to wp-config.php, sign in, correct the setting, then remove the line:

    define('CALTECH_SECURITY_DISABLE_LOGIN_URL', true);  // wp-login.php works normally again
    define('CALTECH_SECURITY_DISABLE_2FA', true);        // no verification code is asked for

Renaming the plugin's folder in wp-content/plugins switches everything off as well.

Authenticator secrets are encrypted with a key derived from the salts in wp-config.php. If you rotate
the salts, existing 2FA setups stop working and each user must be reset and set up again.

== Notes ==

* Behind nginx/Apache the standard WordPress rule that sends unknown paths to index.php is all that is
  needed; the custom path is not a real file or rewrite rule.
* Not supported in v1: multisite network login.
* Single sign-on from the Caltech Connector plugin counts as verified (Caltech already signed the person
  in). Other integrations can opt in with the `caltech_security_trust_login` filter.

== Changelog ==

= 1.0.1 =
* Auto-updates can be turned off and on from the Plugins screen. They are on by default for new installs.
* The update checker is bundled with the plugin, so the Plugins screen shows the auto-update option.

= 1.0.0 =
* Initial release: custom login URL, mandatory TOTP 2FA with recovery codes, settings page.
