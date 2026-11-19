<?php
/**
 * Copy this file to config.php and fill in your keys.
 *
 *   1. Sign in at https://proveitonchain.com/tokenlock/dashboard
 *   2. Add your site (its addresses) and pick the tokens that unlock it
 *   3. Paste the pk_ site key and sk_ secret key below
 *
 * config.php is blocked from the web by .htaccess. Never share your secret
 * key, put it in a browser page, or send it in chat.
 */
return array(
    // From your TOKENLOCK dashboard (pk_… is safe in the browser).
    'site_key' => 'pk_…',

    // From your dashboard, shown once. Server only.
    'secret_key' => 'sk_…',

    // Public sign-in page. Visitors without a valid pass are sent here with ?next=.
    'sign_in_page' => '/tokenlock/signin.php',

    // Where to send people after a successful sign-in (if ?next= is missing or unsafe).
    'after_sign_in' => '/holders/',

    // Where sign-out sends people.
    'after_sign_out' => '/',

    // 0.4.0: token-only site (registered keys off): any holder of your tokens may open every locked page.
    // Identity and token are checked; no per-page rules. If the site turns on registered keys, every page is
    // still checked against the key's routes. Without this, a token-only site answers 403 policy_required.
    'token_only' => true,

    // Optional. Leave blank unless PHP sits behind a proxy that hides https.
    // If you use both www and non-www, leave this blank so each host is checked on its own.
    // 'public_origin' => 'https://pepeproject.com',

    // Optional. Defaults to the system temp directory. To keep the cache next
    // to this library (already blocked by .htaccess), use: __DIR__ . '/cache'
    // 'cache_dir' => __DIR__ . '/cache',

    // 'api_base' => 'https://proveitonchain.com',
    // 'cookie_name' => 'tokenlock_pass',
    // 'max_age_seconds' => 86400,

    // Enterprise access controls (sites with registered keys): the page path and method are sent with each
    // check so routes, methods and environments are enforced. Set your environment name if you use them.
    // 'check_resource' => true,
    // 'environment' => 'production',

    // 0.2.1 security options (defaults shown):
    // 'strict' => null,      // on unless fail_open / check_resource=false; true + either = configuration error
    // 'cache' => true,       // false = check with the API on every request (strict never caches registered keys)
    // 'api_paths' => array(),// e.g. array('/api'): JSON 401/403 instead of a redirect (Accept: application/json also)
    // 'fail_open' => false,  // true = let pass holders in UNVERIFIED when the API is down (turns strict off)

    // 0.3.0 early block (early.php via auto_prepend_file or the first line of index.php). Nothing runs until
    // 'protect' or 'deny_ips' is set. Kill switch: create tokenlock/early.off or set TOKENLOCK_EARLY=off.
    // 'early' => array(
    //     'protect' => array('/members/*'),                 // need a pass
    //     'public' => array('/members/join'),               // carve-outs inside protect
    //     'exclude_paths' => array('/wp-admin/*', '/wp-login.php'), // never blocked here (admins can't lock themselves out)
    //     'admin_ips' => array(),                           // e.g. '203.0.113.7', '2001:db8::/48': always let through
    //     'deny_ips' => array(),                            // e.g. '198.51.100.0/24': always 403
    //     'trusted_proxies' => array(),                     // read X-Forwarded-For only from these
    // ),
);
