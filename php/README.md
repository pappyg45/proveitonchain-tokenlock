# TOKENLOCK for PHP

Lock a section of a PHP site to people who hold a name or token on Bitcoin. **Your content stays on your server. We do the Token check.**

Visitors click **Sign in with your Token**, sign a one-time message in their wallet (nothing is paid or sent), and get a short-lived pass. Your page checks that pass with your secret key before anything is shown.

This drop-in works on PHP 7.4 or newer (shared hosting and cPanel are fine). It needs no Composer packages. It uses `curl` when it is available, and falls back to `file_get_contents` if it is not.

Which tokens unlock the site is set in your [TOKENLOCK dashboard](https://proveitonchain.com/tokenlock/dashboard), not in this code.

## Upgrading to 0.4.2 (security hardening, breaking: removed options)

Current release: **0.4.2**, a security-hardening release with no new features.

- **Removed:** `'fail_open'` and `'check_resource'` (any value, and `TOKENLOCK_FAIL_OPEN` / `TOKENLOCK_CHECK_RESOURCE`)
  and `'strict' => false` (also `TOKENLOCK_STRICT=0` and `array('strict' => false)` per call). Each is a configuration
  error: locked pages answer **500** (JSON `bad_config` in API mode), the reason goes to the PHP error log, nothing from
  the page is sent. An unreachable API always answers 503.
- **Configuration is validated:** unknown options (typos such as `'tokenonly'`), wrong types (`'token_only' => 'maybe'`,
  `'timeout_seconds' => 'fast'`), a missing or malformed `sk_` secret key, a non-http(s) `api_base`, and an unusable
  `'early'` block (unknown keys such as `'protectt'`, wrong types) are configuration errors instead of being ignored.
  An unusable `'early'` block refuses every path except the TOKENLOCK folder and a valid `exclude_paths` list (it can
  no longer tell what is protected); the kill switch (`tokenlock/early.off` or `TOKENLOCK_EARLY=off`) still works.
- **Answers are checked strictly, identity checks included:** larger than 64 KiB, not a JSON object, wrong types,
  missing fields, a non-ISO `expires_at` (0.4.1 read `'tomorrow'` as a date), or contradictions (`valid => true` with a
  `code`, `error` or `identity_valid => false`; `allowed` disagreeing with `access.allowed`; two echoes naming different
  resources) all deny.
- **Self-verify:** malformed policies are `policy_invalid`; dates must be ISO 8601; holdings answers need a boolean `held`.
- `tokenlock_strict()` now only checks the configuration and returns true. A missing secret key throws `bad_config`
  (0.4.1: `no_secret_key`).

To upgrade: replace the files in `tokenlock/` (keep your `config.php`) and remove `'fail_open'`, `'check_resource'` and
`'strict' => false` from it if present.

## Upgrading to 0.4.0 (breaking: explicit route authorization)

0.4.0 fixes [security advisory 2026-11-18](https://proveitonchain.com/security/advisories/2026-11-18): no page path,
method or environment is authorized unless a policy explicitly permits it. Identity and token checks are unchanged.

- `tokenlock_verify_pass($pass, $resource)` on a **token-only** site (registered keys off) now answers
  `valid => false, allowed => false, code => 'policy_required', identity_valid => true` (0.3.0: `valid => true`,
  nothing checked). Without a resource (identity only) it still answers `valid => true`.
- `tokenlock_require()`, `tokenlock_protect()` and the early block: on a token-only site set `'token_only' => true` in
  `config.php` (or `TOKENLOCK_TOKEN_ONLY=1`). The new `config.sample.php` has it on. Without it, locked pages answer
  **403 policy_required** (written once to the PHP error log). With it, if the site later turns on registered keys,
  pages are still checked against the key's routes.
- Self-verify: `tokenlock_sv_verify_local_pass()` with a resource and no policy, or with a token-mode policy, answers
  `policy_required` (0.3.0: `allowed => true`).
- Sites with registered keys: no change.

To upgrade: replace the files in `tokenlock/` (keep your `config.php`), and add `'token_only' => true,` to your
`config.php` if any holder should open every locked page. Since 18 Nov 2026, 9:03 PM PT the hosted API answers
`policy_required` to PHP 0.2.x/0.3.x too, so a token-only site still on those versions denies locked pages until it upgrades.

### Fail-closed guarantee

No locked page, method or environment is authorized unless a policy explicitly permits it. Since 0.4.2 there is no
setting that turns this off. Each of these denies:

| Situation | Answer |
| --- | --- |
| A page path with no applicable route policy (token-only site, no `'token_only'`) | `403 policy_required` |
| PHP/SDK 0.2.x/0.3.x clients sending a page path to the hosted API on a token-only site | `policy_required` (hosted API, every client version) |
| `'token_only' => true` (or `TOKENLOCK_TOKEN_ONLY=1`) on a site that has registered keys | the page path, method and environment are still checked against the key |
| TOKENLOCK API unreachable, timing out or answering 5xx | `503`, nothing from your page is sent |
| Self-verify: policy can't be loaded, is expired or has a bad signature | `policy_unavailable` / `policy_expired` |
| Self-verify: holdings source fails | `lookup_failed` |
| Self-verify: a page path with no policy, or a token-mode policy | `policy_required` |
| Self-verify: a malformed policy | `policy_invalid` |
| An invalid configuration (removed or unknown options, wrong types, missing or malformed secret key) | `500 bad_config` (logged) |
| A malformed, oversized (> 64 KiB), non-JSON or contradictory API answer | denied (503 for an unreadable answer) |

Remaining limits (not configuration switches): on hosted registered-keys sites, a pass younger than
2 × `recheck_holdings_s` keeps working during a holdings-source outage unless `require_fresh_holdings` is on (the route
policy is still enforced). `'early' => array('admin_ips' => …)` is an explicit IP allowlist that skips the pass check.
Identity answers on token-only sites are cached on disk up to 60 s unless `'cache' => false`. Copies you installed
earlier keep their old behavior until you replace the files.

## What you upload

Unzip this package and put both folders in your site’s web root (`public_html` on A2 Hosting / cPanel):

```
public_html/
  tokenlock/
    tokenlock.php         (the library)
    config.sample.php     (copy this to config.php)
    config.php            (you create this — not in the zip)
    .htaccess             (blocks web access to keys and the cache)
    signin.php
    session.php
    signout.php
    page.css
    cache/                (optional local cache; already blocked)
  holders/
    index.php             (example locked page)
```

The example locked page is `/holders/`. Your public homepage is not changed.

## 1. Get your keys

1. Sign in at **https://proveitonchain.com/tokenlock/dashboard** with your wallet.
2. Add a site. For pepeproject.com, use both addresses:
   - `https://pepeproject.com`
   - `https://www.pepeproject.com`
3. Pick the tokens that unlock it (any one is enough).
4. Copy the two keys:
   - `pk_…` publishable site key, safe in the browser
   - `sk_…` secret key, server only, shown once

If you also want to test on your computer, add `http://localhost:8080` as another site address (or add it later). You can change addresses and tokens anytime in the dashboard.

## 2. Upload with cPanel File Manager

1. Log in to cPanel for the site (A2 Hosting) and open **File Manager**.
2. Open `public_html` (or the document root for pepeproject.com, if it is different).
3. Upload `pepeproject-tokenlock.zip` and extract it there, **or** upload the `tokenlock` and `holders` folders so they sit directly under `public_html`.
   - You should have `public_html/tokenlock/signin.php` and `public_html/holders/index.php`.
   - Do not nest them as `public_html/pepeproject-tokenlock/tokenlock/`.
4. Inside `public_html/tokenlock/`, copy `config.sample.php` and name the copy `config.php`:
   - Select `config.sample.php` → **Copy** → name it `config.php` in the same folder.
5. Open `config.php` and paste your keys:

```php
'site_key'   => 'pk_…',
'secret_key' => 'sk_…',
```

6. Save. Never put the secret key in a chat message, a public page, or a public repository.

Optional: set `'cache_dir' => __DIR__ . '/cache'` so verification results are stored in `tokenlock/cache/` (already blocked by `.htaccess`) instead of the server temp directory.

## 3. Check that it works

1. Visit `https://pepeproject.com/holders/` (or `https://www.pepeproject.com/holders/`). You should be sent to the sign-in page.
2. Click **Sign in with your Token**, sign the message in your wallet, and you should land on the holders page with your address.
3. Click **Sign out**. You should leave the holders page.
4. Confirm your keys are not on the web: open `https://pepeproject.com/tokenlock/config.php`. You should get a 403 or a blank page, not your keys.

If sign-in says “Wrong site,” add the exact address you are visiting (including `www` or not) as a site origin in the dashboard.

## 4. Lock any other page

Add this at the **very top** of the page, before any HTML or whitespace:

```php
<?php
require_once $_SERVER['DOCUMENT_ROOT'] . '/tokenlock/tokenlock.php';
tokenlock_require();
$visitor = tokenlock_pass(); // address, assets_held, expires_at
?>
```

If the file already starts with `<?php`, just add the `require_once` and `tokenlock_require();` before anything is printed.

Sign out: link to `/tokenlock/signout.php`.

**Front controller (one `index.php` for every URL, e.g. Laravel/Slim/WordPress-style routing):** lock by path instead of per file:

```php
require_once __DIR__ . '/tokenlock/tokenlock.php';
tokenlock_protect(array('/admin/*', '/members/*'), array('/members/welcome'));
```

Paths are matched in canonical form, case-insensitively (see Security below), so `/ADMIN`, `//admin` and `/%61dmin` are locked too.

## How it stays safe

- The secret key never leaves your server. Passes are checked with it, so a pass made for another site is refused.
- The pass cookie is HttpOnly, Secure and SameSite=Lax, and ends when the pass ends. `session.php` refuses requests from other sites.
- Good checks are cached on disk (see "Revocation window") and never past the pass’s expiry.
- If the TOKENLOCK API cannot be reached, the page shows a friendly “try again” message and does **not** let the visitor in.
- `.htaccess` blocks web access to `config.php` and the cache. (Your PHP pages can still include them.)
- A pass proves the visitor controlled a wallet holding your token when they signed in. It does not prove who they are.

## Requirements

- PHP 7.4 or newer (7.4.33 on A2 / LiteSpeed is fine)
- `curl` recommended; otherwise `allow_url_fopen` must be on
- HTTPS on the live site (the cookie is marked Secure)
- Self-verify only (0.3.0): the GMP extension (`php-gmp`; on cPanel, "Select PHP Version" → Extensions → gmp)

## Local test

```bash
# In config.php, or as environment variables:
# TOKENLOCK_SITE_KEY=pk_… TOKENLOCK_SECRET_KEY=sk_…
php -S localhost:8080 -t .
# Add http://localhost:8080 as a site address in the dashboard, then open
# http://localhost:8080/holders/
```

MIT © Prove It Onchain

## Enterprise access controls (0.2.0)

For sites with registered keys turned on (Business and Enterprise), `tokenlock_require()` now sends the page path and method with each check, so the key's routes, methods, environment and expiry are enforced and revocations take effect within seconds (the answer is cached for at most `cache_max_s`, 5 s). A signed-in key that isn't allowed on a page gets a 403 "Not allowed here" page instead of a sign-in redirect. Token-only sites have no per-page rules: since 0.4.0 they need `'token_only' => true` (see Upgrading to 0.4.0), and `tokenlock_verify_pass()` with a path on a token-only site answers `policy_required`.

```php
// config.php (optional)
'environment' => 'production',   // checked against the key's environments (path + method are always sent)
// or call it yourself:
$info = tokenlock_verify_pass($pass, array('path' => '/api/partner/prices', 'method' => 'GET'));
```

## Security model (0.2.1)

- **Sessions are bearer passes.** The wallet signature happens once, at sign-in, and gets a pass (a signed, expiring token in an HttpOnly cookie). Later requests present the pass; they are not signed one by one. A stolen pass works until it expires or the key is revoked. Per-request signing for agent APIs is on the roadmap.
- **Path rules v1.1** (same as the Node SDK and the API): query dropped, percent-decoded once, `//` collapsed, trailing `/` dropped, matched case-insensitively. Rejected with `400 bad_path`: backslashes, control bytes, encoded `/` `\` NUL `%` `.` or `;` (`%2f`, `%5c`, `%00`, `%25`, `%2e`, `%3b`), invalid encoding, any `;` and any `.` or `..` segment. Ambiguous forms are refused, not resolved: `/admin/..` would be `/` to a resolver but most PHP routers serve it as `/admin`. The path sent to the API, the cache key and the answer check use the canonical path lowercased (`tokenlock_resource_path()`). `tokenlock_canonical_path()`, `tokenlock_path_matches()`. Test vectors: `test/fixtures/path-vectors.json`.
- **Authorization paths are case-insensitive:** `/Admin`, `/ADMIN` and `/admin` are one authorization identity, even if your app routes them to different pages. A rule for `/admin/*` also covers `/ADMIN/x`, and a public carve-out for `/join` also opens `/JOIN`. Don't rely on case to separate protected and public routes.
- **Proxies:** TOKENLOCK must see the same path your router uses. If nginx, Apache or a CDN rewrites the path, make it pass the path through unchanged (or normalize it the same way before PHP). Don't decode `%2f` or resolve `..` after the check. Protect whole prefixes (`/admin/*`).
- **Sign-in `next`:** only same-site paths. `//evil.com`, `/\evil.com`, `javascript:`, encoded or control-character variants fall back to `after_sign_in` (`tokenlock_safe_next()`, and the same check in the sign-in page's script).
- **What our tests don't show:** the tests (unit, PHP built-in server, and the SDK's app-level integration matrix) run against a local copy of the API. They don't establish the security of the hosted service or isolation between tenants; an independent security review is on the roadmap.
- **Strict mode** (always on since 0.4.2): an answer counts only if complete, unambiguous and `allowed === true` for exactly this page's path, method and environment (echoed by the API). `'strict' => false`, `'fail_open'` and `'check_resource'` were removed and are configuration errors (`TokenlockException`, `bad_config`; locked pages answer 500). When the API can't answer, locked pages are denied (503).
- **API mode:** `Accept: application/json`, or a path under `'api_paths' => array('/api')`, gets JSON for every denial: 401 (no/invalid/expired pass), 403 (signed in but not allowed), 400 (bad path), 503 (unavailable). Body `{ error, code, reason, correlation_id }`.
- **Cache:** `'cache' => false` asks the API on every request. `tokenlock_clear_cache($pass)` removes every cached answer for that pass (all pages).

### Revocation window

| Setup | How long a revoked key can still get in |
| --- | --- |
| 0.2.1 or later (strict), registered keys | 0: never cached |
| 0.2.0 | up to 5 s (`cache_max_s`) |
| Token-only sites | Holdings checked at sign-in; a pass stays good until it expires (cached up to 60 s) |

## Early block (0.3.0, preview)

`tokenlock/early.php` checks the pass **before your app boots**. WordPress, Laravel and your own code never run for
visitors it turns away. Install it one of two ways:

```ini
; php.ini or .user.ini (cPanel: MultiPHP INI Editor)
auto_prepend_file = "/home/you/public_html/tokenlock/early.php"
```

```php
<?php require __DIR__ . '/tokenlock/early.php'; // first line of index.php
```

Settings go in `config.php`:

```php
'early' => array(
    'protect'         => array('/members/*', '/api/*'),          // need a pass (nothing else is touched)
    'public'          => array('/members/join'),                 // carve-outs inside protect
    'exclude_paths'   => array('/wp-admin/*', '/wp-login.php'),  // never blocked here
    'admin_ips'       => array('203.0.113.7', '2001:db8::/48'),  // always let through
    'deny_ips'        => array('198.51.100.0/24'),               // always 403
    'trusted_proxies' => array(),                                // X-Forwarded-For is read only from these
),
```

- **Order:** CLI → kill switch → bad path (400, protected paths only) → the TOKENLOCK folder and `exclude_paths` → `admin_ips` → `deny_ips` → `public` → `protect`.
- **You can't lock yourself out.** The sign-in, session and sign-out pages are always reachable, and `exclude_paths`
  and `admin_ips` win over every other rule. To turn the early block off without editing code, upload an empty file named
  `tokenlock/early.off` (for example over FTP), or set `TOKENLOCK_EARLY=off`.
- **Outages and mistakes** always fail closed: an outage answers 503 on protected paths. A broken configuration (missing
  or malformed keys, removed or unknown options) answers 500 on protected paths; the rest of the site keeps working.
  An unusable `'early'` block itself refuses every path except the TOKENLOCK folder and a valid `exclude_paths`
  list until you fix it or use the kill switch (0.4.2).
- **What gets blocked:** paths are matched in canonical form, as in `tokenlock_require()`, so `/MEMBERS`, `//members` and
  `/x/../members` are all protected. A malformed or ambiguous path (`%2f`, `;`, `.` or `..` segments, …) gets 400 before your app runs if any reading of it could reach a protected path (so `/members/..` and `/x/%2e%2e/members` are refused). Malformed paths that can't reach a protected path are left to your app, so the early block never breaks the rest of your site.

## Self-verify (0.3.0, preview, Enterprise)

`tokenlock/self-verify.php` runs the whole sign-in on your server. It needs the **GMP** extension. You issue the
challenge, keep the nonce, verify the wallet signature locally (BIP-322 and legacy: XCP Wallet, Horizon, Unisat, Xverse,
Leather) and read holdings from a source you choose. The formats are the same as the Node SDK. Spec:
https://proveitonchain.com/docs/self-verify

```php
require __DIR__ . '/tokenlock/self-verify.php';
$store = tokenlock_sv_file_store('/var/lib/tokenlock-nonces');            // outside the web root
$holdings = tokenlock_sv_require_agreement(array(tokenlock_sv_tokenscan_provider(), tokenlock_sv_proveitonchain_provider()));
$c = tokenlock_sv_create_challenge(array('site' => 'https://shop.example', 'assets' => array('CLUBTOKEN'), 'store' => $store));
// … the wallet signs $c['message'] …
$r = tokenlock_sv_verify_sign_in($_POST, array('store' => $store, 'holdings' => $holdings, 'pass_secret' => getenv('MY_PASS_SECRET')));
$v = tokenlock_sv_verify_local_pass($_COOKIE['tl_pass'] ?? '', array('pass_secret' => getenv('MY_PASS_SECRET')));
```

To check registered keys offline, use `tokenlock_sv_signed_policy(array('site_id' => …, 'secret_key' => …, 'public_keys' => array($kid => $key), 'cache_dir' => …))`.
It caches the BIP-340-signed bundle on disk, refreshes it every 60 s, and rejects rollbacks. If refreshes fail, it keeps
using the cached bundle until that bundle expires, then fails closed. You can also use `tokenlock_sv_local_policy(...)`.

A resource always needs a registered-keys policy: with no policy, or a token-mode policy, `tokenlock_sv_verify_local_pass()` answers `policy_required` (0.4.0; `identity_valid` says whether the pass itself is good).

Shared authorization matrix (same cases as the Node SDK and the hosted API): `php test/authz-matrix.php`.

Tests: `php test/self-verify.php` covers signatures (the 396 shared vectors), the policy bundle, access rules, replay,
providers, the policy cache, and passes moving between Node and PHP. `node test/early.mjs` tests the early block over HTTP.
