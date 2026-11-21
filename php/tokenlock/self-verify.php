<?php
/**
 * TOKENLOCK self-verify for PHP (Enterprise), spec v1: https://proveitonchain.com/docs/self-verify
 * Your server issues the challenge, stores the nonce, verifies the wallet signature locally (GMP, no network) and
 * reads holdings from a source you choose. Our API is optional: only if you pick our holdings provider or pull a
 * signed policy bundle. Same message, policy and pass formats as the Node SDK (@proveitonchain/tokenlock/self-verify).
 *
 *   require __DIR__ . '/tokenlock/self-verify.php';
 *   $store = tokenlock_sv_file_store('/var/lib/tokenlock-nonces');
 *   $c = tokenlock_sv_create_challenge(array('site' => 'https://shop.example', 'assets' => array('CLUBTOKEN'), 'store' => $store));
 *   // ... wallet signs $c['message'] ...
 *   $r = tokenlock_sv_verify_sign_in($_POST, array('store' => $store, 'holdings' => tokenlock_sv_tokenscan_provider(), 'pass_secret' => getenv('MY_PASS_SECRET')));
 */
require_once __DIR__ . '/btcsig.php';
if (!function_exists('tokenlock_canonical_path')) {
    require_once __DIR__ . '/tokenlock.php';
}
if (defined('TOKENLOCK_SV_SPEC')) {
    return;
}
define('TOKENLOCK_SV_SPEC', 1);

class TokenlockSelfVerifyError extends RuntimeException
{
    public $tlcode, $status;

    public function __construct($code, $message, $status = 400)
    {
        parent::__construct($message);
        $this->tlcode = $code;
        $this->status = $status;
    }
}

function tokenlock_sv_fail($code, $message, $status = 400)
{
    throw new TokenlockSelfVerifyError($code, $message, $status);
}

function tokenlock_sv_iso($ms)
{
    $s = intdiv((int) $ms, 1000);
    return gmdate('Y-m-d\TH:i:s', $s) . sprintf('.%03dZ', ((int) $ms) % 1000);
}

function tokenlock_sv_ms($iso)
{
    // 0.4.2: ISO 8601 timestamps only. strtotime() also reads 'tomorrow', 'never' or 'soon', which must not count.
    if (!is_string($iso) || !preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/', $iso)) {
        return null;
    }
    $t = strtotime($iso);
    if ($t === false) {
        return null;
    }
    $ms = 0;
    if (preg_match('/\.(\d{1,3})/', (string) $iso, $m)) {
        $ms = (int) str_pad($m[1], 3, '0');
    }
    return $t * 1000 + $ms;
}

function tokenlock_sv_now()
{
    return (int) floor(microtime(true) * 1000);
}

function tokenlock_sv_b64url($s)
{
    return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
}

function tokenlock_sv_b64url_decode($s)
{
    $b = strtr((string) $s, '-_', '+/');
    $r = base64_decode($b . str_repeat('=', (4 - strlen($b) % 4) % 4), true);
    return $r === false ? null : $r;
}

function tokenlock_sv_json($v)
{
    return json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

// ------------------------------------------------------------------ assets
function tokenlock_sv_normalize_asset($raw)
{
    // 0.4.5 RC5 (deep review, Node/hosted parity): a string only; trims ASCII whitespace but not NUL (trim()'s default
    // list has \0; Node and hosted refuse it); strtoupper is ASCII-only in PHP 8.
    $a = is_string($raw) ? trim($raw, " \t\n\r\x0B") : '';
    $dot = strpos($a, '.');
    $a = ($dot !== false && $dot > 0) ? strtoupper(substr($a, 0, $dot)) . substr($a, $dot) : strtoupper($a);
    if (preg_match('/^[B-Z][A-Z]{3,11}$/', $a) || preg_match('/^A\d{12,21}$/', $a) || preg_match('/^([B-Z][A-Z]{3,11}|A\d{12,21})\.[a-zA-Z0-9.\-_@!]{1,200}$/', $a)) {
        return $a;
    }
    tokenlock_sv_fail('bad_asset', '"' . substr(is_string($raw) ? $raw : gettype($raw), 0, 60) . '" is not a valid Bitcoin asset name.');
}

// ------------------------------------------------------------------ challenge message (spec §2)
function tokenlock_sv_build_message($r)
{
    $assets = $r['assets'];
    $req = (count($assets) ? implode(' or ', $assets) : '') . (count($assets) && !empty($r['any_name']) ? ' or ' : '') . (!empty($r['any_name']) ? 'any name on Bitcoin' : '');
    return implode("\n", array('Sign in with your Token', 'Site: ' . $r['site'], 'Requires: ' . $req, 'Via: self-verify', 'Nonce: ' . $r['nonce'],
        'Issued: ' . $r['issued_at'], 'Expires: ' . $r['expires_at'], 'Signing proves you control this address. It moves no funds.'));
}

// ------------------------------------------------------------------ nonce stores (spec §3: replay protection is yours)
/** A store is array('put' => fn($nonce, $record, $expiresAtMs), 'take' => fn($nonce): ?array). take must be atomic. */
function tokenlock_sv_file_store($dir)
{
    return array(
        'put' => function ($n, $r, $e) use ($dir) {
            if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
                tokenlock_sv_fail('store_unavailable', 'Nonce folder is not writable.', 503);
            }
            $f = @fopen($dir . '/' . $n . '.json', 'x');
            if (!$f) {
                tokenlock_sv_fail('nonce_collision', 'Nonce already exists.', 500);
            }
            @chmod($dir . '/' . $n . '.json', 0600);
            fwrite($f, tokenlock_sv_json(array('r' => $r, 'e' => $e)));
            fclose($f);
        },
        'take' => function ($n) use ($dir) {
            if (!preg_match('/^[0-9a-f]{32}$/', (string) $n)) {
                return null;
            }
            $src = $dir . '/' . $n . '.json';
            $dst = $src . '.taken.' . bin2hex(random_bytes(4));
            if (!@rename($src, $dst)) {
                return null; // unknown or already taken (rename is atomic on one filesystem)
            }
            $raw = @file_get_contents($dst);
            @unlink($dst);
            $j = $raw === false ? null : json_decode($raw, true);
            return (is_array($j) && isset($j['e']) && $j['e'] >= tokenlock_sv_now() - 60000) ? $j['r'] : null;
        },
    );
}

/** In-process store (tests, single long-running worker only). */
function tokenlock_sv_memory_store()
{
    $m = new ArrayObject();
    return array(
        'put' => function ($n, $r, $e) use ($m) {
            $m[$n] = $r;
        },
        'take' => function ($n) use ($m) {
            if (!isset($m[$n])) {
                return null;
            }
            $r = $m[$n];
            unset($m[$n]);
            return $r;
        },
    );
}

/** Redis store via phpredis: SET NX PX + GETDEL (Redis 6.2+). */
function tokenlock_sv_redis_store($redis, $prefix = 'tokenlock:nonce:')
{
    return array(
        'put' => function ($n, $r, $e) use ($redis, $prefix) {
            if (!$redis->set($prefix . $n, tokenlock_sv_json($r), array('nx', 'px' => max(1000, $e - tokenlock_sv_now())))) {
                tokenlock_sv_fail('nonce_collision', 'Nonce already exists.', 500);
            }
        },
        'take' => function ($n) use ($redis, $prefix) {
            $v = $redis->rawCommand('GETDEL', $prefix . $n);
            return $v ? json_decode($v, true) : null;
        },
    );
}

/** The origin of a site URL (scheme://host[:port], lowercase, default port dropped), or null. */
function tokenlock_sv_site_origin($raw)
{
    $u = is_string($raw) ? parse_url($raw) : false;
    if (!$u || empty($u['scheme']) || empty($u['host']) || !in_array(strtolower($u['scheme']), array('http', 'https'), true)) {
        return null;
    }
    return strtolower($u['scheme']) . '://' . strtolower($u['host']) . (isset($u['port']) && !(($u['scheme'] === 'https' && $u['port'] == 443) || ($u['scheme'] === 'http' && $u['port'] == 80)) ? ':' . $u['port'] : '');
}

/** One-time challenge. Default lifetime 10 minutes (60 s to 30 min); pass lifetime default 15 min (60 s to 24 h). */
function tokenlock_sv_create_challenge($o)
{
    $site = tokenlock_sv_site_origin($o['site'] ?? '');
    if ($site === null) {
        tokenlock_sv_fail('bad_site', '`site` must be your origin, e.g. https://shop.example');
    }
    $assets = array_values(array_unique(array_map('tokenlock_sv_normalize_asset', (array) ($o['assets'] ?? array()))));
    if (count($assets) > 10) {
        tokenlock_sv_fail('too_many_assets', 'At most 10 assets.');
    }
    $any = !empty($o['any_name']);
    if (!$assets && !$any) {
        tokenlock_sv_fail('asset_required', 'Give `assets` (any one is enough) or set `any_name` => true.');
    }
    $ttl = min(1800, max(60, (int) round($o['ttl_seconds'] ?? 600)));
    $now = isset($o['now']) ? (int) $o['now'] : tokenlock_sv_now();
    $r = array('v' => 1, 'nonce' => bin2hex(random_bytes(16)), 'site' => $site, 'assets' => $assets, 'any_name' => $any,
        'issued_at' => tokenlock_sv_iso($now), 'expires_at' => tokenlock_sv_iso($now + $ttl * 1000), 'pass_ttl_s' => min(86400, max(60, (int) round($o['pass_ttl_seconds'] ?? 900))));
    call_user_func($o['store']['put'], $r['nonce'], $r, $now + $ttl * 1000);
    return array('challenge_id' => $r['nonce'], 'message' => tokenlock_sv_build_message($r), 'assets' => $assets, 'any_name' => $any, 'origin' => $site,
        'issued_at' => $r['issued_at'], 'expires_at' => $r['expires_at'], 'mode' => 'self-verify');
}

// ------------------------------------------------------------------ holdings providers (spec §4)
/** Default HTTP GET JSON (curl). Returns array(status, body|null). Throws on network errors. Override with 'http'. */
function tokenlock_sv_http_get($url, $headers = array(), $timeout = 8)
{
    $h = array('Accept: application/json');
    foreach ($headers as $k => $v) {
        $h[] = $k . ': ' . $v;
    }
    $ch = curl_init($url);
    curl_setopt_array($ch, array(CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => $timeout, CURLOPT_CONNECTTIMEOUT => min(5, $timeout), CURLOPT_HTTPHEADER => $h,
        CURLOPT_FOLLOWLOCATION => false, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP));
    $body = curl_exec($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $err = curl_errno($ch);
    curl_close($ch);
    if ($body === false || $err) {
        throw new TokenlockSelfVerifyError('lookup_failed', 'network', 502);
    }
    return array($status, json_decode($body, true));
}

function tokenlock_sv_lookup_failed($who, $why)
{
    return new TokenlockSelfVerifyError('lookup_failed', $who . ': could not read holdings (' . $why . ').', 502);
}

function tokenlock_sv_get($o, $url, $headers = array())
{
    $http = $o['http'] ?? 'tokenlock_sv_http_get';
    return call_user_func($http, $url, $headers, (int) ceil(($o['timeout_ms'] ?? 8000) / 1000));
}

/** Our hosted lookup (optional). You then trust our reading of the chain. A provider is fn($address, $assets): array. */
function tokenlock_sv_proveitonchain_provider($o = array())
{
    $api = rtrim($o['api'] ?? 'https://proveitonchain.com', '/');
    return function ($address, $assets) use ($o, $api) {
        try {
            list($st, $b) = tokenlock_sv_get($o, $api . '/api/v1/tokenlock/holdings?address=' . rawurlencode($address) . '&assets=' . rawurlencode(implode(',', $assets)));
        } catch (Throwable $e) {
            throw tokenlock_sv_lookup_failed('proveitonchain', 'network');
        }
        if ($st < 200 || $st >= 300 || !is_array($b) || !isset($b['holdings']) || !is_array($b['holdings'])) {
            throw tokenlock_sv_lookup_failed('proveitonchain', 'status ' . $st);
        }
        $out = array();
        foreach ($assets as $a) {
            $x = $b['holdings'][$a] ?? null;
            if ($x === null) {
                $out[$a] = array('held' => false, 'how' => null);
                continue;
            }
            // 0.4.2: an entry must be an object whose 'held' is a boolean; "false", 1 or "yes" are unreadable, not "held".
            if (!is_array($x) || !array_key_exists('held', $x) || !is_bool($x['held'])) {
                throw tokenlock_sv_lookup_failed('proveitonchain', 'unreadable answer');
            }
            $out[$a] = array('held' => $x['held'], 'how' => $x['how'] ?? null, 'quantity' => $x['quantity'] ?? null, 'exists' => $x['exists'] ?? null);
        }
        return $out;
    };
}

/** Public explorer tokenscan.io (no key): asset owner, then address balances. */
function tokenlock_sv_tokenscan_provider($o = array())
{
    $base = rtrim($o['base'] ?? 'https://tokenscan.io/api', '/');
    return function ($address, $assets) use ($o, $base) {
        $out = array();
        $bal = null;
        foreach ($assets as $a) {
            try {
                list($st, $info) = tokenlock_sv_get($o, $base . '/asset/' . rawurlencode($a));
            } catch (Throwable $e) {
                throw tokenlock_sv_lookup_failed('tokenscan', 'network');
            }
            if (is_array($info) && isset($info['error']) && preg_match('/not found/i', (string) $info['error'])) {
                $out[$a] = array('held' => false, 'how' => null, 'exists' => false);
                continue;
            }
            if ($st < 200 || $st >= 300 || !is_array($info) || empty($info['asset'])) {
                throw tokenlock_sv_lookup_failed('tokenscan', 'status ' . $st);
            }
            if ((($info['owner'] ?? null) ?: ($info['issuer'] ?? null)) === $address) {
                $out[$a] = array('held' => true, 'how' => 'owner', 'exists' => true);
                continue;
            }
            if ($bal === null) {
                $bal = array();
                for ($page = 1; $page <= 4; $page++) {
                    try {
                        list($st, $r) = tokenlock_sv_get($o, $base . '/balances/' . rawurlencode($address) . '/' . $page . '/500');
                    } catch (Throwable $e) {
                        throw tokenlock_sv_lookup_failed('tokenscan', 'network');
                    }
                    if ($st < 200 || $st >= 300) {
                        throw tokenlock_sv_lookup_failed('tokenscan', 'status ' . $st);
                    }
                    $list = (is_array($r) && isset($r['data']) && is_array($r['data'])) ? $r['data'] : array();
                    foreach ($list as $x) {
                        $q = (float) ($x['quantity'] ?? 0);
                        if ($q > 0) {
                            if (!empty($x['asset'])) {
                                $bal[(string) $x['asset']] = $q;
                            }
                            if (!empty($x['asset_longname'])) {
                                $bal[(string) $x['asset_longname']] = $q;
                            }
                        }
                    }
                    if (count($list) < 500) {
                        break;
                    }
                }
            }
            $q = $bal[$a] ?? 0;
            $out[$a] = $q > 0 ? array('held' => true, 'how' => 'balance', 'quantity' => (string) $q, 'exists' => true) : array('held' => false, 'how' => null, 'exists' => true);
        }
        return $out;
    };
}

/**
 * Any HTTP JSON source (your node, your indexer, another explorer). 'url' has {address} and {asset}.
 * 'quantity' => fn($body) gives the balance; optional 'owner' => fn($body), 'not_found' => fn($status, $body), 'headers'.
 */
function tokenlock_sv_http_json_provider($o)
{
    $name = $o['name'] ?? 'http-json';
    if (strpos((string) ($o['url'] ?? ''), '{address}') === false) {
        tokenlock_sv_fail('bad_provider', '`url` must contain {address}.');
    }
    return function ($address, $assets) use ($o, $name) {
        $out = array();
        foreach ($assets as $a) {
            $url = str_replace(array('{address}', '{asset}'), array(rawurlencode($address), rawurlencode($a)), $o['url']);
            try {
                list($st, $b) = tokenlock_sv_get($o, $url, $o['headers'] ?? array());
            } catch (Throwable $e) {
                throw tokenlock_sv_lookup_failed($name, 'network');
            }
            if (isset($o['not_found']) && call_user_func($o['not_found'], $st, $b)) {
                $out[$a] = array('held' => false, 'how' => null, 'exists' => false);
                continue;
            }
            if ($st < 200 || $st >= 300) {
                throw tokenlock_sv_lookup_failed($name, 'status ' . $st);
            }
            $owner = isset($o['owner']) ? call_user_func($o['owner'], $b) : null;
            if ($owner && $owner === $address) {
                $out[$a] = array('held' => true, 'how' => 'owner');
                continue;
            }
            $q = call_user_func($o['quantity'], $b);
            if (!is_numeric($q)) {
                throw tokenlock_sv_lookup_failed($name, 'unreadable answer');
            }
            $out[$a] = $q > 0 ? array('held' => true, 'how' => 'balance', 'quantity' => (string) $q) : array('held' => false, 'how' => null);
        }
        return $out;
    };
}

/** Fixed holdings (tests, demos). $owners lists, per address, the names it OWNS ('how' => 'owner'); the rest of $map is a balance. */
function tokenlock_sv_static_provider($map, $owners = array())
{
    return function ($address, $assets) use ($map, $owners) {
        $have = $map[$address] ?? array();
        $own = $owners[$address] ?? array();
        $out = array();
        foreach ($assets as $a) {
            if (in_array($a, $own, true)) {
                $out[$a] = array('held' => true, 'how' => 'owner');
                continue;
            }
            $h = in_array($a, $have, true);
            $out[$a] = array('held' => $h, 'how' => $h ? 'balance' : null);
        }
        return $out;
    };
}

/** First provider that answers wins; fails closed if none does. */
function tokenlock_sv_first_available($providers)
{
    return function ($address, $assets) use ($providers) {
        foreach ($providers as $p) {
            try {
                return call_user_func($p, $address, $assets);
            } catch (Throwable $e) {
                // next
            }
        }
        throw new TokenlockSelfVerifyError('lookup_failed', 'No holdings source answered.', 502);
    };
}

/** All providers must answer and agree on `held`, else fail closed. */
function tokenlock_sv_require_agreement($providers)
{
    return function ($address, $assets) use ($providers) {
        $all = array();
        foreach ($providers as $p) {
            $all[] = call_user_func($p, $address, $assets);
        }
        foreach ($assets as $x) {
            $seen = array();
            foreach ($all as $h) {
                $v = (is_array($h) && isset($h[$x]) && is_array($h[$x]) && array_key_exists('held', $h[$x])) ? $h[$x]['held'] : null;
                if ($v !== null && !is_bool($v)) {
                    throw new TokenlockSelfVerifyError('lookup_failed', 'A holdings source gave an unreadable answer for ' . $x . '.', 502);
                }
                $seen[$v === true ? 1 : 0] = true;
            }
            if (count($seen) !== 1) {
                throw new TokenlockSelfVerifyError('lookup_disagreement', 'Holdings sources disagree on ' . $x . '.', 502);
            }
        }
        return $all[0];
    };
}

// ------------------------------------------------------------------ policy (spec §5)
/** Check a policy bundle offline: pinned key, site, freshness, no rollback. Returns the policy array; throws. */
function tokenlock_sv_verify_policy_bundle($bundle, $o)
{
    if (!is_array($bundle) || ($bundle['v'] ?? null) !== 1 || ($bundle['alg'] ?? null) !== 'BIP340' || !is_string($bundle['payload'] ?? null) || !is_string($bundle['sig'] ?? null)) {
        tokenlock_sv_fail('policy_invalid', 'Not a policy bundle.', 502);
    }
    $pk = $o['public_keys'];
    $cands = array_values(array_filter(array_keys($pk) === range(0, count($pk) - 1) ? $pk : array($pk[(string) ($bundle['kid'] ?? '')] ?? null)));
    if (!$cands) {
        tokenlock_sv_fail('policy_untrusted_key', 'Policy signed by unknown key ' . substr((string) ($bundle['kid'] ?? ''), 0, 20) . '.', 502);
    }
    $bytes = tokenlock_sv_b64url_decode($bundle['payload']);
    $sig = preg_match('/^[0-9a-f]{128}$/i', $bundle['sig']) ? hex2bin($bundle['sig']) : null;
    $ok = false;
    if ($bytes !== null && $sig !== null) {
        $msg = tokenlock_tagged_hash('TOKENLOCK/policy/v1', $bytes);
        foreach ($cands as $c) {
            if (preg_match('/^[0-9a-f]{64}$/i', (string) $c) && TokenlockSecp::schnorrVerify($sig, $msg, hex2bin($c))) {
                $ok = true;
                break;
            }
        }
    }
    if (!$ok) {
        tokenlock_sv_fail('policy_bad_signature', 'Policy bundle signature does not verify.', 502);
    }
    $p = json_decode($bytes, true);
    if (!is_array($p)) {
        tokenlock_sv_fail('policy_invalid', 'Policy payload is not JSON.', 502);
    }
    if (($p['typ'] ?? null) !== 'tokenlock.policy' || ($p['v'] ?? null) !== 1) {
        tokenlock_sv_fail('policy_invalid', 'Unknown policy version.', 502);
    }
    if (($p['site_id'] ?? null) !== $o['site_id']) {
        tokenlock_sv_fail('policy_wrong_site', 'Policy is for another site.', 502);
    }
    $now = $o['now'] ?? tokenlock_sv_now();
    tokenlock_sv_validate_policy($p, $now, true);
    $exp = tokenlock_sv_ms($p['expires_at'] ?? '');
    if (!$exp || $exp <= $now) {
        tokenlock_sv_fail('policy_expired', 'Policy bundle expired. Fetch a fresh one.', 503);
    }
    if (!empty($o['max_age_seconds']) && $now - tokenlock_sv_ms($p['issued_at'] ?? '') > $o['max_age_seconds'] * 1000) {
        tokenlock_sv_fail('policy_stale', 'Policy bundle is older than allowed.', 503);
    }
    if (isset($o['min_seq']) && $o['min_seq'] !== null && ($p['seq'] ?? -1) < $o['min_seq']) {
        tokenlock_sv_fail('policy_rollback', 'Policy bundle is older than one already seen.', 502);
    }
    // 0.4.5 RC5 (H1, client side): a bundle that drops registered-keys mode is accepted only when its state_version is
    // higher than the bundle it replaces ('previous': the last accepted policy, or array('mode', 'state_version')).
    $prev = $o['previous'] ?? null;
    if (is_array($prev) && ($prev['mode'] ?? null) === 'registered_keys' && ($p['mode'] ?? null) !== 'registered_keys' && !(tokenlock_sv_state_version($p) > tokenlock_sv_state_version($prev))) {
        tokenlock_sv_fail('policy_downgrade', 'Policy bundle drops registered-keys mode without a newer state version.', 502);
    }
    return $p;
}

function tokenlock_sv_state_version($p)
{
    $v = tokenlock_sv_whole($p['state_version'] ?? null);
    return $v === null ? -1 : $v;
}

// 0.4.5 RC5 (deep review, Node parity): a JSON whole number 0 .. 2^53-1 (Number.isSafeInteger in Node), also when JSON
// wrote it as an integral float (1e0); returns it as an int, else null. PHP accepted 2^53 .. 2^63-1 and refused 1e0.
function tokenlock_sv_whole($v)
{
    if (is_int($v)) return ($v >= 0 && $v <= 9007199254740991) ? $v : null;
    if (is_float($v) && is_finite($v) && floor($v) == $v && $v >= 0 && $v <= 9007199254740991) return (int) $v;
    return null;
}

/**
 * Signed policy from our API, cached on disk across requests. Refreshes every 'refresh_seconds' (default 60); if a
 * refresh fails, the cached bundle is used until it expires, then access fails closed (policy_expired).
 * Options: site_id, secret_key, public_keys, cache_dir, api, refresh_seconds, ttl_seconds, http, load (callable).
 * Returns a policy source: a callable that returns the policy array or throws.
 */
function tokenlock_sv_signed_policy($o)
{
    $api = rtrim($o['api'] ?? 'https://proveitonchain.com', '/');
    $dir = $o['cache_dir'] ?? (__DIR__ . '/cache');
    $file = $dir . '/tokenlock_policy_' . substr(hash('sha256', (string) $o['site_id']), 0, 16) . '.json';
    return function () use ($o, $api, $file) {
        $now = tokenlock_sv_now();
        $c = is_file($file) ? json_decode((string) @file_get_contents($file), true) : null;
        $cur = null;
        $seq = null;
        if (is_array($c) && isset($c['bundle'])) {
            try {
                $cur = tokenlock_sv_verify_policy_bundle($c['bundle'], array('public_keys' => $o['public_keys'], 'site_id' => $o['site_id'], 'now' => $now));
            } catch (TokenlockSelfVerifyError $e) {
                $cur = null; // expired or tampered cache: refetch
            }
            $seq = $c['seq'] ?? null;
        }
        // 0.4.5 RC5 (H1): the mode and state version of the last accepted bundle survive in the cache record even after the
        // cached bundle itself expires, so a later downgrade is still compared against them.
        $prev = $cur ? $cur : ((is_array($c) && isset($c['mode'])) ? array('mode' => $c['mode'], 'state_version' => $c['state_version'] ?? null) : null);
        if (!$cur || $now - (int) ($c['fetched_at'] ?? 0) > ($o['refresh_seconds'] ?? 60) * 1000) {
            try {
                if (isset($o['load'])) {
                    $b = call_user_func($o['load']);
                } else {
                    list($st, $b) = tokenlock_sv_get($o, $api . '/api/v1/tokenlock/access/policy' . (!empty($o['ttl_seconds']) ? '?ttl=' . (int) $o['ttl_seconds'] : ''), array('Authorization' => 'Bearer ' . $o['secret_key']));
                    if ($st < 200 || $st >= 300) {
                        throw new TokenlockSelfVerifyError('policy_unavailable', 'Policy endpoint answered ' . $st, 503);
                    }
                }
                $p = tokenlock_sv_verify_policy_bundle($b, array('public_keys' => $o['public_keys'], 'site_id' => $o['site_id'], 'now' => $now, 'min_seq' => $seq, 'previous' => $prev));
                return tokenlock_sv_policy_cache_commit($file, $b, $p, $now, function ($bundle) use ($o, $now) {
                    return tokenlock_sv_verify_policy_bundle($bundle, array('public_keys' => $o['public_keys'], 'site_id' => $o['site_id'], 'now' => $now));
                });
            } catch (Throwable $e) {
                if ($e instanceof TokenlockSelfVerifyError && ($e->tlcode === 'policy_rollback' || $e->tlcode === 'policy_downgrade' || $e->tlcode === 'policy_cache_failed')) {
                    throw $e;
                }
                // 0.5.0 RC6: the cached bundle is a fallback only while the cache can be written. If it cannot, a newer
                // bundle accepted by an earlier request may never have reached the disk, so the record on disk may be
                // older than what was already enforced: fail closed instead of falling back to it.
                if (!$cur || !tokenlock_sv_policy_cache_writable($file)) {
                    throw ($e instanceof TokenlockSelfVerifyError) ? $e : new TokenlockSelfVerifyError('policy_unavailable', 'Could not load the policy bundle.', 503);
                }
            }
        }
        return $cur;
    };
}

/**
 * 0.5.0 RC6 (PHP policy cache): store a newly accepted bundle so the disk record never falls behind the newest policy
 * any worker accepted. RC5 wrote without a lock and ignored write failures, so (a) two overlapping refreshes could leave
 * the OLDER bundle on disk (a revocation in the newer one was then ignored by later requests, and used as the fallback
 * during an API outage), and (b) a failed write left the previous bundle as the fallback. Now:
 *   - updates are serialized with flock() on "<cache>.lock", and the record is re-read under the lock;
 *   - the bundle with the higher seq wins: if a concurrent refresh already stored a newer one, that one is returned;
 *   - if the new record cannot be written, the old record is deleted, so no older bundle can be used as a fallback
 *     later; if it cannot be deleted either, the refresh fails closed (policy_cache_failed, 503).
 */
function tokenlock_sv_policy_cache_commit($file, $bundle, $p, $now, $verify)
{
    $lock = @fopen($file . '.lock', 'c');
    $locked = $lock !== false && @flock($lock, LOCK_EX);
    if (!$locked) {
        if ($lock !== false) {
            @fclose($lock);
        }
        tokenlock_sv_policy_cache_drop($file);
        return $p;
    }
    try {
        clearstatcache(true, $file);
        $c = is_file($file) ? json_decode((string) @file_get_contents($file), true) : null;
        $stored = (is_array($c) && isset($c['bundle'])) ? tokenlock_sv_whole($c['seq'] ?? null) : null;
        $mine = tokenlock_sv_whole($p['seq']);
        if ($stored !== null && $stored > $mine) {
            // A concurrent refresh stored a newer bundle: it wins (never write an older one over it).
            try {
                return call_user_func($verify, $c['bundle']);
            } catch (TokenlockSelfVerifyError $e) {
                throw new TokenlockSelfVerifyError('policy_cache_failed', 'A newer cached policy exists but cannot be used.', 503);
            }
        }
        if ($stored !== null && $stored === $mine) {
            return $p; // the same bundle is already stored
        }
        $tmp = $file . '.' . bin2hex(random_bytes(4));
        $ok = @file_put_contents($tmp, tokenlock_sv_json(array('bundle' => $bundle, 'seq' => $p['seq'], 'mode' => $p['mode'], 'state_version' => $p['state_version'] ?? null, 'fetched_at' => $now))) !== false;
        if ($ok) {
            @chmod($tmp, 0600);
            $ok = @rename($tmp, $file);
        }
        if (!$ok) {
            @unlink($tmp);
            tokenlock_sv_policy_cache_drop($file);
        }
        return $p;
    } finally {
        @flock($lock, LOCK_UN);
        @fclose($lock);
    }
}

function tokenlock_sv_policy_cache_writable($file)
{
    clearstatcache(true, $file);
    return @is_writable(dirname($file)) && (!is_file($file) || @is_writable($file));
}

function tokenlock_sv_policy_cache_drop($file)
{
    @unlink($file);
    clearstatcache(true, $file);
    if (is_file($file)) {
        throw new TokenlockSelfVerifyError('policy_cache_failed', 'The policy cache could not be updated or removed.', 503);
    }
}

function tokenlock_sv_is_list($a)
{
    if (!is_array($a)) {
        return false;
    }
    $i = 0;
    foreach ($a as $k => $unused) {
        if ($k !== $i++) {
            return false;
        }
    }
    return true;
}

function tokenlock_sv_str_list($a)
{
    if (!tokenlock_sv_is_list($a)) {
        return false;
    }
    foreach ($a as $x) {
        if (!is_string($x)) {
            return false;
        }
    }
    return true;
}

/**
 * 0.4.2: shape check for a policy (signed or local). Anything malformed throws policy_invalid and access is denied:
 * a typo in 'mode', a string where a list belongs, an unparseable date (an unparseable key expiry would never
 * expire), a non-integer seq (breaks rollback protection) or an unknown key status.
 */
// 0.4.4: the validity window is part of validity, for EVERY policy (signed bundle, local policy, custom source, a policy
// handed straight to tokenlock_sv_evaluate()), checked against the decision's $now: expires_at <= now is policy_expired and
// issued_at more than 5 minutes ahead is policy_invalid. 0.4.3 checked expiry only on the signed-bundle path and the future
// check only when $signed, so an explicitly expired local policy still authorized (external review). $signed is kept for
// compatibility and no longer changes the rules.
function tokenlock_sv_validate_policy($p, $now = null, $signed = false)
{
    $now = $now ?? tokenlock_sv_now();
    $bad = function ($why) {
        tokenlock_sv_fail('policy_invalid', 'Policy is malformed: ' . $why . '.', 502);
    };
    if (!is_array($p) || tokenlock_sv_is_list($p)) {
        $bad('not an object');
    }
    if (($p['v'] ?? null) !== 1 || ($p['typ'] ?? null) !== 'tokenlock.policy') {
        $bad('unknown version');
    }
    if (!isset($p['site_id']) || !is_string($p['site_id']) || $p['site_id'] === '') {
        $bad('site_id');
    }
    if (!isset($p['seq']) || tokenlock_sv_whole($p['seq']) === null) {
        $bad('seq must be a whole number >= 0');
    }
    $iss = tokenlock_sv_ms($p['issued_at'] ?? null);
    $exp = tokenlock_sv_ms($p['expires_at'] ?? null);
    if ($iss === null) {
        $bad('issued_at');
    }
    if ($exp === null) {
        $bad('expires_at');
    }
    if ($exp < $iss) {
        $bad('expires_at is before issued_at');
    }
    if (!is_int($now) && !is_float($now)) {
        $bad('no valid current time to check it against');
    }
    if ($iss > $now + 300000) {
        $bad('issued_at is in the future');
    }
    if ($exp <= $now) {
        tokenlock_sv_fail('policy_expired', 'Access policy expired at ' . $p['expires_at'] . '. Fetch or write a fresh one.', 503);
    }
    if (!in_array($p['mode'] ?? null, array('token', 'registered_keys'), true)) {
        $bad('mode must be "token" or "registered_keys"');
    }
    if (!tokenlock_sv_is_list($p['orgs'] ?? null)) {
        $bad('orgs');
    }
    foreach ($p['orgs'] as $o) {
        if (!is_array($o) || !isset($o['id'], $o['status']) || !is_string($o['id']) || !is_string($o['status'])) {
            $bad('orgs');
        }
    }
    if (!tokenlock_sv_str_list($p['revoked_assets'] ?? null)) {
        $bad('revoked_assets');
    }
    foreach (array('assets', 'origins') as $k) {
        if (array_key_exists($k, $p) && $p[$k] !== null && !tokenlock_sv_str_list($p[$k])) {
            $bad($k);
        }
    }
    if (array_key_exists('any_name', $p) && $p['any_name'] !== null && !is_bool($p['any_name'])) {
        $bad('any_name');
    }
    if (array_key_exists('settings', $p) && $p['settings'] !== null && (!is_array($p['settings']) || ($p['settings'] !== array() && tokenlock_sv_is_list($p['settings'])))) {
        $bad('settings');
    }
    if (array_key_exists('state_version', $p) && tokenlock_sv_whole($p['state_version']) === null) {
        $bad('state_version must be a whole number >= 0');
    }
    if (!tokenlock_sv_is_list($p['keys'] ?? null)) {
        $bad('keys must be a list');
    }
    foreach ($p['keys'] as $k) {
        if (!is_array($k) || tokenlock_sv_is_list($k)) {
            $bad('key');
        }
        if (!isset($k['id'], $k['address']) || !is_string($k['id']) || $k['id'] === '' || !is_string($k['address']) || $k['address'] === '') {
            $bad('key id/address');
        }
        if (!in_array($k['status'] ?? null, array('active', 'revoked', 'pending_approval'), true)) {
            $bad('key status');
        }
        if (isset($k['org_id']) && !is_string($k['org_id'])) {
            $bad('key org_id');
        }
        if (isset($k['assets']) && !tokenlock_sv_str_list($k['assets'])) {
            $bad('key assets');
        }
        if (isset($k['expires_at']) && tokenlock_sv_ms($k['expires_at']) === null) {
            $bad('key expires_at');
        }
        if (isset($k['pass_ttl_s']) && !((is_int($k['pass_ttl_s']) || is_float($k['pass_ttl_s'])) && $k['pass_ttl_s'] > 0)) {
            $bad('key pass_ttl_s');
        }
        if (isset($k['permissions'])) {
            $pm = $k['permissions'];
            if (!is_array($pm) || ($pm !== array() && tokenlock_sv_is_list($pm))) {
                $bad('key permissions');
            }
            foreach (array('routes', 'methods', 'environments') as $f) {
                if (isset($pm[$f]) && !tokenlock_sv_str_list($pm[$f])) {
                    $bad("key permissions.$f must be a list");
                }
            }
            // 0.4.5 RC3 (contract 1.1 section 5): permissions is a closed object; an unknown field makes the policy invalid.
            foreach (array_keys($pm) as $f) {
                if (!in_array($f, array('routes', 'methods', 'environments'), true)) {
                    $bad("key permissions.$f is not a known field");
                }
            }
        }
    }
    // 0.4.5 RC5 (S2): one entry per address (case-insensitive) and per id. Two entries for one address are ambiguous; RC3
    // used the first one, so a later revoked entry was ignored. Ambiguous data never increases access.
    $ids = array();
    $addrs = array();
    foreach ($p['keys'] as $k) {
        $a = strtolower($k['address']);
        if (isset($ids[$k['id']])) {
            $bad('duplicate key id ' . substr($k['id'], 0, 40));
        }
        if (isset($addrs[$a])) {
            $bad('duplicate key address');
        }
        $ids[$k['id']] = true;
        $addrs[$a] = true;
    }
}

/**
 * Your own policy (array or callable): same shape, no signature (you are the source). Malformed → policy_invalid.
 * Leaving out issued_at/expires_at gives 1970 / 9999 (no expiry); an expires_at you SET is enforced on every call (0.4.4):
 * past it the source throws policy_expired and every decision that uses it is denied.
 */
function tokenlock_sv_local_policy($get)
{
    return function () use ($get) {
        $p = is_callable($get) ? call_user_func($get) : $get;
        if (!is_array($p)) {
            tokenlock_sv_fail('policy_invalid', 'Policy is malformed: not an object.', 502);
        }
        $out = array_merge(array('v' => 1, 'typ' => 'tokenlock.policy', 'site_id' => 'local', 'seq' => 0, 'issued_at' => tokenlock_sv_iso(0),
            'expires_at' => '9999-12-31T00:00:00.000Z', 'orgs' => array(), 'revoked_assets' => array(), 'keys' => array(), 'mode' => 'registered_keys'), $p);
        tokenlock_sv_validate_policy($out);
        return $out;
    };
}

/** Case-insensitive route match on a canonical path (same as the hosted API). */
function tokenlock_sv_route_matches($pattern, $path)
{
    $p = strtolower(trim((string) $pattern));
    $q = strtolower((string) $path);
    if ($p === '*' || $p === '/*') {
        return true;
    }
    if (substr($p, -2) === '/*') {
        $base = rtrim(substr($p, 0, -2), '/');
        return $q === $base || strpos($q, $base . '/') === 0 || ($base === '' && strpos($q, '/') === 0);
    }
    // 0.4.5 RC2 (contract v1): only a trailing "/*" is a prefix. "/api/" is the exact route /api; RC1 and earlier read it
    // as the prefix /api/* (a broader grant than written).
    return $q === rtrim($p, '/') || ($p === '/' && $q === '/');
}

/**
 * Same access rule as hosted TOKENLOCK. $resource is array('path' => …, 'method' => …[, 'environment' => …]) or
 * array('identity_only' => true). 0.4.4 order, every step before any mode branch: (1) the authorization request (null,
 * missing or malformed → bad_resource / bad_path; identity is never implied); (2) $held must be a list of asset names
 * (bad_input; null no longer skips the holdings check); (3) the policy: shape and validity window against $now
 * (policy_invalid / policy_expired); (4) a token-mode policy has no route rules, so a resource is policy_required;
 * (5) keys, holdings, routes. 0.4.3 returned allowed from the token-mode branch for a valid resource (external review).
 */
function tokenlock_sv_evaluate($policy, $address, $held, $resource = null, $now = null)
{
    $deny = function ($r) { return array('allowed' => false, 'reason' => $r); };
    list($clean, $rerr) = tokenlock_validate_resource($resource);
    if ($rerr !== null) {
        return $deny($rerr === 'bad_path' ? 'bad_path' : 'bad_resource');
    }
    $resource = $clean; // null here = array('identity_only' => true), given explicitly
    if (!tokenlock_sv_str_list($held)) {
        return $deny('bad_input');
    }
    $now = $now ?? tokenlock_sv_now();
    if (!is_int($now) && !is_float($now)) {
        return $deny('bad_input');
    }
    try {
        tokenlock_sv_validate_policy($policy, $now);
    } catch (TokenlockSelfVerifyError $e) {
        return $deny($e->tlcode === 'policy_expired' ? 'policy_expired' : 'policy_invalid');
    }
    $revoked = $policy['revoked_assets'] ?? array();
    if (($policy['mode'] ?? '') !== 'registered_keys') {
        if ($resource !== null) {
            return $deny('policy_required');
        }
        if (!array_diff($held, $revoked)) {
            return $deny($held ? 'entitlement_revoked' : 'not_holder');
        }
        return array('allowed' => true, 'reason' => 'ok');
    }
    $key = null;
    foreach ($policy['keys'] ?? array() as $k) {
        if (($k['address'] ?? null) === $address) {
            $key = $k;
            break;
        }
    }
    $no = function ($r) use (&$key) {
        return array('allowed' => false, 'reason' => $r, 'key' => $key);
    };
    if (!$key) {
        return $no('not_registered');
    }
    $st = $key['status'] ?? '';
    if ($st === 'revoked') {
        return $no('key_revoked');
    }
    if ($st === 'pending_approval') {
        return $no('pending_approval');
    }
    if ($st !== 'active') {
        return $no('not_registered');
    }
    if (isset($key['expires_at']) && $key['expires_at'] !== '') {
        $ke = tokenlock_sv_ms($key['expires_at']);
        if ($ke === null || $ke <= $now) {
            return $no('key_expired');
        }
    }
    if (!empty($key['org_id'])) {
        $org = null;
        foreach ($policy['orgs'] ?? array() as $x) {
            if (($x['id'] ?? null) === $key['org_id']) {
                $org = $x;
            }
        }
        if (!$org || ($org['status'] ?? '') !== 'approved') {
            return $no('org_not_approved');
        }
    } elseif (!empty($policy['settings']['require_org'])) {
        return $no('org_required');
    }
    $ka = $key['assets'] ?? array();
    $ok = array_filter($held, function ($a) use ($revoked, $ka) {
        return !in_array($a, $revoked, true) && (!$ka || in_array($a, $ka, true));
    });
    if (!$ok) {
        return $no($held ? 'entitlement_revoked' : 'not_holder');
    }
    if ($resource) {
        // 0.4.5: a grant must be explicit. permissions missing, null or not an array, or routes / methods missing, null or
        // not a list of strings: the key is refused (policy_invalid). 0.4.4 read a missing or null routes / methods as
        // array('*'), so a key with no permissions could call any route with any method. array() grants nothing; only an
        // explicit '*' is a wildcard.
        $perm = $key['permissions'] ?? null;
        if (!is_array($perm)) {
            return $no('policy_invalid');
        }
        $routes = $perm['routes'] ?? null;
        $methods = $perm['methods'] ?? null;
        // 0.4.5 RC2 (contract v1): environments is required too (missing or null is policy_invalid; RC1 read it as
        // array()). array('*') is any environment. A restricted list denies a request whose environment is omitted or not
        // listed (RC1 skipped the check when the request had no environment). array() grants no environment
        // (contract 1.1 section 5; RC2 read it as any).
        $envs = $perm['environments'] ?? null;
        if (!tokenlock_sv_str_list($routes) || !tokenlock_sv_str_list($methods) || !tokenlock_sv_str_list($envs)) {
            return $no('policy_invalid');
        }
        $renv = isset($resource['environment']) ? (string) $resource['environment'] : '';
        // 0.4.5 RC3 (contract 1.1, U1): an empty environments list grants no environment (RC2 read [] as any).
        if (!in_array('*', $envs, true) && !($renv !== '' && in_array($renv, $envs, true))) {
            return $no('environment_not_allowed');
        }
        if (isset($resource['path']) && $resource['path'] !== '') {
            $p = tokenlock_canonical_path($resource['path']);
            if ($p === null) {
                return $no('bad_path');
            }
            $hit = false;
            foreach ($routes as $x) {
                if (tokenlock_sv_route_matches($x, $p)) {
                    $hit = true;
                    break;
                }
            }
            if (!$hit) {
                return $no('route_not_allowed');
            }
        }
        if (!empty($resource['method']) && !in_array('*', $methods, true) && !in_array(strtoupper($resource['method']), $methods, true)) {
            return $no('method_not_allowed');
        }
    }
    return array('allowed' => true, 'reason' => 'ok', 'key' => $key);
}

// ------------------------------------------------------------------ sign-in + local pass (spec §6)
function tokenlock_sv_reasons()
{
    return array(
        'ok' => 'Signed in.', 'bad_pass' => 'Not a valid pass.', 'bad_name' => 'Names are 4–12 letters A–Z and do not start with A.', 'wrong_site' => 'This pass was issued for another site.', 'bad_site' => '`site` must be your origin, e.g. https://shop.example.', 'route_not_allowed' => 'This key is not allowed on this route.', 'method_not_allowed' => 'This key is not allowed to use this method here.',
        'environment_not_allowed' => 'This key is not allowed in this environment.', 'bad_path' => 'Not a valid path.', 'unknown_challenge' => 'This sign-in request is unknown or was already used. Start again.',
        'expired' => 'This sign-in request expired. Start again.', 'bad_signature' => 'The signature does not match this address and message.', 'bad_address' => 'Not a Bitcoin address we support.',
        'not_holder' => 'This wallet does not hold the token.', 'lookup_failed' => 'Could not read holdings right now. Try again in a minute.', 'lookup_disagreement' => 'Holdings sources disagree. Try again in a minute.',
        'name_required' => 'Give the name you hold.', 'not_registered' => 'This wallet is not a registered key for this site.', 'key_revoked' => 'This key was revoked.', 'key_expired' => 'This key has expired.',
        'pending_approval' => 'Waiting for the site admin to approve this wallet.', 'org_not_approved' => 'The organization for this key is not approved.',
        'org_required' => 'This site requires keys to belong to an organization.', 'entitlement_revoked' => 'This token no longer unlocks this site.',
        'policy_expired' => 'Access policy is out of date. Try again in a minute.', 'policy_invalid' => 'Access policy is malformed, so access is denied. Fix the policy.', 'policy_unavailable' => 'Access policy is unavailable. Try again in a minute.',
        'bad_resource' => "Malformed authorization request: pass a valid array('path' => ..., 'method' => ...) or 'identity_only' => true.",
        'bad_secret' => "'pass_secret' must be a string of at least 32 characters.", 'bad_input' => 'Malformed input: held must be a list of asset names.',
        'policy_required' => "No route policy applies: a resource (path, method or environment) was given but there is no policy, or the policy has no route rules (token mode), so it cannot be explicitly permitted. Use a registered-keys policy that grants the route, or, for an identity-only check, pass 'identity_only' => true instead of a resource.",
    );
}

function tokenlock_sv_policy_get($src)
{
    try {
        return array(call_user_func($src), null);
    } catch (Throwable $e) {
        return array(null, ($e instanceof TokenlockSelfVerifyError && in_array($e->tlcode, array('policy_expired', 'policy_invalid'), true)) ? $e->tlcode : 'policy_unavailable');
    }
}

/**
 * Verify a sign-in with no call to our API (except the providers/policy you chose). Fails closed on any lookup error.
 * $cfg: store, holdings (provider callable), pass_secret (32+ chars), optional policy (source callable), clock_skew_seconds.
 */
function tokenlock_sv_verify_sign_in($input, $cfg, $now = null)
{
    $now = $now ?? tokenlock_sv_now();
    $cid = (string) ($input['challenge_id'] ?? '');
    $R = tokenlock_sv_reasons();
    $out = function ($code, $extra = array()) use ($cid, $R) {
        return array_merge(array('valid' => $code === 'ok', 'code' => $code, 'reason' => $R[$code] ?? $code, 'correlation_id' => $cid), $extra);
    };
    if (!preg_match('/^[0-9a-f]{32}$/', $cid)) {
        return $out('unknown_challenge');
    }
    $rec = call_user_func($cfg['store']['take'], $cid); // single use: taken even if what follows fails
    if (!$rec) {
        return $out('unknown_challenge');
    }
    if ($now > tokenlock_sv_ms($rec['expires_at']) + (int) ($cfg['clock_skew_seconds'] ?? 0) * 1000) {
        return $out('expired');
    }
    $address = trim((string) ($input['address'] ?? ''));
    if (!tokenlock_decode_address($address)) {
        return $out('bad_address');
    }
    if (!tokenlock_verify_message_signature($address, tokenlock_sv_build_message($rec), (string) ($input['signature'] ?? ''))) {
        return $out('bad_signature', array('address' => $address));
    }
    $policy = null;
    if (!empty($cfg['policy'])) {
        list($policy, $err) = tokenlock_sv_policy_get($cfg['policy']);
        if ($err) {
            return $out($err, array('address' => $address));
        }
    }
    $want = $rec['assets'];
    // 0.5.0 RC6 (S1, option A): "any name on Bitcoin" means a registered name (4-12 letters A-Z, not starting with A) that
    // this address OWNS, as on hosted sign-in. RC5 accepted any asset name (numeric A... assets included) with any positive
    // balance. A name that is not a registered name answers bad_name, like hosted.
    $anyName = null;
    if (!empty($rec['any_name'])) {
        $raw = $input['name'] ?? null;
        if ($raw === null || $raw === '') {
            if (!$want) {
                return $out('name_required', array('address' => $address));
            }
        } else {
            $n = is_string($raw) ? strtoupper(trim($raw, " \t\n\r\x0B")) : '';
            if (!preg_match('/^[B-Z][A-Z]{3,11}$/', $n)) {
                return $out('bad_name', array('address' => $address));
            }
            $anyName = $n;
            if (!in_array($n, $want, true)) {
                $want[] = $n;
            }
        }
    }
    try {
        $h = call_user_func($cfg['holdings'], $address, $want);
    } catch (Throwable $e) {
        return $out(($e instanceof TokenlockSelfVerifyError && $e->tlcode === 'lookup_disagreement') ? 'lookup_disagreement' : 'lookup_failed', array('address' => $address));
    }
    // The site's listed assets count with any positive balance; the "any name" only when owned.
    $held = array_values(array_filter($want, function ($a) use ($h, $rec, $anyName) {
        if (!(is_array($h) && isset($h[$a]) && is_array($h[$a]) && ($h[$a]['held'] ?? null) === true)) {
            return false;
        }
        return in_array($a, $rec['assets'], true) || ($a === $anyName && ($h[$a]['how'] ?? null) === 'owner');
    }));
    if (!$held) {
        return $out('not_holder', array('address' => $address, 'assets_held' => array()));
    }
    $keyId = null;
    $ttl = (int) $rec['pass_ttl_s'];
    if ($policy) {
        $ev = tokenlock_sv_evaluate($policy, $address, $held, array('identity_only' => true), $now);
        if (!$ev['allowed']) {
            return $out($ev['reason'], array('address' => $address, 'assets_held' => $held));
        }
        if (!empty($ev['key'])) {
            $k = $ev['key'];
            $keyId = $k['id'] ?? null;
            $kt = !empty($k['pass_ttl_s']) ? $k['pass_ttl_s'] : ((($k['owner_type'] ?? '') === 'agent') ? ($policy['settings']['agent_pass_ttl_s'] ?? null) : ($policy['settings']['default_pass_ttl_s'] ?? null));
            if ($kt) {
                $ttl = min($ttl, (int) $kt);
            }
            if (!empty($k['expires_at'])) {
                $ttl = min($ttl, max(60, intdiv(tokenlock_sv_ms($k['expires_at']) - $now, 1000)));
            }
        }
    }
    $exp = $now + $ttl * 1000;
    $pass = tokenlock_sv_issue_pass(array('sub' => $address, 'h' => $held, 'k' => $keyId, 'n' => $cid, 's' => $rec['site'], 'i' => $now, 'e' => $exp), $cfg['pass_secret']);
    return $out('ok', array('address' => $address, 'assets_held' => $held, 'pass' => $pass, 'expires_at' => tokenlock_sv_iso($exp), 'key_id' => $keyId));
}

/** Local pass: tl3.<base64url(json)>.<base64url(hmac-sha256)>, keyed by YOUR secret (never ours). */
function tokenlock_sv_issue_pass($p, $secret)
{
    if (!is_string($secret) || strlen($secret) < 32) {
        tokenlock_sv_fail('bad_secret', '`pass_secret` must be at least 32 characters.', 500);
    }
    $body = tokenlock_sv_b64url(tokenlock_sv_json(array_merge(array('v' => 1), $p)));
    return 'tl3.' . $body . '.' . tokenlock_sv_b64url(hash_hmac('sha256', 'tl3.' . $body, $secret, true));
}

/** Check a local pass. valid = authentic, unexpired, access still granted; allowed = also covers $resource. */
function tokenlock_sv_verify_local_pass($token, $o)
{
    $R = tokenlock_sv_reasons();
    // valid => true with allowed => false is only answered AFTER the pass was verified and a route/method/environment rule
    // said no. 0.4.3 also listed bad_path, which is checked before the pass: a garbage token with a malformed path answered
    // valid => true (found by the 0.4.4 widened audit).
    $scope = array('route_not_allowed', 'method_not_allowed', 'environment_not_allowed');
    $no = function ($code, $extra = array()) use ($R, $scope) {
        return array_merge(array('valid' => in_array($code, $scope, true), 'allowed' => false, 'code' => $code, 'reason' => $R[$code] ?? $code), $extra);
    };
    $early = function ($code) use ($R) { // before the pass is verified: never valid
        return array('valid' => false, 'allowed' => false, 'code' => $code, 'reason' => $R[$code] ?? $code);
    };
    // 0.4.3: the authorization request is explicit: 'identity_only' => true (no resource), or a resource that passes the
    // shared schema. No resource, an unknown option or a malformed resource is refused (never an identity-only check).
    if (!is_array($o)) {
        return $early('bad_resource');
    }
    foreach (array_keys($o) as $k) {
        if (!in_array($k, array('pass_secret', 'policy', 'resource', 'identity_only', 'now', 'site'), true)) {
            return $early('bad_resource');
        }
    }
    // 0.4.4: the HMAC key is checked like tokenlock_sv_issue_pass() checks it. 0.4.3 cast whatever it got to a string, so a
    // missing or empty pass_secret verified passes anyone can forge with an empty key.
    if (!isset($o['pass_secret']) || !is_string($o['pass_secret']) || strlen($o['pass_secret']) < 32) {
        return $early('bad_secret');
    }
    // 0.5.0 RC6: 'site' (your origin, as given to tokenlock_sv_create_challenge) binds the check to this site: a pass issued
    // for another site (possible only when both share a pass_secret) answers wrong_site and is never valid. Optional for
    // compatibility; use one pass_secret per site.
    $site = null;
    if (array_key_exists('site', $o)) {
        $site = tokenlock_sv_site_origin($o['site']);
        if ($site === null) {
            return $early('bad_site');
        }
    }
    if (array_key_exists('identity_only', $o)) {
        if ($o['identity_only'] !== true || array_key_exists('resource', $o)) {
            return $early('bad_resource');
        }
        $req = null;
    } else {
        list($req, $rerr) = tokenlock_validate_resource(array_key_exists('resource', $o) ? $o['resource'] : null);
        if ($rerr !== null || $req === null) {
            return $early($rerr === 'bad_path' ? 'bad_path' : 'bad_resource');
        }
    }
    if (!preg_match('/^tl3\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{43})$/', (string) $token, $m)) {
        return $early('bad_pass');
    }
    $want = hash_hmac('sha256', 'tl3.' . $m[1], $o['pass_secret'], true);
    $got = tokenlock_sv_b64url_decode($m[2]);
    if ($got === null || !hash_equals($want, $got)) {
        return $early('bad_pass');
    }
    $p = json_decode((string) tokenlock_sv_b64url_decode($m[1]), true);
    if (!is_array($p)) {
        return $early('bad_pass');
    }
    if ($site !== null && ($p['s'] ?? null) !== $site) {
        return $early('wrong_site');
    }
    $now = $o['now'] ?? tokenlock_sv_now();
    if (!is_int($now) && !is_float($now)) {
        return $early('bad_input');
    }
    if (!isset($p['e']) || !($p['e'] > $now)) {
        return $early('expired');
    }
    $base = array('address' => $p['sub'] ?? null, 'assets_held' => $p['h'] ?? array(), 'expires_at' => tokenlock_sv_iso($p['e']), 'key_id' => $p['k'] ?? null);
    $hasResource = $req !== null;
    $policyRequired = function ($identityValid) use ($base, $R) {
        return array_merge(array('valid' => false, 'allowed' => false, 'identity_valid' => $identityValid, 'code' => 'policy_required', 'reason' => $R['policy_required']), $base);
    };
    if (empty($o['policy']) && $hasResource) {
        // 0.3.0 answered allowed => true here although no route, method or environment rule was checked (advisory 2026-11-18).
        return $policyRequired(true);
    }
    if (!empty($o['policy'])) {
        list($pol, $err) = tokenlock_sv_policy_get($o['policy']);
        if ($err) {
            return $no($err, $base);
        }
        // tokenlock_sv_evaluate() checks the policy's shape and validity window against $now first (0.4.4), then the mode:
        // a token-mode policy has no route rules, so a resource is policy_required (0.4.0).
        $ID = array('identity_only' => true);
        $ev = tokenlock_sv_evaluate($pol, $p['sub'] ?? '', $p['h'] ?? array(), $hasResource ? $req : $ID, $now);
        if ($ev['reason'] === 'policy_required') {
            $idv = tokenlock_sv_evaluate($pol, $p['sub'] ?? '', $p['h'] ?? array(), $ID, $now);
            return $policyRequired(!empty($idv['allowed']));
        }
        if (!$ev['allowed']) {
            return $no($ev['reason'], $base);
        }
        if (($pol['mode'] ?? '') === 'registered_keys' && (($ev['key']['id'] ?? null) !== ($p['k'] ?? null))) {
            return $no('not_registered', $base); // pass bound to its key
        }
    }
    return array_merge(array('valid' => true, 'allowed' => true, 'code' => 'ok', 'reason' => 'Allowed.'), $base);
}
