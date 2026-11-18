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
    $t = strtotime((string) $iso);
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
    $a = trim((string) $raw);
    $dot = strpos($a, '.');
    $a = ($dot !== false && $dot > 0) ? strtoupper(substr($a, 0, $dot)) . substr($a, $dot) : strtoupper($a);
    if (preg_match('/^[B-Z][A-Z]{3,11}$/', $a) || preg_match('/^A\d{12,21}$/', $a) || preg_match('/^([B-Z][A-Z]{3,11}|A\d{12,21})\.[a-zA-Z0-9.\-_@!]{1,200}$/', $a)) {
        return $a;
    }
    tokenlock_sv_fail('bad_asset', '"' . substr((string) $raw, 0, 60) . '" is not a valid Bitcoin asset name.');
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

/** One-time challenge. Default lifetime 10 minutes (60 s to 30 min); pass lifetime default 15 min (60 s to 24 h). */
function tokenlock_sv_create_challenge($o)
{
    $u = parse_url((string) ($o['site'] ?? ''));
    if (!$u || empty($u['scheme']) || empty($u['host']) || !in_array(strtolower($u['scheme']), array('http', 'https'), true)) {
        tokenlock_sv_fail('bad_site', '`site` must be your origin, e.g. https://shop.example');
    }
    $site = strtolower($u['scheme']) . '://' . strtolower($u['host']) . (isset($u['port']) && !(($u['scheme'] === 'https' && $u['port'] == 443) || ($u['scheme'] === 'http' && $u['port'] == 80)) ? ':' . $u['port'] : '');
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
            $x = $b['holdings'][$a] ?? array();
            $out[$a] = array('held' => !empty($x['held']), 'how' => $x['how'] ?? null, 'quantity' => $x['quantity'] ?? null, 'exists' => $x['exists'] ?? null);
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

function tokenlock_sv_static_provider($map)
{
    return function ($address, $assets) use ($map) {
        $have = $map[$address] ?? array();
        $out = array();
        foreach ($assets as $a) {
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
                $seen[!empty($h[$x]['held']) ? 1 : 0] = true;
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
    return $p;
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
                $p = tokenlock_sv_verify_policy_bundle($b, array('public_keys' => $o['public_keys'], 'site_id' => $o['site_id'], 'now' => $now, 'min_seq' => $seq));
                $tmp = $file . '.' . bin2hex(random_bytes(4));
                if (@file_put_contents($tmp, tokenlock_sv_json(array('bundle' => $b, 'seq' => $p['seq'], 'fetched_at' => $now))) !== false) {
                    @chmod($tmp, 0600);
                    @rename($tmp, $file);
                }
                return $p;
            } catch (Throwable $e) {
                if ($e instanceof TokenlockSelfVerifyError && $e->tlcode === 'policy_rollback') {
                    throw $e;
                }
                if (!$cur) {
                    throw ($e instanceof TokenlockSelfVerifyError) ? $e : new TokenlockSelfVerifyError('policy_unavailable', 'Could not load the policy bundle.', 503);
                }
            }
        }
        return $cur;
    };
}

/** Your own policy (array or callable): same shape, no signature (you are the source). */
function tokenlock_sv_local_policy($get)
{
    return function () use ($get) {
        $p = is_callable($get) ? call_user_func($get) : $get;
        return array_merge(array('v' => 1, 'typ' => 'tokenlock.policy', 'site_id' => 'local', 'seq' => 0, 'issued_at' => tokenlock_sv_iso(0),
            'expires_at' => '9999-12-31T00:00:00.000Z', 'orgs' => array(), 'revoked_assets' => array(), 'keys' => array(), 'mode' => 'registered_keys'), (array) $p);
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
    if (substr($p, -1) === '/' && strlen($p) > 1) {
        $base = rtrim($p, '/');
        return $q === $base || strpos($q, $base . '/') === 0;
    }
    return $q === rtrim($p, '/') || ($p === '/' && $q === '/');
}

/** Same access rule as hosted TOKENLOCK. $held null = holdings not re-checked. */
function tokenlock_sv_evaluate($policy, $address, $held, $resource = null, $now = null)
{
    $now = $now ?? tokenlock_sv_now();
    $revoked = $policy['revoked_assets'] ?? array();
    if (($policy['mode'] ?? '') !== 'registered_keys') {
        if (is_array($held) && !array_diff($held, $revoked)) {
            return array('allowed' => false, 'reason' => $held ? 'entitlement_revoked' : 'not_holder');
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
    if (!empty($key['expires_at']) && tokenlock_sv_ms($key['expires_at']) <= $now) {
        return $no('key_expired');
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
    if (is_array($held)) {
        $ka = $key['assets'] ?? array();
        $ok = array_filter($held, function ($a) use ($revoked, $ka) {
            return !in_array($a, $revoked, true) && (!$ka || in_array($a, $ka, true));
        });
        if (!$ok) {
            return $no($held ? 'entitlement_revoked' : 'not_holder');
        }
    }
    if ($resource) {
        $perm = $key['permissions'] ?? array();
        $routes = $perm['routes'] ?? array('*');
        $methods = $perm['methods'] ?? array('*');
        $envs = $perm['environments'] ?? array();
        if (!empty($resource['environment']) && $envs && !in_array('*', $envs, true) && !in_array($resource['environment'], $envs, true)) {
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
        'ok' => 'Signed in.', 'bad_pass' => 'Not a valid pass.', 'route_not_allowed' => 'This key is not allowed on this route.', 'method_not_allowed' => 'This key is not allowed to use this method here.',
        'environment_not_allowed' => 'This key is not allowed in this environment.', 'bad_path' => 'Not a valid path.', 'unknown_challenge' => 'This sign-in request is unknown or was already used. Start again.',
        'expired' => 'This sign-in request expired. Start again.', 'bad_signature' => 'The signature does not match this address and message.', 'bad_address' => 'Not a Bitcoin address we support.',
        'not_holder' => 'This wallet does not hold the token.', 'lookup_failed' => 'Could not read holdings right now. Try again in a minute.', 'lookup_disagreement' => 'Holdings sources disagree. Try again in a minute.',
        'name_required' => 'Give the name you hold.', 'not_registered' => 'This wallet is not a registered key for this site.', 'key_revoked' => 'This key was revoked.', 'key_expired' => 'This key has expired.',
        'pending_approval' => 'Waiting for the site admin to approve this wallet.', 'org_not_approved' => 'The organization for this key is not approved.',
        'org_required' => 'This site requires keys to belong to an organization.', 'entitlement_revoked' => 'This token no longer unlocks this site.',
        'policy_expired' => 'Access policy is out of date. Try again in a minute.', 'policy_unavailable' => 'Access policy is unavailable. Try again in a minute.',
    );
}

function tokenlock_sv_policy_get($src)
{
    try {
        return array(call_user_func($src), null);
    } catch (Throwable $e) {
        return array(null, ($e instanceof TokenlockSelfVerifyError && $e->tlcode === 'policy_expired') ? 'policy_expired' : 'policy_unavailable');
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
    if (!empty($rec['any_name'])) {
        if (empty($input['name'])) {
            if (!$want) {
                return $out('name_required', array('address' => $address));
            }
        } else {
            try {
                $want[] = tokenlock_sv_normalize_asset($input['name']);
            } catch (TokenlockSelfVerifyError $e) {
                return $out('bad_asset', array('address' => $address));
            }
        }
    }
    try {
        $h = call_user_func($cfg['holdings'], $address, $want);
    } catch (Throwable $e) {
        return $out(($e instanceof TokenlockSelfVerifyError && $e->tlcode === 'lookup_disagreement') ? 'lookup_disagreement' : 'lookup_failed', array('address' => $address));
    }
    $held = array_values(array_filter($want, function ($a) use ($h) {
        return !empty($h[$a]['held']);
    }));
    if (!$held) {
        return $out('not_holder', array('address' => $address, 'assets_held' => array()));
    }
    $keyId = null;
    $ttl = (int) $rec['pass_ttl_s'];
    if ($policy) {
        $ev = tokenlock_sv_evaluate($policy, $address, $held, null, $now);
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
    $scope = array('route_not_allowed', 'method_not_allowed', 'environment_not_allowed', 'bad_path');
    $no = function ($code, $extra = array()) use ($R, $scope) {
        return array_merge(array('valid' => in_array($code, $scope, true), 'allowed' => false, 'code' => $code, 'reason' => $R[$code] ?? $code), $extra);
    };
    if (!preg_match('/^tl3\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{43})$/', (string) $token, $m)) {
        return $no('bad_pass');
    }
    $want = hash_hmac('sha256', 'tl3.' . $m[1], (string) $o['pass_secret'], true);
    $got = tokenlock_sv_b64url_decode($m[2]);
    if ($got === null || !hash_equals($want, $got)) {
        return $no('bad_pass');
    }
    $p = json_decode((string) tokenlock_sv_b64url_decode($m[1]), true);
    if (!is_array($p)) {
        return $no('bad_pass');
    }
    $now = $o['now'] ?? tokenlock_sv_now();
    if (!isset($p['e']) || !($p['e'] > $now)) {
        return $no('expired');
    }
    $base = array('address' => $p['sub'] ?? null, 'assets_held' => $p['h'] ?? array(), 'expires_at' => tokenlock_sv_iso($p['e']), 'key_id' => $p['k'] ?? null);
    if (!empty($o['policy'])) {
        list($pol, $err) = tokenlock_sv_policy_get($o['policy']);
        if ($err) {
            return $no($err, $base);
        }
        $ev = tokenlock_sv_evaluate($pol, $p['sub'] ?? '', $p['h'] ?? array(), $o['resource'] ?? null, $now);
        if (!$ev['allowed']) {
            return $no($ev['reason'], $base);
        }
        if (($pol['mode'] ?? '') === 'registered_keys' && (($ev['key']['id'] ?? null) !== ($p['k'] ?? null))) {
            return $no('not_registered', $base); // pass bound to its key
        }
    }
    return array_merge(array('valid' => true, 'allowed' => true, 'code' => 'ok', 'reason' => 'Allowed.'), $base);
}
