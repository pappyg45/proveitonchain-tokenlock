<?php
/**
 * 0.4.4 widened audit (PHP): enumerate EVERY function the package defines (get_defined_functions after loading
 * tokenlock.php, self-verify.php, btcsig.php via tokenlock.php, and early.php in manual mode) and fuzz each one.
 * Decision functions: a known-good baseline must allow; every malformed / expired / not-yet-valid / partial mutation
 * must deny. Output/exit functions are listed with a reason (exercised by the HTTP suites). Everything else is called
 * with a garbage corpus in every parameter position: an allow-shaped answer is a finding.
 * Run: php test/fuzz-exports.php [report.json]   (no network: stub API handler; throwaway secrets only)
 */
error_reporting(E_ALL);
define('TOKENLOCK_EARLY_MANUAL', true);
$before = get_defined_functions()['user'];
require_once dirname(__DIR__) . '/tokenlock/tokenlock.php';
require_once dirname(__DIR__) . '/tokenlock/self-verify.php';
require_once dirname(__DIR__) . '/tokenlock/early.php';
$FUNCS = array_values(array_diff(get_defined_functions()['user'], $before));
$FX = is_file(__DIR__ . '/fixtures/signin-vectors.json') && is_file(__DIR__ . '/fixtures/policy-bundle.json') ? __DIR__ . '/fixtures/' : dirname(__DIR__, 2) . '/test/fixtures/';
$SI = json_decode(file_get_contents($FX . 'signin-vectors.json'), true);
$PB = json_decode(file_get_contents($FX . 'policy-bundle.json'), true);

$findings = array(); $report = array();
function allow_shaped($v) { return is_array($v) && ((($v['allowed'] ?? null) === true) || (($v['valid'] ?? null) === true)); }
function run($f) { try { return array('v' => $f(), 'e' => null); } catch (Throwable $e) { return array('v' => null, 'e' => $e); } }
function decision($name, $base, $muts, $allow = 'allow_shaped')
{
    global $findings, $report;
    $r = array('kind' => 'decision', 'mutations' => count($muts), 'denied' => 0, 'findings' => array());
    $b = run($base);
    $r['baseline'] = $b['e'] ? 'THREW ' . get_class($b['e']) . ': ' . $b['e']->getMessage() : ($allow($b['v']) ? 'allowed' : 'DENIED ' . substr(json_encode($b['v']), 0, 160));
    if ($r['baseline'] !== 'allowed') { $findings[] = "$name: baseline not allowed (harness): {$r['baseline']}"; }
    foreach ($muts as $label => $f) {
        $o = run($f);
        if (!$o['e'] && $allow($o['v'])) { $r['findings'][] = $label; $findings[] = "$name: $label: ALLOWED " . substr(json_encode($o['v']), 0, 180); }
        else { $r['denied']++; }
    }
    $report[$name] = $r;
}

// ------------------------------------------------------------------ corpora
$GOOD = array('path' => '/app/x', 'method' => 'GET', 'environment' => 'production');
class FuzzRes { public $path = '/app/x'; public $method = 'GET'; }
$MAL = array(
    'resource null' => null, 'misspelled pth' => array('pth' => '/app/x', 'method' => 'GET'), 'method only' => array('method' => 'GET'), 'environment only' => array('environment' => 'production'),
    'path only' => array('path' => '/app/x'), 'path array' => array('path' => array('/app/x'), 'method' => 'GET'), 'path int' => array('path' => 5, 'method' => 'GET'), 'method array' => array('path' => '/app/x', 'method' => array('GET')),
    'method over-long' => array('path' => '/app/x', 'method' => 'GETXXXXXXXXXXX'), 'method with space' => array('path' => '/app/x', 'method' => 'GET '), 'empty method' => array('path' => '/app/x', 'method' => ''),
    'empty path' => array('path' => '', 'method' => 'GET'), 'relative path' => array('path' => 'app/x', 'method' => 'GET'), 'traversal' => array('path' => '/app/../admin', 'method' => 'GET'),
    'encoded dot' => array('path' => '/app/%2e%2e/admin', 'method' => 'GET'), 'encoded slash' => array('path' => '/app%2fx', 'method' => 'GET'), 'backslash' => array('path' => '/app\\x', 'method' => 'GET'),
    'NUL' => array('path' => "/app/\0", 'method' => 'GET'), 'semicolon' => array('path' => '/app/x;a', 'method' => 'GET'), 'over-long path' => array('path' => '/app/' . str_repeat('a', 3000), 'method' => 'GET'),
    'padded environment' => array('path' => '/app/x', 'method' => 'GET', 'environment' => ' production '), 'environment array' => array('path' => '/app/x', 'method' => 'GET', 'environment' => array('production')),
    'unknown field' => array('path' => '/app/x', 'method' => 'GET', 'route' => '/admin'), 'string resource' => 'path=/app/x', 'list resource' => array('/app/x', 'GET'), 'int resource' => 7, 'true resource' => true,
    'object resource' => new FuzzRes(), 'identity_only mixed with path' => array('path' => '/app/x', 'method' => 'GET', 'identity_only' => true), 'identity_only string' => array('identity_only' => 'true'),
    'identity_only false' => array('identity_only' => false),
);
mt_srand(0x044);
$chars = array('/', 'a', '.', '%', '2', 'e', 'f', '\\', ';', '?', '#', "\0", ' ', 'Z', '-', '~');
for ($i = 0; $i < 150; $i++) {
    $p = ''; $n = mt_rand(1, 14); for ($j = 0; $j < $n; $j++) { $p .= $chars[mt_rand(0, count($chars) - 1)]; }
    if (tokenlock_canonical_path($p) === null || strpos(tokenlock_canonical_path($p), '/app/') !== 0) { $MAL["random path #$i " . json_encode($p)] = array('path' => $p, 'method' => 'GET', 'environment' => 'production'); }
}
$S = str_repeat('x', 40);
$A = 'bc1qfuzz00000000000000000000000000000000';
$now = (int) floor(microtime(true) * 1000);
$iso = function ($ms) { return tokenlock_sv_iso($ms); };
$pol = function ($o, $t = null) use ($now, $iso) { $t = $t ?? $now; return array_merge(array('v' => 1, 'typ' => 'tokenlock.policy', 'site_id' => 'local', 'seq' => 1, 'issued_at' => $iso($t - 60000), 'expires_at' => $iso($t + 3600000), 'orgs' => array(), 'revoked_assets' => array(), 'keys' => array()), $o); };
$KEY = array('id' => 'k1', 'address' => $A, 'status' => 'active', 'permissions' => array('routes' => array('/app/*'), 'methods' => array('GET'), 'environments' => array('production')));
$REG = $pol(array('mode' => 'registered_keys', 'keys' => array($KEY)));
$TOK = $pol(array('mode' => 'token', 'assets' => array('GOTPROOF')));
$TIME_BAD = function ($t) use ($iso) { return array(
    'policy expired (2020)' => array('issued_at' => '2019-12-01T00:00:00.000Z', 'expires_at' => '2020-01-15T00:00:00.000Z'),
    'policy expired 1 s ago' => array('issued_at' => $iso($t - 3600000), 'expires_at' => $iso($t - 1000)),
    'policy issued tomorrow (not yet valid)' => array('issued_at' => $iso($t + 86400000), 'expires_at' => $iso($t + 2 * 86400000)),
    'policy missing expires_at' => array('expires_at' => null),
); };
$pass = function ($k = 'k1', $h = array('GOTPROOF'), $secret = null, $e = null) use ($A, $S, $now) {
    $secret = $secret ?? $S; $e = $e ?? $now + 3600000;
    $body = tokenlock_sv_b64url(tokenlock_sv_json(array('v' => 1, 'sub' => $A, 'h' => $h, 'k' => $k, 'n' => 'n1', 's' => 'https://shop.example', 'i' => $now, 'e' => $e)));
    return 'tl3.' . $body . '.' . tokenlock_sv_b64url(hash_hmac('sha256', 'tl3.' . $body, $secret, true)); // forged directly so empty/short keys can be tried
};
$GENERIC = array(null, '', 'x', 0, -1, NAN, INF, true, false, array(), array(null), array('allowed' => true, 'valid' => true), array('path' => '/admin', 'method' => 'GET'), str_repeat('a', 5000), new stdClass(), function () { return array('allowed' => true); }, "\0", '../../etc/passwd');

$H = array();
$H['tokenlock_sv_evaluate'] = function () use ($REG, $TOK, $A, $GOOD, $MAL, $TIME_BAD, $now, $pol, $KEY) {
    $ev = function ($p, $res, $held = array('GOTPROOF'), $addr = null) use ($A) { return tokenlock_sv_evaluate($p, $addr ?? $A, $held, $res); };
    $m = array();
    foreach ($MAL as $k => $v) { $m["resource $k"] = function () use ($ev, $REG, $v) { return $ev($REG, $v); }; }
    $m['resource omitted (identity implied)'] = function () use ($REG, $A) { return tokenlock_sv_evaluate($REG, $A, array('GOTPROOF')); };
    foreach (array('held null' => null, 'held string' => 'GOTPROOF', 'held [1]' => array(1), 'held empty' => array()) as $k => $h) { $m[$k] = function () use ($ev, $REG, $GOOD, $h) { return $ev($REG, $GOOD, $h); }; }
    foreach ($TIME_BAD($now) as $k => $t) {
        $m["$k (registered, resource)"] = function () use ($ev, $REG, $GOOD, $t) { return $ev(array_merge($REG, $t), $GOOD); };
        $m["$k (token, identity)"] = function () use ($ev, $TOK, $t) { return $ev(array_merge($TOK, $t), array('identity_only' => true)); };
    }
    $m['token mode, valid resource'] = function () use ($ev, $TOK, $GOOD) { return $ev($TOK, $GOOD); };
    foreach (array_slice($MAL, 1, 25, true) as $k => $v) { $m["token mode resource $k"] = function () use ($ev, $TOK, $v) { return $ev($TOK, $v); }; }
    $m['other address'] = function () use ($ev, $REG, $GOOD) { return $ev($REG, $GOOD, array('GOTPROOF'), 'bc1qother'); };
    $m['key revoked'] = function () use ($ev, $pol, $KEY, $GOOD) { return $ev($pol(array('mode' => 'registered_keys', 'keys' => array(array_merge($KEY, array('status' => 'revoked'))))), $GOOD); };
    $m['key expired'] = function () use ($ev, $pol, $KEY, $GOOD, $now) { return $ev($pol(array('mode' => 'registered_keys', 'keys' => array(array_merge($KEY, array('expires_at' => tokenlock_sv_iso($now - 1000)))))), $GOOD); };
    $m['route not granted'] = function () use ($ev, $REG, $GOOD) { return $ev($REG, array_merge($GOOD, array('path' => '/admin'))); };
    $m['policy not an array'] = function () use ($ev, $GOOD) { return $ev('x', $GOOD); };
    decision('tokenlock_sv_evaluate', function () use ($ev, $REG, $GOOD) { return $ev($REG, $GOOD); }, $m);
};
$H['tokenlock_sv_verify_local_pass'] = function () use ($REG, $TOK, $S, $GOOD, $MAL, $TIME_BAD, $now, $pass) {
    $v = function ($tok, $o) use ($S) { return tokenlock_sv_verify_local_pass($tok, $o + array('pass_secret' => $S)); };
    $LP = tokenlock_sv_local_policy($REG);
    $m = array();
    foreach ($MAL as $k => $r) { $m["resource $k"] = function () use ($v, $pass, $LP, $r) { return $v($pass(), array('policy' => $LP, 'resource' => $r)); }; }
    foreach ($TIME_BAD($now) as $k => $t) {
        $m["$k, resource"] = function () use ($v, $pass, $REG, $GOOD, $t) { return $v($pass(), array('policy' => tokenlock_sv_local_policy(array_merge($REG, $t)), 'resource' => $GOOD)); };
        $m["$k, identity"] = function () use ($v, $pass, $REG, $t) { return $v($pass(), array('policy' => tokenlock_sv_local_policy(array_merge($REG, $t)), 'identity_only' => true)); };
        $m["$k, token mode identity"] = function () use ($v, $pass, $TOK, $t) { return $v($pass(null), array('policy' => tokenlock_sv_local_policy(array_merge($TOK, $t)), 'identity_only' => true)); };
        $m["$k, custom source"] = function () use ($v, $pass, $REG, $GOOD, $t) { return $v($pass(), array('policy' => function () use ($REG, $t) { return array_merge($REG, $t); }, 'resource' => $GOOD)); };
    }
    foreach (array('""' => '', '"short"' => 'short') as $k => $sec) {
        $m["pass_secret $k + pass forged with that key"] = function () use ($pass, $sec, $LP, $GOOD) { return tokenlock_sv_verify_local_pass($pass('k1', array('GOTPROOF'), $sec), array('pass_secret' => $sec, 'policy' => $LP, 'resource' => $GOOD)); };
    }
    $m['pass_secret missing + pass forged with ""'] = function () use ($pass, $LP, $GOOD) { return tokenlock_sv_verify_local_pass($pass('k1', array('GOTPROOF'), ''), array('policy' => $LP, 'resource' => $GOOD)); };
    $m['pass_secret null + pass forged with ""'] = function () use ($pass, $LP, $GOOD) { return tokenlock_sv_verify_local_pass($pass('k1', array('GOTPROOF'), ''), array('pass_secret' => null, 'policy' => $LP, 'resource' => $GOOD)); };
    foreach (array('/a/../admin', 'admin', '/%2e%2e/x', '/a%2fb') as $p) { $m["garbage token + path $p"] = function () use ($v, $LP, $p) { return $v('garbage', array('policy' => $LP, 'resource' => array('path' => $p, 'method' => 'GET'))); }; }
    $m['expired pass'] = function () use ($v, $pass, $LP, $GOOD, $now) { return $v($pass('k1', array('GOTPROOF'), null, $now - 1000), array('policy' => $LP, 'resource' => $GOOD)); };
    $m['pass for another key'] = function () use ($v, $pass, $LP, $GOOD) { return $v($pass('k9'), array('policy' => $LP, 'resource' => $GOOD)); };
    $m['tampered pass'] = function () use ($v, $pass, $LP, $GOOD) { $t = $pass(); return $v(substr($t, 0, -3) . 'AAA', array('policy' => $LP, 'resource' => $GOOD)); };
    $m['token policy + resource'] = function () use ($v, $pass, $TOK, $GOOD) { return $v($pass(null), array('policy' => tokenlock_sv_local_policy($TOK), 'resource' => $GOOD)); };
    $m['no policy + resource'] = function () use ($v, $pass, $GOOD) { return $v($pass(null), array('resource' => $GOOD)); };
    $m['unknown option'] = function () use ($v, $pass, $LP, $GOOD) { return $v($pass(), array('policy' => $LP, 'resource' => $GOOD, 'skip' => true)); };
    $m['options not an array'] = function () use ($pass) { return tokenlock_sv_verify_local_pass($pass(), 'x'); };
    decision('tokenlock_sv_verify_local_pass', function () use ($v, $pass, $LP, $GOOD) { return $v($pass(), array('policy' => $LP, 'resource' => $GOOD)); }, $m);
};
$H['tokenlock_sv_local_policy'] = function () use ($REG, $TIME_BAD, $now) {
    $ok = function ($x) { return is_array($x) && isset($x['mode']); };
    $m = array();
    foreach ($TIME_BAD($now) as $k => $t) { $m[$k] = function () use ($REG, $t) { return call_user_func(tokenlock_sv_local_policy(array_merge($REG, $t))); }; }
    $m['callable returning expired'] = function () use ($REG) { return call_user_func(tokenlock_sv_local_policy(function () use ($REG) { return array_merge($REG, array('expires_at' => '2020-01-15T00:00:00.000Z', 'issued_at' => '2019-12-01T00:00:00.000Z')); })); };
    $m['not an array'] = function () { return call_user_func(tokenlock_sv_local_policy('x')); };
    decision('tokenlock_sv_local_policy', function () use ($REG) { return call_user_func(tokenlock_sv_local_policy($REG)); }, $m, $ok);
};
$H['tokenlock_sv_verify_sign_in'] = function () use ($SI, $TIME_BAD, $pol) {
    $t = $SI['now'] + 1000; $A0 = $SI['signers'][0]['address'];
    $run = function ($policy, $extra = array(), $secret = null) use ($SI, $t, $A0) {
        $store = tokenlock_sv_memory_store(); call_user_func($store['put'], $SI['record']['nonce'], $SI['record'], $SI['now'] + 600000);
        $cfg = array('store' => $store, 'holdings' => tokenlock_sv_static_provider(array($A0 => array('GOTPROOF'))), 'pass_secret' => $secret ?? $SI['pass_secret']);
        if ($policy !== null) { $cfg['policy'] = $policy; }
        return tokenlock_sv_verify_sign_in(array_merge(array('challenge_id' => $SI['record']['nonce'], 'address' => $A0, 'signature' => $SI['signers'][0]['signature']), $extra), $cfg, $t);
    };
    $TP = $pol(array('mode' => 'token', 'assets' => array('GOTPROOF')), $SI['now']);
    $m = array();
    foreach ($TIME_BAD($SI['now']) as $k => $tb) { $m["$k (custom source)"] = function () use ($run, $TP, $tb) { return $run(function () use ($TP, $tb) { return array_merge($TP, $tb); }); }; }
    $m['wrong address'] = function () use ($run, $SI) { return $run(null, array('address' => $SI['signers'][1]['address'])); };
    $m['bad signature'] = function () use ($run) { return $run(null, array('signature' => base64_encode(str_repeat("\1", 65)))); };
    $m['unknown challenge'] = function () use ($run) { return $run(null, array('challenge_id' => str_repeat('f', 32))); };
    decision('tokenlock_sv_verify_sign_in', function () use ($run, $TP) { return $run(function () use ($TP) { return $TP; }); }, $m);
};
$H['tokenlock_sv_verify_policy_bundle'] = function () use ($PB) {
    $ok = function ($x) { return is_array($x) && isset($x['mode']); };
    $o = array('public_keys' => array($PB['kid'] => $PB['public_key']), 'site_id' => 'site_fixture', 'now' => $PB['now'] + 1000);
    $vb = function ($b, $x = array()) use ($o) { return tokenlock_sv_verify_policy_bundle($b, $x + $o); };
    decision('tokenlock_sv_verify_policy_bundle', function () use ($vb, $PB) { return $vb($PB['bundle']); }, array(
        'expired (now a year later)' => function () use ($vb, $PB) { return $vb($PB['bundle'], array('now' => $PB['now'] + 365 * 86400000)); },
        'not yet valid (now a year earlier)' => function () use ($vb, $PB) { return $vb($PB['bundle'], array('now' => $PB['now'] - 365 * 86400000)); },
        'other site' => function () use ($vb, $PB) { return $vb($PB['bundle'], array('site_id' => 'other')); },
        'unpinned key' => function () use ($vb, $PB) { return $vb($PB['bundle'], array('public_keys' => array(str_repeat('00', 32)))); },
        'tampered sig' => function () use ($vb, $PB) { $b = $PB['bundle']; $b['sig'] = str_repeat('0', 128); return $vb($b); },
        'rollback' => function () use ($vb, $PB) { return $vb($PB['bundle'], array('min_seq' => PHP_INT_MAX)); },
        'stale' => function () use ($vb, $PB) { return $vb($PB['bundle'], array('max_age_seconds' => 1, 'now' => $PB['now'] + 100000)); },
    ), $ok);
};
$H['tokenlock_sv_signed_policy'] = function () use ($PB) {
    global $findings, $report;
    // the fixture bundle is fixed in the past and signed_policy() uses the real clock: it must be refused (no baseline possible without the signing key)
    $dir = sys_get_temp_dir() . '/tlfuzz' . getmypid(); @mkdir($dir);
    $src = tokenlock_sv_signed_policy(array('site_id' => 'site_fixture', 'secret_key' => 'sk_x', 'public_keys' => array($PB['kid'] => $PB['public_key']), 'cache_dir' => $dir, 'load' => function () use ($PB) { return $PB['bundle']; }));
    $o = run($src); if (!$o['e']) { $findings[] = 'tokenlock_sv_signed_policy: expired fixture bundle accepted by the real clock'; }
    $report['tokenlock_sv_signed_policy'] = array('kind' => 'mutation-only', 'note' => 'expired-by-clock fixture must throw', 'threw' => (bool) $o['e']);
    array_map('unlink', glob("$dir/*") ?: array()); @rmdir($dir);
};
$H['tokenlock_validate_resource'] = function () use ($GOOD, $MAL) {
    $m = array(); foreach ($MAL as $k => $v) { $m[$k] = function () use ($v) { return tokenlock_validate_resource($v); }; }
    decision('tokenlock_validate_resource', function () use ($GOOD) { return tokenlock_validate_resource($GOOD); }, $m, function ($x) { return is_array($x) && is_array($x[0] ?? null) && array_key_exists(1, $x) && $x[1] === null; });
};
foreach (array('tokenlock_canonical_path', 'tokenlock_resource_path') as $fn) {
    $H[$fn] = function () use ($fn, $MAL) {
        $m = array(); foreach ($MAL as $k => $v) { if (is_array($v) && isset($v['path']) && is_string($v['path']) && !in_array($k, array('path only', 'unknown field', 'padded environment', 'environment array', 'identity_only mixed with path', 'method only', 'method array', 'method over-long', 'method with space', 'empty method'), true)) { $p = $v['path']; $m[$k] = function () use ($fn, $p) { $c = $fn($p); return array('ok' => $c !== null && strpos(strtolower($c), '/app/') === 0 && strpos($c, '..') === false); }; } }
        decision($fn, function () use ($fn) { return array('ok' => $fn('/app/x') === '/app/x'); }, $m, function ($x) { return ($x['ok'] ?? false) === true; });
    };
}
$H['tokenlock_verify_pass'] = function () use ($GOOD, $MAL) {
    // permissive stub API: answers valid/allowed for anything, echoing the resource it was sent; the client must still refuse malformed requests
    tokenlock_configure(array('secret_key' => 'sk_' . str_repeat('h', 43), 'cache' => false, 'cache_dir' => sys_get_temp_dir(), 'api_base' => 'https://api.test',
        'http_handler' => function ($m, $u, $h, $b) { $j = $b ? json_decode($b, true) : array(); $res = array_intersect_key((array) $j, array('path' => 1, 'method' => 1, 'environment' => 1));
            return array('status' => 200, 'body' => json_encode(array('valid' => true, 'allowed' => true, 'address' => 'bc1qx', 'assets_held' => array('T'), 'site_id' => 's1', 'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 600),
                'access' => array('mode' => 'registered_keys', 'allowed' => true, 'reason' => 'ok', 'resource' => $res), 'resource' => $res ?: null, 'cache_max_s' => 5))); }));
    $P = 'pp1.' . str_repeat('H', 40) . '.' . str_repeat('Q', 43);
    $m = array(); foreach ($MAL as $k => $v) { if (strpos($k, 'random') === 0) { continue; } $m[$k] = function () use ($P, $v) { return tokenlock_verify_pass($P, $v); }; }
    $m['resource omitted'] = function () use ($P) { return tokenlock_verify_pass($P); };
    decision('tokenlock_verify_pass', function () use ($P, $GOOD) { return tokenlock_verify_pass($P, $GOOD); }, $m);
};

// output / exit / network / file-writing functions: not garbage-called (they send headers, exit, or touch disk); covered by the HTTP suites
$NO_GARBAGE = array('tokenlock_send_cookie', 'tokenlock_send_bad_config', 'tokenlock_send_json', 'tokenlock_handle_session', 'tokenlock_handle_signout', 'tokenlock_send_unavailable', 'tokenlock_send_forbidden',
    'tokenlock_require', 'tokenlock_protect', 'tokenlock_pass', 'tokenlock_early', 'tokenlock_early_deny', 'tokenlock_http', 'tokenlock_request', 'tokenlock_sv_http_get', 'tokenlock_sv_get', 'tokenlock_clear_cache',
    'tokenlock_cache_put', 'tokenlock_cache_prune', 'tokenlock_cache_drop', 'tokenlock_configure', 'tokenlock_assert_config', 'tokenlock_sv_file_store', 'tokenlock_sv_fail', 'tokenlock_check_request', 'tokenlock_read_body_pass');
$generic = 0;
foreach ($FUNCS as $fn) {
    if (isset($H[$fn])) { $H[$fn](); continue; }
    if (in_array($fn, $NO_GARBAGE, true)) { $report[$fn] = array('kind' => 'no-garbage', 'note' => 'output/exit/network/disk; covered by the HTTP suites (http.mjs, early.mjs, correction-043-protect.mjs, e2e.mjs)'); continue; }
    $rf = new ReflectionFunction($fn); $n = max(1, min(3, $rf->getNumberOfParameters())); $calls = 0; $f0 = array();
    for ($pos = 0; $pos < $n; $pos++) { foreach ($GENERIC as $g) {
        $args = array_fill(0, $n, null); $args[$pos] = $g; $calls++;
        $o = run(function () use ($fn, $args) { return @call_user_func_array($fn, $args); });
        if (!$o['e'] && allow_shaped($o['v']) && $o['v'] !== $g && !in_array($fn, array('tokenlock_defaults', 'tokenlock_config', 'tokenlock_sv_reasons'), true)) { $f0[] = "arg$pos=" . substr(json_encode($g), 0, 30) . ': allow-shaped ' . substr(json_encode($o['v']), 0, 80); }
    } }
    $generic += $calls; $report[$fn] = array('kind' => 'generic', 'calls' => $calls, 'findings' => $f0); foreach ($f0 as $x) { $findings[] = "$fn: $x"; }
}
$summary = array('functions' => count($FUNCS), 'decision_harnesses' => count(array_filter($report, function ($r) { return ($r['kind'] ?? '') === 'decision'; })), 'generic_calls' => $generic, 'findings' => count($findings));
echo json_encode($summary, JSON_PRETTY_PRINT), "\n"; foreach ($findings as $f) { echo "FINDING $f\n"; }
if (!empty($argv[1])) { file_put_contents($argv[1], json_encode(array('summary' => $summary, 'findings' => $findings, 'report' => $report), JSON_PRETTY_PRINT | JSON_PARTIAL_OUTPUT_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE)); }
exit($findings ? 1 : 0);
