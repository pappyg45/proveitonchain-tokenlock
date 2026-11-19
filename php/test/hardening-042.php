<?php
/**
 * 0.4.2 security-hardening regression tests (PHP drop-in + PHP self-verify). Written BEFORE the fixes.
 * Every test asserts the 0.4.2 contract: protected pages are never served, removed or unknown options are a
 * configuration error (bad_config), and any malformed, conflicting, stale or ambiguous answer is a denial.
 * Run: php test/hardening-042.php   (needs GMP for the self-verify part). No network, throwaway keys only.
 */
error_reporting(E_ALL);
require_once dirname(__DIR__) . '/tokenlock/tokenlock.php';
require_once dirname(__DIR__) . '/tokenlock/self-verify.php';
require_once __DIR__ . '/fixtures/hardening-mock.php';

$failed = 0;
$passed = 0;
function hk($cond, $name, $detail = '')
{
    global $failed, $passed;
    if ($cond) {
        $passed++;
        echo "  ✔ $name\n";
        return;
    }
    $failed++;
    echo "  ✖ $name" . ($detail !== '' ? " — $detail" : '') . "\n";
}
/** Run tokenlock_require() in a fresh process. Returns array(served bool, output string). */
function page($case)
{
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/fixtures/require-harness.php') . ' ' . escapeshellarg(json_encode($case)) . ' 2>&1';
    $out = array();
    exec($cmd, $out);
    $text = implode("\n", $out);
    return array(strpos($text, 'PAGE-SERVED') !== false, $text);
}
$SK = 'sk_' . str_repeat('h', 43);
$PASS = 'pp1.' . str_repeat('H', 40) . '.' . str_repeat('Q', 43);
$RES = array('path' => '/members/x', 'method' => 'GET', 'environment' => 'production');
function cfg_with($over, $answer = 'registered')
{
    global $SK;
    tokenlock_configure(array_merge(array('secret_key' => $SK, 'cache' => false, 'cache_dir' => sys_get_temp_dir(), 'api_base' => 'https://api.test', 'http_handler' => hm_handler($answer)), $over));
}
/** 'config' if a bad_config TokenlockException was thrown, else the verify answer. */
function try_verify($pass, $res, $opts = array())
{
    try {
        return tokenlock_verify_pass($pass, $res, $opts);
    } catch (TokenlockException $e) {
        return $e->error_code === 'bad_config' ? 'config' : 'exception:' . $e->error_code;
    }
}

echo "(a) fail_open\n";
list($s, $o) = page(array('config' => array('fail_open' => true), 'answer' => 'down'));
hk(!$s, 'fail_open => true cannot serve a protected page while the API is down', $s ? 'SERVED: ' . substr($o, 0, 80) : '');
list($s, $o) = page(array('env' => array('TOKENLOCK_FAIL_OPEN' => '1'), 'answer' => 'down'));
hk(!$s, 'TOKENLOCK_FAIL_OPEN=1 cannot serve a protected page while the API is down', $s ? 'SERVED' : '');
foreach (array(true, false, '1', '0') as $v) {
    cfg_with(array('fail_open' => $v));
    hk(try_verify($PASS, $RES) === 'config', 'fail_open is a removed option: ' . var_export($v, true) . ' is a configuration error');
}

echo "(b) check_resource => false and strict => false\n";
list($s, $o) = page(array('config' => array('check_resource' => false), 'path' => '/private/payroll'));
hk(!$s, 'check_resource => false cannot skip the route check on a registered-keys site', $s ? 'SERVED /private/payroll' : '');
foreach (array(false, true, '0') as $v) {
    cfg_with(array('check_resource' => $v));
    hk(try_verify($PASS, $RES) === 'config', 'check_resource is a removed option: ' . var_export($v, true) . ' is a configuration error');
}
list($s, $o) = page(array('config' => array('strict' => false), 'path' => '/members/x', 'mutation' => array('malformed', 'missing resource echo')));
hk(!$s, "strict => false cannot accept an answer that never names the resource", $s ? 'SERVED' : '');
cfg_with(array('strict' => false));
hk(try_verify($PASS, $RES) === 'config', "'strict' => false is a configuration error");
cfg_with(array());
hk(try_verify($PASS, $RES, array('strict' => false)) === 'config', "tokenlock_verify_pass(…, array('strict' => false)) is a configuration error");

echo "invalid configuration\n";
$badCfgs = array(
    'missing secret key' => array('secret_key' => ''),
    'secret key is a pk_' => array('secret_key' => 'pk_' . str_repeat('a', 43)),
    'secret key too short' => array('secret_key' => 'sk_short'),
    'secret key not a string' => array('secret_key' => 12345),
    'unknown option tokenonly (typo)' => array('tokenonly' => true),
    'unknown option fail-open' => array('fail-open' => true),
    'unknown option bypass' => array('bypass' => true),
    "token_only => 'maybe'" => array('token_only' => 'maybe'),
    'token_only => array()' => array('token_only' => array()),
    "strict => 'perhaps'" => array('strict' => 'perhaps'),
    "cache => 'sometimes'" => array('cache' => 'sometimes'),
    "timeout_seconds => 'fast'" => array('timeout_seconds' => 'fast'),
    'timeout_seconds => 0' => array('timeout_seconds' => 0),
    "api_base => 'ftp://x'" => array('api_base' => 'ftp://x'),
    "api_base => 'not a url'" => array('api_base' => 'not a url'),
    'environment => array()' => array('environment' => array()),
    "early => array('protectt' => …) (typo)" => array('early' => array('protectt' => array('/members/*'))),
    "early => 'yes'" => array('early' => 'yes'),
);
foreach ($badCfgs as $name => $c) {
    cfg_with($c);
    $r = try_verify($PASS, $RES);
    hk($r === 'config', 'config error: ' . $name, 'got ' . (is_array($r) ? json_encode(array('valid' => isset($r['valid']) ? $r['valid'] : null)) : $r));
}
list($s, $o) = page(array('config' => array('token_only' => 'false-ish'), 'answer' => 'tokenonly'));
hk(!$s, "token_only => 'false-ish' (invalid) serves nothing", $s ? 'SERVED' : '');
list($s, $o) = page(array('config' => array('secret_key' => 'pk_' . str_repeat('a', 43))));
hk(!$s, 'a pk_ in secret_key serves nothing', $s ? 'SERVED' : '');

echo "malformed and conflicting answers (tokenlock_verify_pass with this page's resource)\n";
foreach (hm_mutations() as $group => $table) {
    $bad = array();
    foreach ($table as $name => $m) {
        $answer = function ($j) use ($m) {
            return is_string($m) ? $m : call_user_func($m, hm_registered($j), $j);
        };
        cfg_with(array(), $answer);
        try {
            $v = tokenlock_verify_pass($PASS, $RES);
        } catch (TokenlockException $e) {
            $v = array('valid' => false);
        }
        if (is_array($v) && !empty($v['valid'])) {
            $bad[] = $name;
        }
    }
    hk(!$bad, "$group answers are denied (verify)", 'accepted: ' . implode(' | ', $bad));
    $bad = array();
    foreach ($table as $name => $m) {
        list($s) = page(array('mutation' => array($group, $name), 'config' => array('environment' => 'production')));
        if ($s) {
            $bad[] = $name;
        }
    }
    hk(!$bad, "$group answers never serve the page (tokenlock_require)", 'served: ' . implode(' | ', $bad));
}
$idCases = array(
    "allowed:'false' (string) on an identity check" => function ($j) { return array_merge(array('valid' => true, 'allowed' => 'false'), hm_base()); },
    'allowed:0 on an identity check' => function ($j) { return array_merge(array('valid' => true, 'allowed' => 0), hm_base()); },
    'valid:true with code not_holder' => function ($j) { return array_merge(array('valid' => true, 'code' => 'not_holder'), hm_base()); },
    'valid:1' => function ($j) { return array_merge(array('valid' => 1), hm_base()); },
    'expires_at garbage' => function ($j) { return array_merge(array('valid' => true), hm_base(), array('expires_at' => 'soon')); },
    'missing expires_at' => function ($j) { $b = hm_base(); unset($b['expires_at']); return array_merge(array('valid' => true), $b); },
);
$bad = array();
foreach ($idCases as $name => $fn) {
    cfg_with(array('token_only' => true), $fn);
    try {
        $v = tokenlock_verify_pass($PASS);
    } catch (TokenlockException $e) {
        $v = array('valid' => false);
    }
    if (!empty($v['valid'])) {
        $bad[] = 'verify: ' . $name;
    }
    try {
        $v = tokenlock_check_request($PASS);
    } catch (TokenlockException $e) {
        $v = array('valid' => false);
    }
    if (!empty($v['valid'])) {
        $bad[] = 'token_only page check: ' . $name;
    }
}
hk(!$bad, 'malformed identity answers are denied (identity check and token_only)', 'accepted: ' . implode(' | ', $bad));
list($s) = page(array('config' => array('token_only' => true, 'environment' => 'production'), 'path' => '/private/payroll'));
hk(!$s, 'conflicting: identity allowed but route denied → denied (token_only on a registered-keys site)');
list($s) = page(array('config' => array('token_only' => true, 'environment' => 'production'), 'path' => '/members/ok'));
hk($s, 'a permitted route still opens (token_only on a registered-keys site)');

echo "outages\n";
list($s) = page(array('answer' => 'down'));
hk(!$s, 'API unreachable serves nothing');
list($s) = page(array('mutation' => array('malformed', 'non-JSON 200')));
hk(!$s, 'API answering HTML serves nothing');

echo "self-verify: stale, rolled-back and malformed policies\n";
$F = json_decode(file_get_contents(__DIR__ . '/fixtures/hardening-042-bundles.json'), true);
$PK = array($F['kid'] => $F['public_key']);
$O = array('public_keys' => $PK, 'site_id' => 'site1');
function sv_code($fn)
{
    try {
        $fn();
        return null;
    } catch (TokenlockSelfVerifyError $e) {
        return $e->tlcode;
    } catch (Throwable $e) {
        return 'throwable';
    }
}
hk(sv_code(function () use ($F, $O) { return tokenlock_sv_verify_policy_bundle($F['bundles']['good'], $O); }) === null, 'a good bundle verifies');
hk(sv_code(function () use ($F, $O) { return tokenlock_sv_verify_policy_bundle($F['bundles']['seq3_active'], array_merge($O, array('min_seq' => 5))); }) === 'policy_rollback', 'rolled-back bundle (seq 3 after 5) → policy_rollback');
hk(sv_code(function () use ($F, $O) { return tokenlock_sv_verify_policy_bundle($F['bundles']['expired'], $O); }) === 'policy_expired', 'expired bundle → policy_expired');
hk(sv_code(function () use ($F, $O) { return tokenlock_sv_verify_policy_bundle($F['bundles']['good'], array_merge($O, array('max_age_seconds' => 60))); }) === 'policy_stale', 'bundle older than max_age_seconds → policy_stale');
// rollback across requests (disk cache): seq 5 (revoked) then the endpoint serves seq 3 (active)
$dir = sys_get_temp_dir() . '/tl-h042-' . getmypid();
@mkdir($dir, 0700, true);
$served = array($F['bundles']['seq5_revoked'], $F['bundles']['seq3_active']);
$n = 0;
$src = tokenlock_sv_signed_policy(array('site_id' => 'site1', 'secret_key' => $SK, 'public_keys' => $PK, 'cache_dir' => $dir, 'refresh_seconds' => 0, 'load' => function () use (&$n, $served) { return $served[min($n++, 1)]; }));
$PS = str_repeat('s', 40);
$lp = tokenlock_sv_issue_pass(array('sub' => $F['address'], 'h' => array('TOKENLOCK'), 'k' => 'key_a', 'n' => 'n1', 's' => 'https://site1', 'i' => tokenlock_sv_now(), 'e' => tokenlock_sv_now() + 600000), $PS);
$r1 = tokenlock_sv_verify_local_pass($lp, array('pass_secret' => $PS, 'policy' => $src, 'resource' => $RES));
usleep(5000);
$r2 = tokenlock_sv_verify_local_pass($lp, array('pass_secret' => $PS, 'policy' => $src, 'resource' => $RES));
hk($r1['code'] === 'key_revoked' && empty($r2['allowed']), 'a rolled-back bundle never re-grants a revoked key', json_encode(array($r1['code'], $r2['code'])));
$bad = array();
foreach (array('seq_string', 'seq_negative', 'seq_fraction', 'issued_future', 'issued_garbage', 'mode_typo', 'mode_missing', 'keys_object', 'routes_string', 'methods_string', 'key_expires_garbage', 'key_status_unknown', 'revoked_assets_string', 'orgs_null') as $k) {
    if (sv_code(function () use ($F, $O, $k) { return tokenlock_sv_verify_policy_bundle($F['bundles'][$k], $O); }) === null) {
        $bad[] = $k;
    }
}
hk(!$bad, 'malformed policy bundles are rejected', 'accepted: ' . implode(' | ', $bad));
$KEY = function ($o = array()) use ($F) {
    return array_merge(array('id' => 'key_a', 'address' => $F['address'], 'status' => 'active', 'owner_type' => 'agent', 'org_id' => null, 'assets' => array(),
        'permissions' => array('routes' => array('/members/*'), 'methods' => array('GET'), 'environments' => array('production')), 'expires_at' => null, 'pass_ttl_s' => null), $o);
};
$locals = array(
    'mode typo (would read as token mode)' => array('mode' => 'registered-keys', 'keys' => array($KEY(array('status' => 'revoked')))),
    'key expires_at garbage' => array('keys' => array($KEY(array('expires_at' => 'never')))),
    'methods as a string' => array('keys' => array($KEY(array('permissions' => array('routes' => array('/members/*'), 'methods' => 'GETPOST', 'environments' => array('production')))))),
    'routes as a string' => array('keys' => array($KEY(array('permissions' => array('routes' => '/members/*', 'methods' => array('GET'), 'environments' => array('production')))))),
    'environments as a string' => array('keys' => array($KEY(array('permissions' => array('routes' => array('/members/*'), 'methods' => array('GET'), 'environments' => 'productionx'))))),
    'keys not a list' => array('keys' => 'key_a'),
);
$bad = array();
foreach ($locals as $name => $p) {
    $res = $name === 'methods as a string' ? array_merge($RES, array('method' => 'POST')) : $RES;
    try {
        $v = tokenlock_sv_verify_local_pass($lp, array('pass_secret' => $PS, 'policy' => tokenlock_sv_local_policy($p), 'resource' => $res));
    } catch (Throwable $e) {
        $v = array('allowed' => false, 'valid' => false);
    }
    if (!empty($v['allowed'])) {
        $bad[] = $name;
    }
    try {
        $v = tokenlock_sv_verify_local_pass($lp, array('pass_secret' => $PS, 'policy' => tokenlock_sv_local_policy($p)));
    } catch (Throwable $e) {
        $v = array('valid' => false);
    }
    if (!empty($v['valid'])) {
        $bad[] = $name . ' (identity)';
    }
}
hk(!$bad, 'a malformed local policy never grants access', 'granted: ' . implode(' | ', $bad));
$bad = array();
foreach (array('held:"false"' => array('held' => 'false'), 'held:1' => array('held' => 1), 'held:"yes"' => array('held' => 'yes'), 'entry is a string' => 'held') as $name => $h) {
    $prov = tokenlock_sv_proveitonchain_provider(array('api' => 'https://api.test', 'http' => function ($url, $headers, $timeout) use ($h) { return array(200, array('holdings' => array('TOKENLOCK' => $h))); }));
    try {
        $r = call_user_func($prov, $F['address'], array('TOKENLOCK'));
    } catch (Throwable $e) {
        $r = array();
    }
    if (isset($r['TOKENLOCK']['held']) && $r['TOKENLOCK']['held'] === true) {
        $bad[] = $name;
    }
}
hk(!$bad, 'malformed holdings answers are not read as held', 'read as held: ' . implode(' | ', $bad));

echo "\n" . ($failed ? "FAILED: $failed, passed: $passed\n" : "ALL PASSED: $passed\n");
exit($failed ? 1 : 0);
