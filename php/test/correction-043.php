<?php
/**
 * 0.4.3 security correction (PHP drop-in + PHP self-verify). Written BEFORE the fix; fails against 0.4.2.
 * A malformed authorization request (unknown key, wrong type, empty / whitespace-only / null value, malformed path,
 * partial route/method) must be refused (bad_resource / bad_path) and must never become an identity-only check.
 * Identity-only stays supported, but only when asked for explicitly: array('identity_only' => true).
 * Run: php test/correction-043.php  (no network, throwaway keys only)
 */
error_reporting(E_ALL);
require_once dirname(__DIR__) . '/tokenlock/tokenlock.php';
require_once dirname(__DIR__) . '/tokenlock/self-verify.php';
require_once __DIR__ . '/fixtures/hardening-mock.php';
$failed = 0;
$passed = 0;
function ck($cond, $name, $detail = '')
{
    global $failed, $passed;
    if ($cond) { $passed++; echo "  ✔ $name\n"; return; }
    $failed++;
    echo "  ✖ $name" . ($detail !== '' ? " — $detail" : '') . "\n";
}
$SK = 'sk_' . str_repeat('h', 43);
$PASS = 'pp1.' . str_repeat('H', 40) . '.' . str_repeat('Q', 43);
$SENT = array();
function cfg_capture()
{
    global $SK, $SENT;
    $SENT = array();
    $inner = hm_handler('registered');
    tokenlock_configure(array('secret_key' => $SK, 'cache' => false, 'cache_dir' => sys_get_temp_dir(), 'api_base' => 'https://api.test',
        'http_handler' => function ($m, $u, $h, $b, $t = null) use ($inner) { global $SENT; $SENT[] = $b ? json_decode($b, true) : array(); return call_user_func($inner, $m, $u, $h, $b, $t); }));
}
/** Outcome: 'refused:<code>' for a refusal, else 'valid' / 'denied:<code>'. */
function outcome($pass, $res)
{
    try { $v = tokenlock_verify_pass($pass, $res); } catch (TokenlockException $e) { return 'refused:' . $e->error_code; } catch (Throwable $e) { return 'error:' . get_class($e); }
    if (is_array($v) && !empty($v['valid'])) return 'valid';
    $c = is_array($v) && isset($v['code']) ? $v['code'] : '';
    return in_array($c, array('bad_resource', 'bad_path'), true) ? 'refused:' . $c : 'denied:' . $c;
}
$OK = array('path' => '/members/x', 'method' => 'GET', 'environment' => 'production');
$MALFORMED = array(
    'unknown key (typo pth)' => array('pth' => '/members/x', 'method' => 'GET'),
    'unknown key next to a valid resource' => $OK + array('rout' => '/admin'),
    'list instead of keyed array' => array('/members/x', 'GET'),
    'path array' => array('path' => array('/members/x'), 'method' => 'GET'),
    'path int' => array('path' => 5, 'method' => 'GET'),
    'path empty' => array('path' => '', 'method' => 'GET'),
    'path whitespace-only' => array('path' => '   ', 'method' => 'GET'),
    'path null' => array('path' => null, 'method' => 'GET'),
    'path padded' => array('path' => ' /members/x ', 'method' => 'GET'),
    'path relative' => array('path' => 'members/x', 'method' => 'GET'),
    'method empty' => array('path' => '/members/x', 'method' => ''),
    'method whitespace-only' => array('path' => '/members/x', 'method' => '  '),
    'method null' => array('path' => '/members/x', 'method' => null),
    'method array' => array('path' => '/members/x', 'method' => array('GET')),
    'method padded' => array('path' => '/members/x', 'method' => ' GET'),
    'method too long (was truncated)' => array('path' => '/members/x', 'method' => 'GETXXXXXXXXXX'),
    'method with symbols' => array('path' => '/members/x', 'method' => 'GET;POST'),
    'environment empty' => array_merge($OK, array('environment' => '')),
    'environment whitespace-only' => array_merge($OK, array('environment' => '   ')),
    'environment null' => array_merge($OK, array('environment' => null)),
    'environment int' => array_merge($OK, array('environment' => 1)),
    'environment too long (was truncated)' => array_merge($OK, array('environment' => 'production' . str_repeat('x', 40))),
    'empty array' => array(),
    'path without method' => array('path' => '/members/x'),
    'method without path' => array('method' => 'GET'),
    'environment only' => array('environment' => 'production'),
    'identity_only false' => array('identity_only' => false),
    'identity_only string' => array('identity_only' => 'true'),
    'identity_only with a route' => array_merge(array('identity_only' => true), $OK),
    'string instead of array' => '/members/x',
);
$BAD_PATHS = array('/members/../admin', '/members/./x', '/members/%2e%2e/admin', '/members/%2E%2E/admin', '/members/%252e%252e/admin', '/members/%252fadmin',
    '/members/%2fadmin', '/members/%5cadmin', "/members\\admin", '/members/x;jsessionid=1', '/members/%00', '/members/%3b', '/members/%25', "/members/\0x", "/members/\tx", '/members/%E0%A4%A');

echo "malformed authorization requests (tokenlock_verify_pass)\n";
foreach ($MALFORMED as $name => $r) {
    cfg_capture();
    $o = outcome($PASS, $r);
    $downgraded = false;
    foreach ($SENT as $b) { if (!isset($b['path']) && !isset($b['method']) && !isset($b['environment'])) $downgraded = true; }
    ck(strpos($o, 'refused:') === 0 && !$downgraded, "refused, never sent as identity-only: $name", $o . ($downgraded ? ' (sent as identity-only)' : ''));
}
echo "a missing resource is not an identity check\n";
cfg_capture();
$o = outcome($PASS, null);
ck($o === 'refused:bad_resource' && !$SENT, 'tokenlock_verify_pass($pass) / ($pass, null) is refused (bad_resource), nothing sent', $o);
echo "explicit identity-only stays supported\n";
cfg_capture();
$v = tokenlock_verify_pass($PASS, array('identity_only' => true));
ck(!empty($v['valid']) && isset($SENT[0]['identity_only']) && $SENT[0]['identity_only'] === true && !isset($SENT[0]['path']), "array('identity_only' => true) is valid and sends identity_only: true", json_encode($SENT));
echo "malformed and ambiguous paths\n";
foreach ($BAD_PATHS as $p) {
    cfg_capture();
    $o = outcome($PASS, array('path' => $p, 'method' => 'GET'));
    ck(strpos($o, 'refused:') === 0 && !$SENT, 'refused: ' . json_encode($p), $o);
}
cfg_capture();
$v = tokenlock_verify_pass($PASS, array('path' => '/Members//%41/', 'method' => 'get', 'environment' => 'production'));
ck(!empty($v['valid']) && $SENT[0]['path'] === '/members/a' && $SENT[0]['method'] === 'GET', 'canonical form sent (/members/a, GET)', json_encode($SENT));
echo "inconsistent route / method combinations\n";
cfg_capture();
ck(outcome($PASS, array('path' => '/members/x', 'method' => 'POST', 'environment' => 'production')) === 'denied:method_not_allowed', 'route allowed, method not → method_not_allowed');
ck(outcome($PASS, array('path' => '/admin', 'method' => 'GET', 'environment' => 'production')) === 'denied:route_not_allowed', 'method allowed, route not → route_not_allowed');
echo "configuration\n";
foreach (array('   ', ' production', "prod\n") as $env) {
    tokenlock_configure(array('secret_key' => $SK, 'environment' => $env, 'cache_dir' => sys_get_temp_dir()));
    ck(tokenlock_config_problem() !== null, "environment " . json_encode($env) . " is a configuration error");
}

echo "self-verify\n";
$ADDR = 'bc1qagentaddressxxxxxxxxxxxxxxxxxxxxxxxx';
$PS = str_repeat('s', 40);
$POL = array('mode' => 'registered_keys', 'keys' => array(array('id' => 'key_a', 'address' => $ADDR, 'status' => 'active', 'owner_type' => 'agent', 'org_id' => null, 'assets' => array(),
    'permissions' => array('routes' => array('/members/*'), 'methods' => array('GET'), 'environments' => array('production')), 'expires_at' => null)));
$lp = tokenlock_sv_issue_pass(array('sub' => $ADDR, 'h' => array('TOKENLOCK'), 'k' => 'key_a', 'n' => 'n1', 's' => 'https://site1', 'i' => tokenlock_sv_now(), 'e' => tokenlock_sv_now() + 600000), $PS);
$svo = function ($o) use ($lp, $PS, $POL) { try { return tokenlock_sv_verify_local_pass($lp, array_merge(array('pass_secret' => $PS, 'policy' => tokenlock_sv_local_policy($POL)), $o)); } catch (Throwable $e) { return array('allowed' => false, 'code' => 'error: ' . get_class($e)); } };
foreach ($MALFORMED as $name => $r) {
    $v = $svo(array('resource' => $r));
    ck(empty($v['allowed']) && in_array($v['code'] ?? '', array('bad_resource', 'bad_path'), true), "self-verify refuses: $name", json_encode(array($v['allowed'] ?? null, $v['code'] ?? null)));
}
foreach ($BAD_PATHS as $p) {
    $v = $svo(array('resource' => array('path' => $p, 'method' => 'GET')));
    ck(empty($v['allowed']) && in_array($v['code'] ?? '', array('bad_resource', 'bad_path'), true), 'self-verify refuses path ' . json_encode($p), $v['code'] ?? '');
}
$v = $svo(array());
ck(empty($v['allowed']) && ($v['code'] ?? '') === 'bad_resource', 'self-verify: no resource and no identity_only is refused', $v['code'] ?? '');
$v = $svo(array('identity_only' => true));
ck(!empty($v['allowed']), 'self-verify: explicit identity_only works', $v['code'] ?? '');
$v = $svo(array('identity_only' => true, 'resource' => $OK));
ck(empty($v['allowed']), 'self-verify: identity_only with a resource is refused', $v['code'] ?? '');
$v = $svo(array('resource' => $OK));
ck(!empty($v['allowed']), 'self-verify: a valid route is allowed', $v['code'] ?? '');
$v = $svo(array('resource' => $OK, 'resorce' => 1));
ck(empty($v['allowed']), 'self-verify: unknown option is refused', $v['code'] ?? '');
foreach ($MALFORMED as $name => $r) {
    if (strpos($name, 'identity_only') === 0) continue;
    try { $e = tokenlock_sv_evaluate(call_user_func(tokenlock_sv_local_policy($POL)), $ADDR, array('TOKENLOCK'), $r); } catch (Throwable $t) { $e = array('allowed' => false, 'reason' => 'error: ' . get_class($t)); }
    ck(empty($e['allowed']), "evaluate refuses: $name", $e['reason'] ?? '');
}
echo $failed ? "FAILED: $failed (passed $passed)\n" : "ALL PASSED: $passed\n";
exit($failed ? 1 : 0);
