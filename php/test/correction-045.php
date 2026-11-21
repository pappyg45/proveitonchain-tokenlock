<?php
/**
 * 0.4.5 security patch (PHP self-verify). Written BEFORE the fix; fails against 0.4.4.
 * Same cases as the SDK's test/correction-045.test.mjs:
 *  F1 missing / null / {} permissions (or missing / null routes or methods) on an active registered key were read as
 *     routes ['*'] and methods ['*'], so DELETE /private/admin was allowed. Now: routes and methods must each be an
 *     explicit list; otherwise the key is refused with policy_invalid. [] grants nothing; only an explicit '*' is a wildcard.
 * Run: php test/correction-045.php  (no network, throwaway values only)
 */
error_reporting(E_ALL);
require_once dirname(__DIR__) . '/tokenlock/tokenlock.php';
require_once dirname(__DIR__) . '/tokenlock/self-verify.php';
$failed = 0;
$passed = 0;
function ck($cond, $name, $detail = '')
{
    global $failed, $passed;
    if ($cond) { $passed++; echo "  ✔ $name\n"; return; }
    $failed++;
    echo "  ✖ $name" . ($detail !== '' ? " — $detail" : '') . "\n";
}
echo 'TOKENLOCK_PHP ' . TOKENLOCK_PHP . "\n";
$S = str_repeat('x', 40);
$A = 'bc1qreviewer0000000000000000000000000000';
$B = 'bc1qsecondkey00000000000000000000000000000';
$RES = array('path' => '/private/admin', 'method' => 'DELETE');
$now = (int) floor(microtime(true) * 1000);
$pol = function ($keys) use ($now) {
    return array('v' => 1, 'typ' => 'tokenlock.policy', 'site_id' => 'local', 'seq' => 1, 'issued_at' => tokenlock_sv_iso($now - 60000), 'expires_at' => tokenlock_sv_iso($now + 3600000),
        'mode' => 'registered_keys', 'orgs' => array(), 'revoked_assets' => array(), 'keys' => $keys);
};
$key = function ($extra, $addr = null, $id = 'k1') use ($A) {
    return array_merge(array('id' => $id, 'address' => $addr ?: $A, 'status' => 'active'), $extra);
};
$ev = function ($p, $res = null, $addr = null) use ($A, $RES) {
    try { return tokenlock_sv_evaluate($p, $addr ?: $A, array('GOTPROOF'), $res ?: $RES); } catch (Throwable $e) { return array('allowed' => false, 'reason' => 'threw:' . get_class($e) . ':' . $e->getMessage()); }
};
$pass = function ($k = 'k1') use ($A, $S, $now) {
    return tokenlock_sv_issue_pass(array('sub' => $A, 'h' => array('GOTPROOF'), 'k' => $k, 'n' => 'n1', 's' => 'https://shop.example', 'i' => $now, 'e' => $now + 3600000), $S);
};
$MISSING = array(
    'no permissions field' => array(),
    'permissions: null' => array('permissions' => null),
    'permissions: {} (empty array)' => array('permissions' => array()),
    'permissions: {} (stdClass, as json_decode gives objects)' => array('permissions' => new stdClass()),
    'routes: null, methods: null' => array('permissions' => array('routes' => null, 'methods' => null)),
    'routes missing (methods ["*"])' => array('permissions' => array('methods' => array('*'))),
    'methods missing (routes ["/*"])' => array('permissions' => array('routes' => array('/*'))),
    'routes null (methods ["*"])' => array('permissions' => array('routes' => null, 'methods' => array('*'))),
    'methods null (routes ["/*"])' => array('permissions' => array('routes' => array('/*'), 'methods' => null)),
    'only environments given' => array('permissions' => array('environments' => array('production'))),
);
$NOT_LIST = array(
    'routes: "*" (string)' => array('permissions' => array('routes' => '*', 'methods' => array('*'))),
    'methods: "DELETE" (string)' => array('permissions' => array('routes' => array('/*'), 'methods' => 'DELETE')),
    'routes: {"a":"/x"} (map)' => array('permissions' => array('routes' => array('a' => '/x'), 'methods' => array('*'))),
    'routes: 5' => array('permissions' => array('routes' => 5, 'methods' => array('*'))),
    'permissions: "all" (string)' => array('permissions' => 'all'),
);

echo "F1 evaluate(): missing/null/{} routes or methods never grant a route (policy_invalid)\n";
foreach ($MISSING as $name => $x) {
    $r = $ev($pol(array($key($x))));
    ck($r['allowed'] === false && $r['reason'] === 'policy_invalid', $name, json_encode(array('allowed' => $r['allowed'], 'reason' => $r['reason'])));
}
echo "F1 evaluate(): permissions that are not lists are refused (policy_invalid)\n";
foreach ($NOT_LIST as $name => $x) {
    $r = $ev($pol(array($key($x))));
    ck($r['allowed'] === false && $r['reason'] === 'policy_invalid', $name, json_encode(array('allowed' => $r['allowed'], 'reason' => $r['reason'])));
}
echo "F1 explicit grants still work; [] grants nothing; '*' only when explicit\n";
ck($ev($pol(array($key(array('permissions' => array('routes' => array('*'), 'methods' => array('*'), 'environments' => array('*')))))))['allowed'] === true, 'explicit "*" / "*" allowed');
ck($ev($pol(array($key(array('permissions' => array('routes' => array('/private/*'), 'methods' => array('DELETE'), 'environments' => array('*')))))))['allowed'] === true, 'explicit route + method allowed');
ck($ev($pol(array($key(array('permissions' => array('routes' => array(), 'methods' => array('*'), 'environments' => array('*')))))))['reason'] === 'route_not_allowed', 'routes [] → route_not_allowed');
ck($ev($pol(array($key(array('permissions' => array('routes' => array('/*'), 'methods' => array(), 'environments' => array('*')))))))['reason'] === 'method_not_allowed', 'methods [] → method_not_allowed');
echo "F1 mixed keys\n";
$mixed = $pol(array($key(array('permissions' => array())), $key(array('permissions' => array('routes' => array('/private/*'), 'methods' => array('DELETE'), 'environments' => array('*'))), $B, 'k2')));
ck($ev($mixed, null, $A)['reason'] === 'policy_invalid', 'key with permissions {} refused', json_encode($ev($mixed, null, $A)));
ck($ev($mixed, null, $B)['allowed'] === true, 'complete key in the same policy still allowed', json_encode($ev($mixed, null, $B)));
echo "F1 identity-only unchanged\n";
ck(tokenlock_sv_evaluate($pol(array($key(array()))), $A, array('GOTPROOF'), array('identity_only' => true))['allowed'] === true, 'identity_only with a key lacking permissions');
echo "F1 verify_local_pass(): DELETE /private/admin\n";
foreach ($MISSING as $name => $x) {
    try { $r = tokenlock_sv_verify_local_pass($pass(), array('pass_secret' => $S, 'policy' => tokenlock_sv_local_policy($pol(array($key($x)))), 'resource' => $RES)); }
    catch (Throwable $e) { $r = array('valid' => false, 'allowed' => false, 'code' => 'threw:' . $e->getMessage()); }
    ck($r['valid'] === false && $r['allowed'] === false && $r['code'] === 'policy_invalid', $name, json_encode(array('valid' => $r['valid'], 'allowed' => $r['allowed'], 'code' => $r['code'])));
}
$r = tokenlock_sv_verify_local_pass($pass(), array('pass_secret' => $S, 'policy' => tokenlock_sv_local_policy($pol(array($key(array('permissions' => array('routes' => array('/private/*'), 'methods' => array('DELETE'), 'environments' => array('*'))))))), 'resource' => $RES));
ck($r['valid'] === true && $r['allowed'] === true, 'explicit grant still allowed', json_encode($r));

echo "\n$passed passed, $failed failed\n";
exit($failed ? 1 : 0);
