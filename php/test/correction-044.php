<?php
/**
 * 0.4.4 security correction (PHP self-verify). Written BEFORE the fix; fails against 0.4.3.
 * Same cases as the SDK's test/correction-044.test.mjs:
 *  G1 tokenlock_sv_evaluate(): a token-mode policy returned allowed before the resource was looked at (a valid resource
 *     was allowed; PHP 0.4.3 already refused malformed ones), and identity-only was implied by $resource = null.
 *  G2 an explicitly expired local policy (January 2020) still authorized a currently valid local pass.
 *  A1 tokenlock_sv_verify_local_pass() never checked pass_secret: a missing secret became '' and a pass forged with an
 *     empty HMAC key verified.
 *  A2 $held = null skipped the holdings check.
 *  A5 a policy issued in the future was only refused for signed bundles.
 * Run: php test/correction-044.php  (no network, throwaway keys only)
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
$S = str_repeat('x', 40);
$A = 'bc1qreviewer0000000000000000000000000000';
$now = (int) floor(microtime(true) * 1000);
$iso = function ($ms) { return tokenlock_sv_iso($ms); };
$pol = function ($o) use ($now, $iso) {
    return array_merge(array('v' => 1, 'typ' => 'tokenlock.policy', 'site_id' => 'local', 'seq' => 1, 'issued_at' => $iso($now - 60000), 'expires_at' => $iso($now + 3600000),
        'orgs' => array(), 'revoked_assets' => array(), 'keys' => array()), $o);
};
$KEY = array('id' => 'k1', 'address' => $A, 'status' => 'active', 'permissions' => array('routes' => array('/*'), 'methods' => array('*')));
$TOKEN = $pol(array('mode' => 'token', 'assets' => array('GOTPROOF')));
$REG = $pol(array('mode' => 'registered_keys', 'keys' => array($KEY)));
$ID = array('identity_only' => true);
$pass = function ($k = null, $h = array('GOTPROOF')) use ($A, $S, $now) {
    return tokenlock_sv_issue_pass(array('sub' => $A, 'h' => $h, 'k' => $k, 'n' => 'n1', 's' => 'https://shop.example', 'i' => $now, 'e' => $now + 3600000), $S);
};
$ev = function ($p, $res, $held = array('GOTPROOF')) use ($A) {
    try { return tokenlock_sv_evaluate($p, $A, $held, $res); } catch (Throwable $e) { return array('allowed' => false, 'reason' => 'threw:' . get_class($e)); }
};

echo "G1 evaluate(): token-mode policy never authorizes a resource\n";
foreach (array(
    'normal resource' => array(array('path' => '/private', 'method' => 'GET'), 'policy_required'),
    'misspelled pth' => array(array('pth' => '/private'), 'bad_resource'),
    'array-valued path' => array(array('path' => array('/private')), 'bad_resource'),
    'array-valued path with method' => array(array('path' => array('/private'), 'method' => 'GET'), 'bad_resource'),
    'relative path' => array(array('path' => 'private', 'method' => 'GET'), 'bad_path'),
) as $name => $c) {
    $r = $ev($TOKEN, $c[0]);
    ck($r['allowed'] === false && $r['reason'] === $c[1], "token mode, $name → {$c[1]}", json_encode($r));
}
ck($ev($REG, array('path' => '/private', 'method' => 'GET'))['allowed'] === true, 'registered keys: a granted route is still allowed');
ck($ev($REG, array('pth' => '/private'))['allowed'] === false, 'registered keys: misspelled pth refused');

echo "G1 evaluate(): identity-only must be explicit\n";
ck($ev($TOKEN, $ID)['allowed'] === true, "token mode: array('identity_only' => true) allowed");
ck($ev($REG, $ID)['allowed'] === true, "registered keys: array('identity_only' => true) allowed");
foreach (array('null resource' => null, "identity_only => 'true'" => array('identity_only' => 'true'), 'identity_only + path' => array('identity_only' => true, 'path' => '/x', 'method' => 'GET'), 'empty array' => array()) as $name => $res) {
    $r = $ev($TOKEN, $res);
    ck($r['allowed'] === false && $r['reason'] === 'bad_resource', "token mode: $name → bad_resource", json_encode($r));
    ck($ev($REG, $res)['allowed'] === false, "registered keys: $name refused");
}

echo "A2 evaluate(): held must be a list of asset names\n";
foreach (array('null' => null, 'string' => 'GOTPROOF', 'list of ints' => array(1)) as $name => $held) {
    $r = $ev($TOKEN, $ID, $held);
    ck($r['allowed'] === false && $r['reason'] === 'bad_input', "token mode: held $name → bad_input", json_encode($r));
    $r = $ev($REG, $ID, $held);
    ck($r['allowed'] === false && $r['reason'] === 'bad_input', "registered keys: held $name → bad_input", json_encode($r));
}

echo "G2 expired local policy (January 2020) + currently valid local pass\n";
$EXPIRED = array('mode' => 'registered_keys', 'issued_at' => '2020-01-01T00:00:00.000Z', 'expires_at' => '2020-01-31T00:00:00.000Z', 'keys' => array($KEY));
$lp = tokenlock_sv_local_policy($EXPIRED);
$r = tokenlock_sv_verify_local_pass($pass('k1'), array('pass_secret' => $S, 'policy' => $lp, 'identity_only' => true));
ck($r['valid'] === false && $r['allowed'] === false && $r['code'] === 'policy_expired', 'identity-only → policy_expired', json_encode($r));
$r = tokenlock_sv_verify_local_pass($pass('k1'), array('pass_secret' => $S, 'policy' => $lp, 'resource' => array('path' => '/private', 'method' => 'GET')));
ck($r['valid'] === false && $r['allowed'] === false && $r['code'] === 'policy_expired', 'resource → policy_expired', json_encode($r));
$r = tokenlock_sv_verify_local_pass($pass(), array('pass_secret' => $S, 'policy' => tokenlock_sv_local_policy(array_merge($EXPIRED, array('mode' => 'token', 'keys' => array()))), 'identity_only' => true));
ck($r['allowed'] === false && $r['code'] === 'policy_expired', 'token mode → policy_expired', json_encode($r));
try { call_user_func($lp); ck(false, 'local policy source refuses an expired policy', 'returned the policy'); } catch (TokenlockSelfVerifyError $e) { ck($e->tlcode === 'policy_expired', 'local policy source refuses an expired policy', $e->tlcode); }
$exp = $pol($EXPIRED);
ck($ev($exp, $ID)['reason'] === 'policy_expired', 'evaluate(): expired policy, identity-only → policy_expired', json_encode($ev($exp, $ID)));
ck($ev($exp, array('path' => '/private', 'method' => 'GET'))['reason'] === 'policy_expired', 'evaluate(): expired policy, resource → policy_expired');
$custom = function () use ($exp) { return $exp; };
$r = tokenlock_sv_verify_local_pass($pass('k1'), array('pass_secret' => $S, 'policy' => $custom, 'identity_only' => true));
ck($r['allowed'] === false && $r['code'] === 'policy_expired', 'custom policy callable returning an expired policy → policy_expired', json_encode($r));

echo "A5 policy issued in the future (not yet valid)\n";
$later = array('mode' => 'token', 'keys' => array(), 'issued_at' => $iso($now + 86400000), 'expires_at' => $iso($now + 2 * 86400000));
$r = tokenlock_sv_verify_local_pass($pass(), array('pass_secret' => $S, 'policy' => tokenlock_sv_local_policy($later), 'identity_only' => true));
ck($r['allowed'] === false, 'local policy issued tomorrow refused', json_encode($r));
ck($ev($pol($later), $ID)['allowed'] === false, 'evaluate(): policy issued tomorrow refused');

echo "G2 valid local policy still works\n";
$r = tokenlock_sv_verify_local_pass($pass('k1'), array('pass_secret' => $S, 'policy' => tokenlock_sv_local_policy(array('mode' => 'registered_keys', 'keys' => array($KEY))), 'resource' => array('path' => '/private', 'method' => 'GET')));
ck($r['valid'] === true && $r['allowed'] === true, 'registered keys + granted route → allowed', json_encode($r));

echo "A1 pass_secret checked on verify\n";
$body = tokenlock_sv_b64url(json_encode(array('v' => 1, 'sub' => 'bc1qattacker', 'h' => array('GOTPROOF'), 'k' => null, 'n' => 'x', 's' => 'https://shop.example', 'i' => $now, 'e' => $now + 3600000)));
foreach (array('missing' => null, 'empty' => '', 'short' => 'short') as $name => $sec) {
    $forged = 'tl3.' . $body . '.' . tokenlock_sv_b64url(hash_hmac('sha256', 'tl3.' . $body, (string) $sec, true));
    $o = array('identity_only' => true);
    if ($sec !== null) $o['pass_secret'] = $sec;
    try { $r = tokenlock_sv_verify_local_pass($forged, $o); } catch (Throwable $e) { $r = array('valid' => false, 'allowed' => false, 'code' => 'threw:' . get_class($e)); }
    ck(empty($r['valid']) && empty($r['allowed']) && ($r['code'] ?? '') === 'bad_secret', "pass_secret $name → bad_secret (never valid)", json_encode($r));
}

echo "G4 policy_required reason names identity_only\n";
$r = tokenlock_sv_verify_local_pass($pass(), array('pass_secret' => $S, 'resource' => array('path' => '/x', 'method' => 'GET')));
ck(strpos($r['reason'], 'drop the resource') === false && strpos($r['reason'], 'identity_only') !== false, 'reason says identity_only => true', $r['reason']);

echo "\n$passed passed, $failed failed\n";
exit($failed ? 1 : 0);
