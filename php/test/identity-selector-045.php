<?php
// RC4 (review), PHP: identity-only is selected only by the exact request array('identity_only' => true) (PHP's
// top-level form; the PHP API has no separate options object). Every other identity flag (nested, camelCase, "true",
// 1, combined with a resource or an unknown field) and every malformed resource (null, array(), list, string, number)
// must be denied, for token-mode and registered-key policies, keys with empty and normal grants.
//   S1/S2 tokenlock_sv_evaluate variants; S3 tokenlock_sv_verify_local_pass variants; P-ID property (exhaustive pool).
error_reporting(E_ALL & ~E_DEPRECATED);
require_once dirname(__DIR__) . '/tokenlock/tokenlock.php';
require_once dirname(__DIR__) . '/tokenlock/self-verify.php';
require_once __DIR__ . '/lib/prop-gen.php';
$passed = 0; $failed = 0;
function ick($cond, $name, $detail = '') { global $failed, $passed; if ($cond) { $passed++; echo "  ✔ $name\n"; return; } $failed++; echo "  ✖ $name" . ($detail !== '' ? " — $detail" : '') . "\n"; }
$NOW = (int) (strtotime('2026-11-19T12:00:00Z') * 1000);
$A = 'bc1qidentityselector000000000000000000000000';
$pol = function ($o) use ($NOW) { return array_merge(array('v' => 1, 'typ' => 'tokenlock.policy', 'site_id' => 'local', 'seq' => 1, 'issued_at' => tokenlock_sv_iso($NOW - 60000), 'expires_at' => tokenlock_sv_iso($NOW + 3600000), 'orgs' => array(), 'revoked_assets' => array(), 'keys' => array()), $o); };
$key = function ($perm) use ($A) { return array('id' => 'k1', 'address' => $A, 'status' => 'active', 'owner_type' => 'agent', 'org_id' => null, 'assets' => array(), 'expires_at' => null, 'permissions' => $perm); };
$POL = array(
    'token mode' => $pol(array('mode' => 'token')),
    'registered, empty grants' => $pol(array('mode' => 'registered_keys', 'keys' => array($key(array('routes' => array(), 'methods' => array(), 'environments' => array()))))),
    'registered, normal grants' => $pol(array('mode' => 'registered_keys', 'keys' => array($key(array('routes' => array('*'), 'methods' => array('*'), 'environments' => array('*')))))),
);
$VAR = array(
    'nested identity_only: true' => array('resource' => array('identity_only' => true)),
    'nested identityOnly: true' => array('resource' => array('identityOnly' => true)),
    'camelCase identityOnly: true' => array('identityOnly' => true),
    'identity_only "true"' => array('identity_only' => 'true'),
    'identity_only 1' => array('identity_only' => 1),
    'identity_only false' => array('identity_only' => false),
    'identity_only nested in its own value' => array('identity_only' => array('identity_only' => true)),
    'nested two levels' => array('resource' => array('resource' => array('identity_only' => true))),
    'nested inside path' => array('path' => array('identity_only' => true), 'method' => 'GET'),
    'nested inside a list' => array(array('identity_only' => true)),
    'identity_only with path and method' => array('identity_only' => true, 'path' => '/api/x', 'method' => 'GET'),
    'identity_only with an unknown key' => array('identity_only' => true, 'extra' => 1),
    'identity_only with resource null' => array('identity_only' => true, 'resource' => null),
    'identity_only with resource array()' => array('identity_only' => true, 'resource' => array()),
    'resource null' => null, 'resource array()' => array(), 'resource string' => 'identity_only', 'resource 1' => 1, 'resource true' => true, 'resource 0' => 0,
);
$ev = function ($p, $res) use ($A, $NOW) { return tokenlock_sv_evaluate($p, $A, array('GOODTOKEN'), $res, $NOW); };
echo "identity selector (TOKENLOCK_PHP " . TOKENLOCK_PHP . ")\n";
$bad = array();
foreach ($POL as $pn => $p) {
    foreach ($VAR as $vn => $res) { $r = $ev($p, $res); if ($r['allowed'] !== false || $r['reason'] !== 'bad_resource') { $bad[] = "$pn / $vn: " . json_encode($r); } }
    if ($ev($p, array('identity_only' => true))['allowed'] !== true) { $bad[] = "$pn / control identity_only"; }
}
ick($bad === array(), 'S1/S2 tokenlock_sv_evaluate denies every identity-flag variant (bad_resource) on token-mode and registered policies; array(identity_only => true) still works', implode('; ', $bad));
$T = (int) (microtime(true) * 1000); $SECRET = str_repeat('s', 40); $bad = array();
foreach ($POL as $pn => $p0) {
    $p = array_merge($p0, array('issued_at' => tokenlock_sv_iso($T - 60000), 'expires_at' => tokenlock_sv_iso($T + 3600000)));
    $pass = tokenlock_sv_issue_pass(array('v' => 1, 'sub' => $A, 'h' => array('GOODTOKEN'), 'k' => $p['mode'] === 'registered_keys' ? 'k1' : null, 'n' => 'n', 's' => 's', 'i' => $T - 1000, 'e' => $T + 3600000), $SECRET);
    $src = tokenlock_sv_local_policy($p);
    $opts = array('resource' => array('identity_only' => true));
    foreach (array_merge(array('resource=nested identity_only' => array('resource' => array('identity_only' => true)), 'identity_only "true"' => array('identity_only' => 'true'), 'identity_only 1' => array('identity_only' => 1), 'identity_only + resource null' => array('identity_only' => true, 'resource' => null), 'resource null' => array('resource' => null), 'resource array()' => array('resource' => array()), 'camelCase identityOnly' => array('identityOnly' => true), 'no request' => array())) as $vn => $o) {
        $r = tokenlock_sv_verify_local_pass($pass, array_merge(array('pass_secret' => $SECRET, 'policy' => $src), $o));
        if (!empty($r['valid']) || !empty($r['allowed'])) { $bad[] = "$pn / $vn: " . json_encode($r); }
    }
    $c = tokenlock_sv_verify_local_pass($pass, array('pass_secret' => $SECRET, 'policy' => $src, 'identity_only' => true));
    if (empty($c['valid'])) { $bad[] = "$pn / control: " . json_encode($c); }
}
ick($bad === array(), 'S3 tokenlock_sv_verify_local_pass refuses every variant; identity_only => true still works', implode('; ', $bad));
// P-ID property over the PHP request argument
$KEYS = array('identity_only', 'path', 'method', 'environment', 'resource', 'identityOnly', 'extra');
$POOL = array(true, 'true', 1, null, '', array(), '/api/x', 'GET', 'production', array('identity_only' => true), array(array('identity_only' => true)), 'api/x');
$REQ = array(null, array(), 'x', 1, true);
foreach ($KEYS as $k) { foreach ($POOL as $a) { $REQ[] = array($k => $a); } }
for ($i = 0; $i < count($KEYS); $i++) { for ($j = $i + 1; $j < count($KEYS); $j++) { foreach ($POOL as $a) { foreach ($POOL as $b) { $REQ[] = array($KEYS[$i] => $a, $KEYS[$j] => $b); } } } }
foreach ($POOL as $a) { foreach ($POOL as $b) { $REQ[] = array('path' => $a, 'method' => $b, 'identity_only' => true); } }
$strict = function ($r) { return is_array($r) && count($r) === 1 && array_key_exists('identity_only', $r) && $r['identity_only'] === true; };
$okStr = function ($s) { return is_string($s) && $s !== '' && trim($s) === $s; };
$valid = function ($r) use ($okStr) {
    if (!is_array($r) || !$r || array_keys($r) === range(0, count($r) - 1)) { return false; }
    foreach (array_keys($r) as $k) { if (!in_array($k, array('path', 'method', 'environment'), true)) { return false; } }
    if (!array_key_exists('path', $r) || !array_key_exists('method', $r) || !$okStr($r['path']) || !$okStr($r['method']) || !preg_match('/^[A-Za-z]{1,10}$/D', $r['method'])) { return false; }
    if (array_key_exists('environment', $r) && (!$okStr($r['environment']) || !preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,29}$/D', $r['environment']))) { return false; }
    return $r['path'][0] === '/';
};
$bases = array(); foreach ($POL as $p) { $bases[] = array($p, array('GOODTOKEN'), $A); }
foreach (TLPG_SEEDS as $seed) { $rnd = tlpg_rng($seed); for ($b = 0; $b < TLPG_BASES; $b++) { $x = tlpg_base($rnd); $bases[] = array($pol(array('mode' => 'registered_keys', 'settings' => $x['state']['settings'], 'orgs' => $x['state']['orgs'], 'revoked_assets' => $x['state']['revoked_assets'], 'keys' => array($x['key']))), $x['held'], $x['address']); } }
$st = array('requests' => count($REQ), 'bases' => count($bases), 'evaluations' => 0, 'malformed' => 0, 'strict_identity_allowed' => 0, 'violations' => 0, 'examples' => array());
foreach ($REQ as $r) {
    $mal = !$strict($r) && !$valid($r);
    if ($mal) { $st['malformed']++; }
    foreach ($bases as $B) {
        $st['evaluations']++;
        $d = tokenlock_sv_evaluate($B[0], $B[2], $B[1], $r, $NOW);
        if ($mal && $d['allowed'] !== false) { $st['violations']++; if (count($st['examples']) < 8) { $st['examples'][] = array($r, $d['reason']); } }
        if ($strict($r) && $d['allowed']) { $st['strict_identity_allowed']++; }
    }
}
echo json_encode($st, JSON_UNESCAPED_SLASHES) . "\n";
ick($st['violations'] === 0 && $st['malformed'] > 0 && $st['strict_identity_allowed'] > 0, 'P-ID property: a request that is neither exactly array(identity_only => true) nor a valid resource is always denied');
echo "$passed passed, $failed failed\n";
exit($failed ? 1 : 0);
