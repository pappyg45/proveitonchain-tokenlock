<?php
// Widening test (RC3 review), PHP port of test/widening-045.test.mjs: environments [] -> ["production"] is a
// WIDENING under contract 1.1 (§3, §5). W1 explicit example; W2 every generator base with environments [] (lib/prop-gen.php,
// same seeds): [] denies every resource request; ["production"] decides production exactly as ["*"], denies staging and
// an omitted environment, identity-only unchanged; non-vacuous.
declare(strict_types=1);
error_reporting(E_ALL);
require_once dirname(__DIR__) . '/tokenlock/tokenlock.php';
require_once dirname(__DIR__) . '/tokenlock/self-verify.php';
require_once __DIR__ . '/lib/prop-gen.php';
$passed = 0; $failed = 0;
function wck($cond, $name, $detail = '') { global $failed, $passed; if ($cond) { $passed++; echo "  ✔ $name\n"; return; } $failed++; echo "  ✖ $name" . ($detail !== '' ? " — $detail" : '') . "\n"; }
function w_decide($x, $request)
{
    $nowIso = TLPG_NOW;
    $now = (int) (strtotime(substr($nowIso, 0, 19) . 'Z') * 1000) + (int) substr($nowIso, 20, 3);
    $policy = array('v' => 1, 'typ' => 'tokenlock.policy', 'site_id' => 'site_vectors', 'seq' => 1, 'issued_at' => tokenlock_sv_iso($now - 60000), 'expires_at' => tokenlock_sv_iso($now + 3600000),
        'mode' => 'registered_keys', 'settings' => $x['state']['settings'], 'orgs' => $x['state']['orgs'], 'revoked_assets' => $x['state']['revoked_assets'], 'keys' => array($x['key']));
    if (array_key_exists('identityOnly', $request)) { $res = array('identity_only' => $request['identityOnly']); }
    else { $res = $request['resource']; }
    try { $r = tokenlock_sv_evaluate($policy, $x['address'], $x['held'], $res, $now); }
    catch (Throwable $e) { return array('allowed' => false, 'reason' => 'threw:' . get_class($e)); }
    return array('allowed' => $r['allowed'] === true, 'reason' => $r['reason']);
}
function w_env($b, $e) { $b['key']['permissions']['environments'] = $e; return $b; }
function w_res($p, $m, $e = null) { return array('resource' => $e === null ? array('path' => $p, 'method' => $m) : array('path' => $p, 'method' => $m, 'environment' => $e)); }
echo "widening [] -> [\"production\"] (TOKENLOCK_PHP " . TOKENLOCK_PHP . ")\n";
// W1
$addr = 'bc1qwideningkey0000000000000000000000000000';
$base = array('state' => array('settings' => array('require_org' => false), 'orgs' => array(), 'revoked_assets' => array()), 'address' => $addr, 'held' => array('GOODTOKEN'),
    'key' => array('id' => 'key_widening01', 'address' => $addr, 'status' => 'active', 'owner_type' => 'agent', 'org_id' => null, 'assets' => array(), 'expires_at' => null,
        'permissions' => array('routes' => array('/api/*'), 'methods' => array('GET'), 'environments' => array())));
$deny = array('allowed' => false, 'reason' => 'environment_not_allowed');
$ok = w_decide($base, w_res('/api/x', 'GET', 'production')) === $deny && w_decide($base, w_res('/api/x', 'GET', 'staging')) === $deny && w_decide($base, w_res('/api/x', 'GET')) === $deny;
$w = w_env($base, array('production'));
$ok = $ok && w_decide($w, w_res('/api/x', 'GET', 'production')) === array('allowed' => true, 'reason' => 'ok')
    && w_decide($w, w_res('/api/x', 'GET', 'staging')) === $deny && w_decide($w, w_res('/api/x', 'GET')) === $deny
    && w_decide($w, w_res('/other', 'GET', 'production'))['allowed'] === false && w_decide($w, w_res('/api/x', 'POST', 'production'))['allowed'] === false;
wck($ok, 'W1 widening [] -> ["production"]: production now allowed; staging and omitted environment still denied; other grants still apply');
// W2
$st = array('bases' => 0, 'empty_env_bases' => 0, 'evaluations' => 0, 'newly_allowed_production' => 0, 'failures_total' => 0, 'failures' => array());
$fail = function ($f) use (&$st) { $st['failures_total']++; if (count($st['failures']) < 10) { $st['failures'][] = $f; } };
$REQ = tlpg_requests();
foreach (TLPG_SEEDS as $seed) {
    $rnd = tlpg_rng($seed);
    for ($b = 0; $b < TLPG_BASES; $b++) {
        $bb = tlpg_base($rnd); $st['bases']++;
        if (count($bb['key']['permissions']['environments']) !== 0) { continue; }
        $st['empty_env_bases']++;
        $w = w_env($bb, array('production')); $star = w_env($bb, array('*'));
        foreach ($REQ as $request) {
            $st['evaluations']++;
            $d0 = w_decide($bb, $request); $dw = w_decide($w, $request);
            if (array_key_exists('identityOnly', $request)) { if ($dw['allowed'] !== $d0['allowed']) { $fail(array($seed, $b, 'identity-only unchanged')); } continue; }
            if ($d0['allowed']) { $fail(array($seed, $b, $request, '[] grants nothing')); }
            $env = $request['resource']['environment'] ?? null;
            if ($env === 'production') { $ds = w_decide($star, $request); if ($dw['allowed'] !== $ds['allowed']) { $fail(array($seed, $b, $request, 'production decided as with ["*"]')); } if ($dw['allowed']) { $st['newly_allowed_production']++; } }
            elseif ($dw['allowed']) { $fail(array($seed, $b, $request, 'not production -> deny')); }
        }
    }
}
echo tlpg_json($st) . "\n";
wck($st['failures_total'] === 0 && $st['empty_env_bases'] > 0 && $st['newly_allowed_production'] > 0, 'W2 widening [] -> ["production"] over every generator base with environments []', tlpg_json($st['failures']));
echo "$passed passed, $failed failed\n";
exit($failed ? 1 : 0);
