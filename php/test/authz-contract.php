<?php
/**
 * AUTHORIZATION-CONTRACT.md v1 for the PHP drop-in: the shared vectors (docs/authorization-vectors-v1.json, or
 * TL_VECTORS=<file>) and the property tests (test/lib/prop-gen.php, same seeds and cases as Node).
 * AUTHZ_RESULTS=<dir> writes php-selfverify.json and properties-php-selfverify.json for the equivalence matrix.
 * Run: php test/authz-contract.php
 */
error_reporting(E_ALL & ~E_DEPRECATED);
require_once dirname(__DIR__) . '/tokenlock/tokenlock.php';
require_once dirname(__DIR__) . '/tokenlock/self-verify.php';
require_once __DIR__ . '/lib/prop-gen.php';
$failed = 0; $passed = 0;
function ck($cond, $name, $detail = '') { global $failed, $passed; if ($cond) { $passed++; echo "  ✔ $name\n"; return; } $failed++; echo "  ✖ $name" . ($detail !== '' ? " — $detail" : '') . "\n"; }
$vfile = getenv('TL_VECTORS') ?: null;
foreach (array(dirname(__DIR__, 2) . '/docs/authorization-vectors-v1.json', dirname(__DIR__) . '/../docs/authorization-vectors-v1.json') as $cand) { if (!$vfile && is_file($cand)) { $vfile = $cand; } }
$V = json_decode(file_get_contents($vfile), true);
$out = getenv('AUTHZ_RESULTS') ?: null;
$save = function ($name, $data) use ($out) { if ($out) { @mkdir($out, 0777, true); file_put_contents("$out/$name.json", json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)); } };
$ms = function ($iso) { return (int) round(strtotime($iso) * 1000) + (int) substr($iso, 20, 3); };
function tlac_decide($x, $request, $nowIso)
{
    $now = (int) (strtotime(substr($nowIso, 0, 19) . 'Z') * 1000) + (int) substr($nowIso, 20, 3);
    $policy = array('v' => 1, 'typ' => 'tokenlock.policy', 'site_id' => 'site_vectors', 'seq' => 1, 'issued_at' => tokenlock_sv_iso($now - 60000), 'expires_at' => tokenlock_sv_iso($now + 3600000),
        'mode' => (($x['policy_mode'] ?? null) === 'token' ? 'token' : 'registered_keys'), 'settings' => $x['state']['settings'], 'orgs' => $x['state']['orgs'], 'revoked_assets' => $x['state']['revoked_assets'], 'keys' => array($x['key']));
    // RC4: the PHP API takes ONE request argument, so a vector's request maps to it as follows. Before RC4, a resource that
    // was not an array was dropped when it came with identityOnly (so { identityOnly: true, resource: null } became a plain
    // identity-only request), and unknown top-level request fields were ignored. Now: unknown top-level fields and
    // identityOnly together with ANY resource are passed through as extra fields of the request array, which the PHP
    // validator refuses, exactly as Node refuses them. Of the 111 RC3 vectors only R07 ({ identityOnly: true, resource: { path,
    // method } }) has one of these shapes: it was mapped to array('identity_only' => true, 'path' => ..., 'method' => ...) and is now
    // array('identity_only' => true, 'resource' => array(...)); tokenlock_validate_resource answers array(null, 'bad_resource') for
    // both, so R07's expectation and result are unchanged. No RC3 vector has unknown top-level fields.
    $extra = array_diff(array_keys($request), array('identityOnly', 'resource'));
    if (array_key_exists('php_resource', $x)) {
        $res = $x['php_resource']; // RC4 vector group I: the PHP-native form of the same request (see the vector's php_note)
    } elseif ($extra) {
        $res = array();
        foreach ($request as $k => $val) { $res[$k === 'identityOnly' ? 'identity_only' : $k] = $val; }
    } elseif (array_key_exists('identityOnly', $request)) {
        $res = array('identity_only' => $request['identityOnly']);
        if (array_key_exists('resource', $request)) { $res['resource'] = $request['resource']; }
    } elseif (array_key_exists('resource', $request)) {
        $res = $request['resource'];
    } else {
        $res = null;
    }
    try { $r = tokenlock_sv_evaluate($policy, $x['address'], $x['held'], $res, $now); }
    catch (Throwable $e) { return array('allowed' => false, 'reason' => 'threw:' . get_class($e)); }
    return array('allowed' => $r['allowed'] === true, 'reason' => $r['reason']);
}
echo 'TOKENLOCK_PHP ' . TOKENLOCK_PHP . ', contract ' . $V['contract_version'] . ', ' . count($V['vectors']) . " vectors ($vfile)\n";
$results = array();
foreach ($V['vectors'] as $vec) {
    $d = tlac_decide($vec, $vec['request'], $V['now']);
    $results[$vec['id']] = $d;
    $want = $vec['expect']['platform_reason']['php'] ?? $vec['expect']['reason'];
    ck($d['allowed'] === $vec['expect']['allowed'] && $d['reason'] === $want, $vec['id'] . ' ' . $vec['title'], 'got ' . json_encode($d) . ', want ' . json_encode(array('allowed' => $vec['expect']['allowed'], 'reason' => $want)));
}
$save('php-selfverify', array('platform' => 'php-selfverify', 'version' => TOKENLOCK_PHP, 'results' => $results));
echo "Properties P1 removal, P2 corruption, P3 narrowing (seeds " . implode(',', TLPG_SEEDS) . ")\n";
$t0 = microtime(true);
$st = tlpg_run(function ($c, $r) { return tlac_decide($c, $r, TLPG_NOW); });
$st['seconds'] = round(microtime(true) - $t0, 1);
$save('properties-php-selfverify', array_merge(array('platform' => 'php-selfverify', 'version' => TOKENLOCK_PHP), $st));
ck($st['violations_total'] === 0, "no property violations ({$st['evaluations']} evaluations, {$st['mutations']} mutations, {$st['bases']} bases)", $st['violations_total'] . ' violations, e.g. ' . json_encode(array_slice($st['violations'], 0, 3), JSON_UNESCAPED_SLASHES));
echo "input_digest {$st['input_digest']}\nbase_decision_digest {$st['base_decision_digest']}\n";
echo "\n$passed passed, $failed failed\n";
exit($failed ? 1 : 0);
