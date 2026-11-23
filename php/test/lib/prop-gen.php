<?php
/**
 * PHP port of test/vectors/prop-gen.mjs (AUTHORIZATION-CONTRACT.md §8): same mulberry32 PRNG, seeds, bases, request
 * universe and mutation list, so the generated cases are identical (compare input_digest with the Node run).
 */
const TLPG_SEEDS = array(4572833, 4572834);
const TLPG_BASES = 150;
const TLPG_NOW = '2026-11-19T12:00:00.000Z';
const TLPG_ADDR = 'bc1qpropertykey00000000000000000000000000000';
const TLPG_ABSENT = '__absent__';
function tlpg_imul($a, $b)
{
    $a &= 0xFFFFFFFF; $b &= 0xFFFFFFFF;
    $lo = ($a & 0xFFFF) * $b;
    $hi = (($a >> 16) * $b) & 0xFFFF;
    return ($lo + ($hi << 16)) & 0xFFFFFFFF;
}
function tlpg_rng($seed)
{
    $a = $seed & 0xFFFFFFFF;
    return function () use (&$a) {
        $a = ($a + 0x6D2B79F5) & 0xFFFFFFFF;
        $t = $a;
        $t = tlpg_imul($t ^ ($t >> 15), $t | 1);
        $t = ($t ^ (($t + tlpg_imul($t ^ ($t >> 7), $t | 61)) & 0xFFFFFFFF)) & 0xFFFFFFFF;
        return (($t ^ ($t >> 14)) & 0xFFFFFFFF) / 4294967296;
    };
}
function tlpg_json($v) { return json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION); }
function tlpg_requests()
{
    $out = array();
    foreach (array('/', '/api', '/api/x', '/api/x/y', '/admin', '/admin/users', '/other') as $p) {
        foreach (array('GET', 'POST', 'DELETE') as $m) {
            foreach (array(null, 'production', 'staging') as $e) {
                $out[] = array('resource' => $e === null ? array('path' => $p, 'method' => $m) : array('path' => $p, 'method' => $m, 'environment' => $e));
            }
        }
    }
    $out[] = array('identityOnly' => true);
    return $out;
}
function tlpg_base($rnd)
{
    $int = function ($n) use ($rnd) { return (int) floor($rnd() * $n); };
    $subset = function ($arr) use ($rnd) { $o = array(); foreach ($arr as $x) { if ($rnd() < 0.5) { $o[] = $x; } } return $o; };
    $routes = $subset(array('*', '/*', '/api/*', '/api/x', '/api/', '/admin/*', '/admin', '/'));
    $methods = $subset(array('*', 'GET', 'POST', 'DELETE'));
    $ec = $int(4);
    $envs = $ec === 0 ? array('*') : ($ec === 1 ? array() : ($ec === 2 ? $subset(array('production', 'staging')) : array('production')));
    $assets = $int(3) === 0 ? array('GOODTOKEN') : array();
    $org = $int(2) === 0 ? null : 'org_ok';
    $ex = $int(5);
    $exp = $ex === 0 ? '2026-11-19T13:00:00.000Z' : ($ex === 1 ? '2026-11-19T11:00:00.000Z' : null);
    $held = $int(5) === 0 ? array('GOODTOKEN', 'OTHERTOKEN') : array('GOODTOKEN');
    $status = $int(6) === 0 ? 'revoked' : 'active';
    return array(
        'state' => array('settings' => array('require_org' => false), 'orgs' => array(array('id' => 'org_ok', 'status' => 'approved'), array('id' => 'org_sus', 'status' => 'suspended')), 'revoked_assets' => array('REVOKEDTOKEN')),
        'key' => array('id' => 'key_property01', 'address' => TLPG_ADDR, 'status' => $status, 'owner_type' => 'agent', 'org_id' => $org, 'assets' => $assets, 'expires_at' => $exp,
            'permissions' => array('routes' => $routes, 'methods' => $methods, 'environments' => $envs)),
        'address' => TLPG_ADDR, 'held' => $held,
    );
}
function tlpg_set($base, $path, $val)
{
    $k = $base['key'];
    if (count($path) === 1) {
        if ($val === TLPG_ABSENT) { unset($k[$path[0]]); } else { $k[$path[0]] = $val; }
    } else {
        if (!is_array($k[$path[0]] ?? null)) { return null; }
        if ($val === TLPG_ABSENT) { unset($k[$path[0]][$path[1]]); } else { $k[$path[0]][$path[1]] = $val; }
    }
    $c = $base; $c['key'] = $k;
    return $c;
}
function tlpg_mutations($base)
{
    $out = array();
    $add = function ($cat, $label, $c) use (&$out) { if ($c !== null) { $out[] = array($cat, $label, $c); } };
    $obj = new stdClass();
    foreach (array(array('permissions'), array('permissions', 'routes'), array('permissions', 'methods'), array('permissions', 'environments'), array('status'), array('id'), array('address')) as $p) {
        $add('removal', 'delete key.' . implode('.', $p), tlpg_set($base, $p, TLPG_ABSENT));
    }
    $listBad = array(null, '', 0, 5, true, $obj, 'x', '*', array(5), array(null), array(true), array($obj), array(array('*')));
    foreach (array('routes', 'methods', 'environments') as $f) {
        foreach ($listBad as $v) { $add('corruption', "key.permissions.$f = " . tlpg_json($v), tlpg_set($base, array('permissions', $f), $v)); }
    }
    foreach (array(null, '', 0, true, 'all', array(), array($obj), array('*')) as $v) { $add('corruption', 'key.permissions = ' . tlpg_json($v), tlpg_set($base, array('permissions'), $v)); }
    foreach (array(null, '', 0, 'ACTIVE', 'active ', true, 'approved') as $v) { $add('corruption', 'key.status = ' . tlpg_json($v), tlpg_set($base, array('status'), $v)); }
    foreach (array('garbage', 5, 99999, 1000000000000000, true, $obj, array(), '2999') as $v) { $add('corruption', 'key.expires_at = ' . tlpg_json($v), tlpg_set($base, array('expires_at'), $v)); }
    foreach (array('GOODTOKEN', 5, true, $obj, array(5), array(null)) as $v) { $add('corruption', 'key.assets = ' . tlpg_json($v), tlpg_set($base, array('assets'), $v)); }
    foreach (array(5, true, $obj, array(), array('org_ok')) as $v) { $add('corruption', 'key.org_id = ' . tlpg_json($v), tlpg_set($base, array('org_id'), $v)); }
    foreach (array(null, 'GOODTOKEN', array(5), array(null), $obj) as $v) { $c = $base; $c['held'] = $v; $add('corruption', 'held = ' . tlpg_json($v), $c); }
    $pm = $base['key']['permissions'];
    $without = function ($arr, $i) { $o = array(); foreach ($arr as $j => $x) { if ($j !== $i) { $o[] = $x; } } return $o; };
    foreach ($pm['routes'] as $i => $r) { $add('narrowing', "remove route $r", tlpg_set($base, array('permissions', 'routes'), $without($pm['routes'], $i))); }
    foreach ($pm['methods'] as $i => $m) { $add('narrowing', "remove method $m", tlpg_set($base, array('permissions', 'methods'), $without($pm['methods'], $i))); }
    foreach ($pm['routes'] as $i => $r) { if ($r === '*' || $r === '/*') { $n = $pm['routes']; $n[$i] = '/api/*'; $add('narrowing', "replace route $r with /api/*", tlpg_set($base, array('permissions', 'routes'), $n)); } }
    foreach ($pm['methods'] as $i => $m) { if ($m === '*') { $n = $pm['methods']; $n[$i] = 'GET'; $add('narrowing', 'replace method * with GET', tlpg_set($base, array('permissions', 'methods'), $n)); } }
    $envs = $pm['environments'];
    // contract 1.1 (RC3): [] grants no environment, so [] -> ["production"] is a broadening; any list -> [] narrows (same as prop-gen.mjs).
    if (in_array('*', $envs, true)) { $add('narrowing', 'environments ' . tlpg_json($envs) . ' -> ["production"]', tlpg_set($base, array('permissions', 'environments'), array('production'))); }
    if ($envs) { $add('narrowing', 'environments ' . tlpg_json($envs) . ' -> []', tlpg_set($base, array('permissions', 'environments'), array())); }
    if (count(array_filter($envs, function ($e) { return $e !== '*'; })) >= 2) { foreach ($envs as $i => $e) { $add('narrowing', "remove environment $e", tlpg_set($base, array('permissions', 'environments'), $without($envs, $i))); } }
    if (!$base['key']['assets']) { $add('narrowing', 'key.assets [] -> ["GOODTOKEN"]', tlpg_set($base, array('assets'), array('GOODTOKEN'))); $add('narrowing', 'key.assets [] -> ["OTHERTOKEN"]', tlpg_set($base, array('assets'), array('OTHERTOKEN'))); }
    $c = $base; $c['state']['revoked_assets'] = array('REVOKEDTOKEN', 'GOODTOKEN'); $add('narrowing', 'revoke GOODTOKEN site-wide', $c);
    $add('narrowing', 'expires_at -> past', tlpg_set($base, array('expires_at'), '2026-11-19T11:00:00.000Z'));
    if ($base['key']['expires_at'] === null) { $add('narrowing', 'expires_at null -> later today', tlpg_set($base, array('expires_at'), '2026-11-19T12:30:00.000Z')); }
    foreach (array('revoked', 'pending_approval') as $s) { $add('narrowing', "status -> $s", tlpg_set($base, array('status'), $s)); }
    $add('narrowing', 'org_id -> suspended org', tlpg_set($base, array('org_id'), 'org_sus'));
    if ($base['key']['org_id'] === null) { $c = $base; $c['state']['settings'] = array('require_org' => true); $add('narrowing', 'require_org on', $c); }
    return $out;
}
function tlpg_run($decide)
{
    $req = tlpg_requests();
    $st = array('seeds' => TLPG_SEEDS, 'bases_per_seed' => TLPG_BASES, 'requests' => count($req), 'bases' => 0, 'mutations' => 0, 'evaluations' => 0, 'base_allowed' => 0, 'by_category' => array(), 'violations_total' => 0, 'violations_by_mutation' => array(), 'violations' => array());
    $hIn = hash_init('sha256'); $hOut = hash_init('sha256');
    foreach (TLPG_SEEDS as $seed) {
        $rnd = tlpg_rng($seed);
        for ($b = 0; $b < TLPG_BASES; $b++) {
            $base = tlpg_base($rnd); $st['bases']++;
            hash_update($hIn, tlpg_json($base));
            $ab = array();
            foreach ($req as $r) { $d = $decide($base, $r); $ab[] = $d['allowed'] === true; }
            $st['evaluations'] += count($req);
            $st['base_allowed'] += count(array_filter($ab));
            hash_update($hOut, implode('', array_map(function ($x) { return $x ? '1' : '0'; }, $ab)));
            foreach (tlpg_mutations($base) as $mu) {
                list($cat, $label, $c) = $mu;
                $st['mutations']++;
                if (!isset($st['by_category'][$cat])) { $st['by_category'][$cat] = array('mutations' => 0, 'evaluations' => 0, 'violations' => 0); }
                $st['by_category'][$cat]['mutations']++;
                hash_update($hIn, $cat . $label);
                foreach ($req as $i => $r) {
                    $st['by_category'][$cat]['evaluations']++; $st['evaluations']++;
                    try { $d = $decide($c, $r); } catch (Throwable $e) { $d = array('allowed' => false, 'reason' => 'threw:' . $e->getMessage()); }
                    if ($d['allowed'] === true && !$ab[$i]) {
                        $st['by_category'][$cat]['violations']++; $st['violations_total']++; $st['violations_by_mutation'][$label] = ($st['violations_by_mutation'][$label] ?? 0) + 1;
                        if (count($st['violations']) < 20) { $st['violations'][] = array('seed' => $seed, 'base' => $b, 'category' => $cat, 'mutation' => $label, 'request' => $r, 'reason' => $d['reason']); }
                    }
                }
            }
        }
    }
    $st['input_digest'] = hash_final($hIn); $st['base_decision_digest'] = hash_final($hOut);
    return $st;
}
