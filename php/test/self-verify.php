<?php
/**
 * Self-verify (0.3.0) tests against the shared fixtures (same files as the Node SDK).
 * Run: php test/self-verify.php   (needs GMP)
 */
error_reporting(E_ALL);
require_once dirname(__DIR__) . '/tokenlock/self-verify.php';

$failed = 0;
$passed = 0;
function ok($cond, $name, $detail = '')
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
function same($a, $b, $name)
{
    ok($a === $b, $name, 'got ' . var_export($a, true) . ' expected ' . var_export($b, true));
}
function throws_code($fn, $code, $name)
{
    try {
        $fn();
        ok(false, $name, 'no exception');
    } catch (TokenlockSelfVerifyError $e) {
        same($e->tlcode, $code, $name);
    }
}
// Shared fixtures: next to this test (standalone package) or in the SDK repo's test/fixtures (php/ inside the repo).
$F = is_file(dirname(__FILE__) . '/fixtures/sig-vectors.json') ? dirname(__FILE__) . '/fixtures/' : dirname(__DIR__, 2) . '/test/fixtures/';
$VEC = json_decode(file_get_contents($F . 'sig-vectors.json'), true)['vectors'];
$PB = json_decode(file_get_contents($F . 'policy-bundle.json'), true);
$SI = json_decode(file_get_contents($F . 'signin-vectors.json'), true);

echo "signatures (same answers as the hosted check)\n";
$bad = array();
$kinds = array();
foreach ($VEC as $v) {
    $got = tokenlock_verify_message_signature($v['address'], $v['message'], $v['signature']);
    if ($got !== $v['valid']) {
        $bad[] = $v['kind'];
    }
    if ($v['valid']) {
        $kinds[preg_replace('/-h\d+$/', '', $v['kind'])] = true;
    }
}
ok(!$bad, count($VEC) . ' vectors match', implode(',', array_slice($bad, 0, 10)));
foreach (array('bip322-p2wpkh', 'bip322-p2sh', 'bip322-p2tr', 'legacy-p2pkh', 'legacy-p2pkh_u', 'legacy-p2wpkh', 'legacy-p2sh', 'legacy-p2tr') as $k) {
    ok(isset($kinds[$k]), "covers valid $k");
}
same(tokenlock_verify_message_signature('bc1qnope', 'x', 'AAAA'), false, 'bad address is false, no throw');
same(tokenlock_sv_build_message($SI['record']), $SI['message'], 'message format matches Node byte for byte');

echo "policy bundle (BIP-340)\n";
$keys = array($PB['kid'] => $PB['public_key']);
$opts = array('public_keys' => $keys, 'site_id' => 'site_fixture', 'now' => $PB['now'] + 1000);
$pol = tokenlock_sv_verify_policy_bundle($PB['bundle'], $opts);
same($pol['seq'], 7, 'verifies the Node/site-signed fixture');
same(tokenlock_sv_verify_policy_bundle($PB['bundle'], array('public_keys' => array($PB['public_key'])) + $opts)['site_id'], 'site_fixture', 'list of pinned keys works');
$t = $PB['bundle'];
$t['payload'] = tokenlock_sv_b64url(str_replace('"revoked"', '"active"', tokenlock_sv_b64url_decode($t['payload'])));
throws_code(function () use ($t, $opts) {
    tokenlock_sv_verify_policy_bundle($t, $opts);
}, 'policy_bad_signature', 'tampered payload (revoked→active) rejected');
$t = $PB['bundle'];
$t['sig'] = substr($t['sig'], 0, -2) . (substr($t['sig'], -2) === '00' ? '01' : '00');
throws_code(function () use ($t, $opts) {
    tokenlock_sv_verify_policy_bundle($t, $opts);
}, 'policy_bad_signature', 'tampered signature rejected');
throws_code(function () use ($PB, $opts) {
    tokenlock_sv_verify_policy_bundle($PB['bundle'], array('public_keys' => array('nope' => str_repeat('ab', 32))) + $opts);
}, 'policy_untrusted_key', 'unknown kid rejected');
throws_code(function () use ($PB, $opts) {
    tokenlock_sv_verify_policy_bundle($PB['bundle'], array('site_id' => 'other') + $opts);
}, 'policy_wrong_site', 'other site rejected');
throws_code(function () use ($PB, $opts) {
    tokenlock_sv_verify_policy_bundle($PB['bundle'], array('now' => $PB['now'] + 601000) + $opts);
}, 'policy_expired', 'expired bundle fails closed');
throws_code(function () use ($PB, $opts) {
    tokenlock_sv_verify_policy_bundle($PB['bundle'], array('min_seq' => 8) + $opts);
}, 'policy_rollback', 'rollback (older seq) rejected');

echo "access rules (same as hosted)\n";
$ev = function ($addr, $res, $held = array('GOTPROOF')) use ($pol, $PB) {
    return tokenlock_sv_evaluate($pol, $addr, $held, $res, $PB['now'])['reason'];
};
same($ev('bc1qfixtureaddressa', array('path' => '/api/x', 'method' => 'GET', 'environment' => 'production')), 'ok', 'agent key on allowed route');
same($ev('bc1qfixtureaddressa', array('path' => '/API//x/', 'method' => 'get', 'environment' => 'production')), 'ok', 'case + slashes canonicalized');
same($ev('bc1qfixtureaddressa', array('path' => '/admin', 'method' => 'GET', 'environment' => 'production')), 'route_not_allowed', 'other route');
same($ev('bc1qfixtureaddressa', array('path' => '/api/../admin', 'method' => 'GET', 'environment' => 'production')), 'bad_path', 'dot-dot rejected (path rules v1.1)');
same($ev('bc1qfixtureaddressa', array('path' => '/api/x', 'method' => 'POST', 'environment' => 'production')), 'method_not_allowed', 'method');
same($ev('bc1qfixtureaddressa', array('path' => '/api/x', 'method' => 'GET', 'environment' => 'staging')), 'environment_not_allowed', 'environment');
same($ev('bc1qfixtureaddressa', array('path' => '/api%2f..%2fadmin', 'method' => 'GET')), 'bad_path', 'encoded slash is bad_path');
same($ev('bc1qfixtureaddressa', array('path' => '/api/x', 'method' => 'GET'), array('OLDTOKEN')), 'entitlement_revoked', 'revoked asset');
// 0.4.4: identity is explicit (array('identity_only' => true)); a null resource is bad_resource.
same($ev('bc1qfixtureaddressr', array('identity_only' => true)), 'key_revoked', 'revoked key');
same($ev('bc1qsomeoneelse', array('identity_only' => true)), 'not_registered', 'unknown wallet');

echo "challenge + nonce store (replay)\n";
$dir = sys_get_temp_dir() . '/tokenlock-sv-' . getmypid();
$store = tokenlock_sv_file_store($dir);
$c = tokenlock_sv_create_challenge(array('site' => 'https://Shop.Example/path?q=1', 'assets' => array('gotproof'), 'store' => $store));
same($c['origin'], 'https://shop.example', 'site reduced to origin');
same($c['assets'], array('GOTPROOF'), 'asset normalized');
ok(strpos($c['message'], "Nonce: {$c['challenge_id']}\n") !== false && strpos($c['message'], 'Via: self-verify') !== false, 'message carries nonce and mode');
throws_code(function () use ($store) {
    tokenlock_sv_create_challenge(array('site' => 'https://x.example', 'store' => $store));
}, 'asset_required', 'asset or any_name required');
throws_code(function () use ($store) {
    tokenlock_sv_create_challenge(array('site' => 'nope', 'assets' => array('GOTPROOF'), 'store' => $store));
}, 'bad_site', 'bad site');
$r1 = call_user_func($store['take'], $c['challenge_id']);
$r2 = call_user_func($store['take'], $c['challenge_id']);
ok(is_array($r1) && $r2 === null, 'file store take is single use');
same(call_user_func($store['take'], '../../etc/passwd'), null, 'store rejects non-hex ids');

echo "sign-in (fixture signed by Node)\n";
$store = tokenlock_sv_memory_store(); // fixture times are fixed in the past; the file store also checks the real clock
$A = $SI['signers'][0]['address'];
$B = $SI['signers'][1]['address'];
$secret = $SI['pass_secret'];
$put = function ($st) use ($SI) {
    call_user_func($st['put'], $SI['record']['nonce'], $SI['record'], $SI['now'] + 600000);
};
$cfg = function ($extra = array()) use (&$store, $A, $B, $secret) {
    return array_merge(array('store' => $store, 'holdings' => tokenlock_sv_static_provider(array($A => array('GOTPROOF'), $B => array('PEPECASH'))), 'pass_secret' => $secret), $extra);
};
$in = function ($i, $extra = array()) use ($SI) {
    return array_merge(array('challenge_id' => $SI['record']['nonce'], 'address' => $SI['signers'][$i]['address'], 'signature' => $SI['signers'][$i]['signature']), $extra);
};
$put($store);
$r = tokenlock_sv_verify_sign_in($in(0), $cfg(), $SI['now'] + 1000);
same($r['code'], 'ok', 'p2wpkh holder signs in');
ok(strpos($r['pass'], 'tl3.') === 0, 'local pass issued');
same(tokenlock_sv_verify_sign_in($in(0), $cfg(), $SI['now'] + 2000)['code'], 'unknown_challenge', 'replay of the same nonce rejected');
$put($store);
same(tokenlock_sv_verify_sign_in($in(0), $cfg(), $SI['now'] + 601000)['code'], 'expired', 'expired challenge');
same(tokenlock_sv_verify_sign_in($in(0), $cfg(), $SI['now'] + 1000)['code'], 'unknown_challenge', 'expired attempt still consumed the nonce');
$put($store);
same(tokenlock_sv_verify_sign_in($in(0, array('address' => $B)), $cfg(), $SI['now'] + 1000)['code'], 'bad_signature', 'signature for another address');
$put($store);
same(tokenlock_sv_verify_sign_in($in(1), $cfg(), $SI['now'] + 1000)['code'], 'not_holder', 'p2tr signer without the token');
$put($store);
// RC6 (S1 option A, U16): the name must be OWNED. A balance of it is not enough (hosted parity).
same(tokenlock_sv_verify_sign_in($in(1, array('name' => 'pepecash')), $cfg(), $SI['now'] + 1000)['code'], 'not_holder', 'any_name: p2tr with only a balance of the named asset is not a holder of a name');
$put($store);
same(tokenlock_sv_verify_sign_in($in(1, array('name' => 'pepecash')), $cfg(array('holdings' => tokenlock_sv_static_provider(array($A => array('GOTPROOF')), array($B => array('PEPECASH'))))), $SI['now'] + 1000)['code'], 'ok', 'any_name: p2tr owner of the named asset');
$put($store);
$down = function () {
    throw new TokenlockSelfVerifyError('lookup_failed', 'down', 502);
};
same(tokenlock_sv_verify_sign_in($in(0), $cfg(array('holdings' => $down)), $SI['now'] + 1000)['code'], 'lookup_failed', 'holdings outage fails closed');
$put($store);
same(tokenlock_sv_verify_sign_in($in(0), $cfg(array('holdings' => tokenlock_sv_first_available(array($down, tokenlock_sv_static_provider(array($A => array('GOTPROOF'))))))), $SI['now'] + 1000)['code'], 'ok', 'first_available falls through');
$put($store);
same(tokenlock_sv_verify_sign_in($in(0), $cfg(array('holdings' => tokenlock_sv_require_agreement(array(tokenlock_sv_static_provider(array($A => array('GOTPROOF'))), tokenlock_sv_static_provider(array()))))), $SI['now'] + 1000)['code'], 'lookup_disagreement', 'require_agreement fails closed on disagreement');
$polLocal = tokenlock_sv_local_policy(array('keys' => array(array('id' => 'key_a', 'address' => $A, 'status' => 'active', 'owner_type' => 'agent', 'permissions' => array('routes' => array('/api/*'), 'methods' => array('GET'), 'environments' => array('*')))), 'settings' => array('agent_pass_ttl_s' => 120)));
$put($store);
$r = tokenlock_sv_verify_sign_in($in(0), $cfg(array('policy' => $polLocal)), $SI['now'] + 1000);
same(array($r['code'], $r['key_id'], $r['expires_at']), array('ok', 'key_a', tokenlock_sv_iso($SI['now'] + 1000 + 120000)), 'registered key: bound key id, agent pass TTL');
$put($store);
$broken = function () {
    throw new TokenlockSelfVerifyError('policy_expired', 'old', 503);
};
same(tokenlock_sv_verify_sign_in($in(0), $cfg(array('policy' => $broken)), $SI['now'] + 1000)['code'], 'policy_expired', 'policy outage fails closed');

echo "local pass\n";
$v = tokenlock_sv_verify_local_pass($SI['node_pass']['token'], array('pass_secret' => $secret, 'identity_only' => true, 'now' => $SI['now'] + 1000));
same(array($v['valid'], $v['address'], $v['key_id']), array(true, $A, 'key_a'), 'pass issued by Node verifies in PHP');
same(tokenlock_sv_verify_local_pass($SI['node_pass']['token'], array('pass_secret' => str_repeat('z', 40), 'identity_only' => true, 'now' => $SI['now']))['code'], 'bad_pass', 'wrong secret');
same(tokenlock_sv_verify_local_pass($SI['node_pass']['token'], array('pass_secret' => $secret, 'identity_only' => true, 'now' => $SI['now'] + 301000))['code'], 'expired', 'expired pass');
$parts = explode('.', $SI['node_pass']['token']);
$forged = 'tl3.' . tokenlock_sv_b64url(str_replace('GOTPROOF', 'GOTPROOX', tokenlock_sv_b64url_decode($parts[1]))) . '.' . $parts[2];
same(tokenlock_sv_verify_local_pass($forged, array('pass_secret' => $secret, 'identity_only' => true, 'now' => $SI['now']))['code'], 'bad_pass', 'edited pass body');
$withPol = array('pass_secret' => $secret, 'now' => $SI['now'] + 1000, 'policy' => $polLocal);
same(tokenlock_sv_verify_local_pass($SI['node_pass']['token'], $withPol + array('resource' => array('path' => '/api/data', 'method' => 'GET')))['code'], 'ok', 'policy + resource allowed');
$x = tokenlock_sv_verify_local_pass($SI['node_pass']['token'], $withPol + array('resource' => array('path' => '/admin', 'method' => 'GET')));
same(array($x['valid'], $x['allowed'], $x['code']), array(true, false, 'route_not_allowed'), 'out-of-scope route: valid but not allowed (403)');
$revoked = tokenlock_sv_local_policy(array('keys' => array(array('id' => 'key_a', 'address' => $A, 'status' => 'revoked'))));
same(tokenlock_sv_verify_local_pass($SI['node_pass']['token'], array('policy' => $revoked) + $withPol + array('identity_only' => true))['code'], 'key_revoked', 'revocation in the policy kills a live pass');
// advisory 2026-11-18: a resource is allowed only when a route policy explicitly permits it (PHP 0.4.0)
$noPol = array('pass_secret' => $secret, 'now' => $SI['now'] + 1000);
foreach (array(array('path' => '/admin', 'method' => 'POST'), array('path' => '/api/data', 'method' => 'GET'), array('path' => '/x', 'method' => 'DELETE', 'environment' => 'production')) as $res) {
    $x = tokenlock_sv_verify_local_pass($SI['node_pass']['token'], $noPol + array('resource' => $res));
    same(array($x['valid'], $x['allowed'], $x['code'], $x['identity_valid'], $x['address']), array(false, false, 'policy_required', true, $A), 'resource without a policy → policy_required: ' . json_encode($res));
}
same(tokenlock_sv_verify_local_pass($SI['node_pass']['token'], $noPol + array('identity_only' => true))['code'], 'ok', 'identity-only check without a policy still works (explicit since 0.4.3)');
same(tokenlock_sv_verify_local_pass($SI['node_pass']['token'], $noPol)['code'], 'bad_resource', '0.4.3: no resource and no identity_only is refused');
same(tokenlock_sv_verify_local_pass($SI['node_pass']['token'], $noPol + array('resource' => null))['code'], 'bad_resource', '0.4.3: resource => null is refused (identity-only must be explicit)');
same(tokenlock_sv_verify_local_pass($forged, $noPol + array('resource' => array('path' => '/a', 'method' => 'GET')))['code'], 'bad_pass', 'forged pass reported before the policy check');
$tokenMode = tokenlock_sv_local_policy(array('mode' => 'token'));
$x = tokenlock_sv_verify_local_pass($SI['node_pass']['token'], array('policy' => $tokenMode) + $withPol + array('resource' => array('path' => '/api/data', 'method' => 'GET')));
same(array($x['valid'], $x['allowed'], $x['code'], $x['identity_valid']), array(false, false, 'policy_required', true), 'token-mode policy + resource → policy_required');
same(tokenlock_sv_verify_local_pass($SI['node_pass']['token'], array('policy' => $tokenMode) + $withPol + array('identity_only' => true))['code'], 'ok', 'token-mode policy, identity-only → ok');
$other = tokenlock_sv_local_policy(array('keys' => array(array('id' => 'key_b', 'address' => $A, 'status' => 'active'))));
same(tokenlock_sv_verify_local_pass($SI['node_pass']['token'], array('policy' => $other) + $withPol + array('identity_only' => true))['code'], 'not_registered', 'pass bound to its key id');
throws_code(function () {
    tokenlock_sv_issue_pass(array('sub' => 'x', 'e' => 1), 'short');
}, 'bad_secret', 'short pass secret refused');
$php = tokenlock_sv_issue_pass(array('sub' => $A, 'h' => array('GOTPROOF'), 'k' => null, 'n' => 'n', 's' => 'https://shop.example', 'i' => $SI['now'], 'e' => $SI['now'] + 60000), $secret);
$sdk = getenv('TOKENLOCK_SDK_DIR') ?: (is_file(dirname(__DIR__, 2) . '/dist/self-verify.js') ? dirname(__DIR__, 2) : dirname(__DIR__, 2) . '/tokenlock-sdk');
if (is_file($sdk . '/dist/self-verify.js')) {
    $js = "import('" . $sdk . "/dist/self-verify.js').then(async S=>{const r=await S.verifyLocalPass(process.argv[1],{passSecret:process.argv[2],identityOnly:true,now:" . ($SI['now'] + 1000) . "});console.log(r.code)})";
    $o = trim((string) shell_exec('node -e ' . escapeshellarg($js) . ' ' . escapeshellarg($php) . ' ' . escapeshellarg($secret) . ' 2>&1'));
    same($o, 'ok', 'pass issued by PHP verifies in Node');
} else {
    echo "  - (Node SDK not found: PHP→Node pass check SKIPPED)\n";
    if (getenv('TL_CI') === '1') { // RC5 runner audit (disclosed): a skip fails in CI mode
        same('skipped', 'ran', 'TL_CI=1: PHP→Node pass check must run (set TOKENLOCK_SDK_DIR to a built SDK)');
    }
}

echo "signed policy source (disk cache, refresh, fail closed)\n";
$cache = $dir . '/cache';
@mkdir($cache, 0700, true);
$loads = 0;
$serve = $PB['bundle'];
$fail = false;
$src = function ($refresh) use (&$loads, &$serve, &$fail, $cache, &$keys) {
    return tokenlock_sv_signed_policy(array('site_id' => 'site_fixture', 'public_keys' => $keys, 'cache_dir' => $cache, 'refresh_seconds' => $refresh,
        'load' => function () use (&$loads, &$serve, &$fail) {
            $loads++;
            if ($fail) {
                throw new RuntimeException('down');
            }
            return $serve;
        }));
};
// The fixture expires at a fixed time; only run while it would still be fresh in tests, using a fresh self-signed bundle otherwise.
$sk = gmp_init('1f' . str_repeat('3c', 31), 16);
$P = TokenlockSecp::mul2($sk, TokenlockSecp::G());
$pubx = TokenlockSecp::bytes32($P[0]);
$sign = function ($payload) use ($sk, $P, $pubx) {
    // BIP-340 sign (test only; deterministic nonce is fine here)
    $n = TokenlockSecp::$n;
    $d = gmp_intval(gmp_mod($P[1], 2)) ? gmp_sub($n, $sk) : $sk;
    $msg = tokenlock_tagged_hash('TOKENLOCK/policy/v1', $payload);
    $k0 = gmp_mod(TokenlockSecp::int(tokenlock_tagged_hash('BIP0340/nonce', TokenlockSecp::bytes32($d) . $pubx . $msg)), $n);
    $R = TokenlockSecp::mul2($k0, TokenlockSecp::G());
    $k = gmp_intval(gmp_mod($R[1], 2)) ? gmp_sub($n, $k0) : $k0;
    $rx = TokenlockSecp::bytes32($R[0]);
    $e = gmp_mod(TokenlockSecp::int(tokenlock_tagged_hash('BIP0340/challenge', $rx . $pubx . $msg)), $n);
    return bin2hex($rx . TokenlockSecp::bytes32(gmp_mod(gmp_add($k, gmp_mul($e, $d)), $n)));
};
$mk = function ($seq, $ttl, $mode = 'registered_keys', $sv = null) use ($sign) {
    $now = tokenlock_sv_now();
    $pa = array('v' => 1, 'typ' => 'tokenlock.policy', 'site_id' => 'site_fixture', 'seq' => $seq, 'issued_at' => tokenlock_sv_iso($now), 'expires_at' => tokenlock_sv_iso($now + $ttl * 1000),
        'mode' => $mode, 'orgs' => array(), 'revoked_assets' => array(), 'keys' => array());
    if ($sv !== null) {
        $pa['state_version'] = $sv; // 0.4.5 RC5: a mode drop needs a higher state_version (H1 client guard)
    }
    $p = tokenlock_sv_json($pa);
    return array('v' => 1, 'typ' => 'tokenlock.policy-bundle', 'alg' => 'BIP340', 'kid' => 'tk', 'payload' => tokenlock_sv_b64url($p), 'sig' => $sign($p));
};
$keys = array('tk' => bin2hex($pubx));
$serve = $mk(10, 600);
same(tokenlock_sv_verify_policy_bundle($serve, array('public_keys' => $keys, 'site_id' => 'site_fixture'))['seq'], 10, 'PHP-made BIP-340 signature verifies (round trip)');
$s = $src(60);
same($s()['seq'], 10, 'first get loads');
$s2 = $src(60);
same(array($s2()['seq'], $loads), array(10, 1), 'next request (new source) reads the disk cache, no fetch');
$fail = true;
$s0 = $src(0);
same(array($s0()['seq'], $loads), array(10, 2), 'refresh fails: cached bundle still used until it expires');
$fail = false;
$serve = $mk(9, 600);
throws_code(function () use ($s0) {
    $s0();
}, 'policy_rollback', 'older seq from the endpoint rejected');
$serve = $mk(11, 600, 'token', 1); // RC5: was $mk(11, 600, 'token') — a registered→token drop now needs a newer state_version
same($s0()['mode'], 'token', 'newer bundle replaces cache');
// expired cache + endpoint down = fail closed
file_put_contents(glob($cache . '/tokenlock_policy_*.json')[0], tokenlock_sv_json(array('bundle' => $mk(12, -1), 'seq' => 12, 'fetched_at' => 0)));
$fail = true;
throws_code(function () use ($s0) {
    $s0();
}, 'policy_unavailable', 'expired cache + endpoint down fails closed');

echo "providers\n";
$http = function ($routes) {
    return function ($url, $headers, $timeout) use ($routes) {
        foreach ($routes as $pat => $resp) {
            if (strpos($url, $pat) !== false) {
                if ($resp === 'throw') {
                    throw new RuntimeException('net');
                }
                return $resp;
            }
        }
        return array(404, array('error' => 'not found'));
    };
};
$ts = tokenlock_sv_tokenscan_provider(array('http' => $http(array(
    '/asset/GOTPROOF' => array(200, array('asset' => 'GOTPROOF', 'owner' => 'bc1qowner')),
    '/asset/CLUBTOKEN' => array(200, array('asset' => 'CLUBTOKEN', 'owner' => 'bc1qsomeone')),
    '/asset/NOPE' => array(200, array('error' => 'Asset not found')),
    '/balances/bc1qholder/1/500' => array(200, array('data' => array(array('asset' => 'CLUBTOKEN', 'quantity' => '5')))),
    '/balances/bc1qowner/1/500' => array(200, array('data' => array())),
))));
$h = $ts('bc1qholder', array('GOTPROOF', 'CLUBTOKEN', 'NOPE'));
same(array($h['GOTPROOF']['held'], $h['CLUBTOKEN']['held'], $h['CLUBTOKEN']['how'], $h['NOPE']['exists']), array(false, true, 'balance', false), 'tokenscan: balance, not owner, missing asset');
same($ts('bc1qowner', array('GOTPROOF'))['GOTPROOF']['how'], 'owner', 'tokenscan: owner holds');
throws_code(function () use ($http) {
    $p = tokenlock_sv_tokenscan_provider(array('http' => $http(array('/asset/' => array(500, null)))));
    $p('bc1q', array('GOTPROOF'));
}, 'lookup_failed', 'tokenscan 500 fails closed');
$hp = tokenlock_sv_http_json_provider(array('url' => 'https://node.example/bal/{address}/{asset}', 'quantity' => function ($b) {
    return $b['qty'] ?? null;
}, 'http' => $http(array('/bal/bc1qa/GOTPROOF' => array(200, array('qty' => 2)), '/bal/bc1qa/ZERO' => array(200, array('qty' => 0)), '/bal/bc1qa/WEIRD' => array(200, array('x' => 1))))));
$h = $hp('bc1qa', array('GOTPROOF', 'ZERO'));
same(array($h['GOTPROOF']['held'], $h['ZERO']['held']), array(true, false), 'http_json: quantity > 0');
throws_code(function () use ($hp) {
    $hp('bc1qa', array('WEIRD'));
}, 'lookup_failed', 'http_json: unreadable answer fails closed');
$pr = tokenlock_sv_proveitonchain_provider(array('http' => $http(array('/api/v1/tokenlock/holdings?address=bc1qa&assets=GOTPROOF%2CNOPE' => array(200, array('holdings' => array('GOTPROOF' => array('held' => true, 'how' => 'balance'))))))));
$h = $pr('bc1qa', array('GOTPROOF', 'NOPE'));
same(array($h['GOTPROOF']['held'], $h['NOPE']['held']), array(true, false), 'proveitonchain provider');
throws_code(function () use ($http) {
    $p = tokenlock_sv_proveitonchain_provider(array('http' => $http(array('/holdings' => 'throw'))));
    $p('bc1qa', array('GOTPROOF'));
}, 'lookup_failed', 'proveitonchain provider down fails closed');

// cleanup
foreach (array_merge(glob($dir . '/cache/*') ?: array(), glob($dir . '/*') ?: array()) as $f) {
    is_file($f) && @unlink($f);
}
@rmdir($dir . '/cache');
@rmdir($dir);
echo "\n$passed passed, $failed failed\n";
exit($failed ? 1 : 0);
