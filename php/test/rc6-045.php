<?php
// 0.4.5 RC6, PHP, failing first on 10cfc26 (same cases as test/rc6-045.test.mjs):
//   S1 option A: "any name on Bitcoin" is a registered name (4-12 letters A-Z, not starting with A) the address OWNS, as on
//      hosted sign-in. RC5 accepted a numeric asset and any positive balance.
//   Site binding: tokenlock_sv_verify_local_pass(..., 'site' => ...) refuses a pass issued for another site (wrong_site).
error_reporting(E_ALL & ~E_DEPRECATED);
require_once dirname(__DIR__) . '/tokenlock/tokenlock.php';
require_once dirname(__DIR__) . '/tokenlock/self-verify.php';
$passed = 0; $failed = 0;
function rk($cond, $name, $detail = '') { global $failed, $passed; if ($cond) { $passed++; echo "  ✔ $name\n"; return; } $failed++; echo "  ✖ $name" . ($detail !== '' ? " — $detail" : '') . "\n"; }
$F = is_file(__DIR__ . '/fixtures/sig-vectors.json') ? __DIR__ . '/fixtures/' : dirname(__DIR__, 2) . '/test/fixtures/';
$SI = json_decode(file_get_contents($F . 'signin-vectors.json'), true); // record: any_name true, assets ['GOTPROOF']; signed by Node
$B = $SI['signers'][1]['address'];
$NUMERIC = 'A' . str_repeat('1', 17);
$signIn = function ($name, $holdings) use ($SI) {
    $store = tokenlock_sv_memory_store();
    call_user_func($store['put'], $SI['record']['nonce'], $SI['record'], $SI['now'] + 600000);
    $in = array('challenge_id' => $SI['record']['nonce'], 'address' => $SI['signers'][1]['address'], 'signature' => $SI['signers'][1]['signature']);
    if ($name !== '__none__') { $in['name'] = $name; }
    try { return tokenlock_sv_verify_sign_in($in, array('store' => $store, 'holdings' => $holdings, 'pass_secret' => $SI['pass_secret']), $SI['now'] + 1000); } catch (Throwable $e) { return array('code' => 'THREW ' . get_class($e)); }
};
$own = function ($names) use ($B) { return tokenlock_sv_static_provider(array(), array($B => $names)); };

$r = $signIn($NUMERIC, tokenlock_sv_static_provider(array($B => array($NUMERIC)), array($B => array($NUMERIC))));
rk($r['code'] === 'bad_name', 'S1: a numeric asset is not "any name" (bad_name), even when owned', $r['code']);
$r = $signIn('PEPECASH.club', $own(array('PEPECASH.club')));
rk($r['code'] === 'bad_name', 'S1: a subasset is not "any name" (bad_name)', $r['code']);
$r = $signIn('PEPECASH', tokenlock_sv_static_provider(array($B => array('PEPECASH'))));
rk($r['code'] === 'not_holder' && empty($r['valid']), 'S1: a balance of a name the wallet does not own is not enough (not_holder)', $r['code']);
$codes = array(); foreach (array('PEPECASH', 'pepecash', " PepeCash\t") as $n) { $codes[] = $signIn($n, $own(array('PEPECASH')))['code']; }
rk($codes === array('ok', 'ok', 'ok'), 'S1: the owner of a registered name signs in (any case, ASCII whitespace trimmed)', json_encode($codes));
$codes = array(); foreach (array('ABCD', 'BCD', 'BCDEFGHIJKLMN', 'B1CD', "pepeca\u{17f}h", 'PEPE CASH', 42, true, array()) as $n) { $codes[] = $signIn($n, $own(array('PEPECASH', 'ABCD')))['code']; }
rk(count(array_unique($codes)) === 1 && $codes[0] === 'bad_name', 'S1: names the hosted rule refuses answer bad_name and never throw', json_encode($codes));
$r = $signIn('__none__', tokenlock_sv_static_provider(array($B => array('GOTPROOF'))));
rk($r['code'] === 'ok', 'S1 control: the site-listed asset (GOTPROOF) still counts with a positive balance', $r['code']);

$secret = str_repeat('s', 40);
$mk = function ($site) use ($secret) { return tokenlock_sv_issue_pass(array('sub' => 'bc1qx', 'h' => array('GOTPROOF'), 'k' => null, 'n' => str_repeat('a', 32), 's' => $site, 'i' => tokenlock_sv_now(), 'e' => tokenlock_sv_now() + 600000), $secret); };
$v = function ($pass, $extra) use ($secret) { return tokenlock_sv_verify_local_pass($pass, array_merge(array('pass_secret' => $secret, 'identity_only' => true), $extra)); };
$r = $v($mk('https://a.example'), array('site' => 'https://b.example'));
rk($r['code'] === 'wrong_site' && $r['valid'] === false, 'site binding: a pass for site A is refused at site B sharing the pass_secret (wrong_site)', $r['code']);
$codes = array(); foreach (array('https://club.example', 'https://CLUB.example/', 'https://club.example:443/x?y=1') as $s) { $codes[] = $v($mk('https://club.example'), array('site' => $s))['code']; }
rk($codes === array('ok', 'ok', 'ok'), 'site binding: the issuing site accepts its own pass (origin compared after normalization)', json_encode($codes));
$codes = array(); foreach (array('', 'not a url', 42, null, 'ftp://a.example', 'ws://a.example', 'file:///etc', 'https://') as $s) { $codes[] = $v($mk('https://a.example'), array('site' => $s))['code']; }
rk(count(array_unique($codes)) === 1 && $codes[0] === 'bad_site', 'site binding: a malformed site option is refused (bad_site)', json_encode($codes));
rk($v($mk('https://a.example'), array())['code'] === 'ok', 'site binding: omitting site keeps RC5 behavior');

echo "\n$passed passed, $failed failed\n";
exit($failed ? 1 : 0);
