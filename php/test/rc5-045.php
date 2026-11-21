<?php
// 0.4.5 RC5 (RC3 review), PHP, failing first:
//   H1 client side: tokenlock_sv_signed_policy never accepts a bundle that drops registered-keys mode unless its
//      state_version is higher than the last accepted one (store-loss shape: mode token, keys [], state_version 0).
//   S2 (poc5.php): two keys for one address (or one id) in a policy: policy_invalid, never "first one wins".
// S3 does not apply to PHP (tokenlock_sv_verify_sign_in already answers bad_asset; the review report).
error_reporting(E_ALL & ~E_DEPRECATED);
require_once dirname(__DIR__) . '/tokenlock/tokenlock.php';
require_once dirname(__DIR__) . '/tokenlock/self-verify.php';
$passed = 0; $failed = 0;
function rk($cond, $name, $detail = '') { global $failed, $passed; if ($cond) { $passed++; echo "  ✔ $name\n"; return; } $failed++; echo "  ✖ $name" . ($detail !== '' ? " — $detail" : '') . "\n"; }
$F = json_decode(file_get_contents(__DIR__ . '/fixtures/rc5-bundles.json'), true);
$B = $F['bundles']; $PK = $F['public_keys']; $ADDR = $F['address'];
function src_of($served, $tag) {
    global $PK;
    $dir = sys_get_temp_dir() . '/tl-rc5-' . getmypid() . '-' . $tag; @mkdir($dir, 0700, true); foreach (glob($dir . '/*') ?: array() as $f) { @unlink($f); }
    $n = 0;
    return tokenlock_sv_signed_policy(array('site_id' => 'site1', 'secret_key' => 'sk_x', 'public_keys' => $PK, 'cache_dir' => $dir, 'refresh_seconds' => 0, 'load' => function () use (&$n, $served) { return $served[min($n++, count($served) - 1)]; }));
}
function pget($src) { try { return call_user_func($src); } catch (TokenlockSelfVerifyError $e) { return array('thrown' => $e->tlcode); } }
// H1 client
$s = src_of(array($B['registered_v7_revoked'], $B['token_v0_after_loss']), 'a');
$p1 = pget($s); usleep(2000); $p2 = pget($s);
rk(($p1['mode'] ?? null) === 'registered_keys' && ($p2['mode'] ?? null) !== 'token', 'H1 client: a token bundle with state_version 0 after a registered one (v7) is refused', json_encode(array($p1['mode'] ?? $p1, $p2['mode'] ?? $p2)));
rk(isset($p2['thrown']) && $p2['thrown'] === 'policy_downgrade', 'H1 client: the refusal is policy_downgrade (fails closed, like policy_rollback)', json_encode($p2['thrown'] ?? $p2['mode'] ?? null));
$ok = true; foreach (array('token_v7_same_version', 'token_no_version') as $i => $k) { $s = src_of(array($B['registered_v7_revoked'], $B[$k]), 'b' . $i); pget($s); usleep(2000); $p = pget($s); if (($p['mode'] ?? null) === 'token') { $ok = false; } }
rk($ok, 'H1 client: a token bundle at the same state_version, or without one, is refused');
$prev = tokenlock_sv_verify_policy_bundle($B['registered_v7_revoked'], array('public_keys' => $PK, 'site_id' => 'site1'));
$c = null; try { tokenlock_sv_verify_policy_bundle($B['token_v0_after_loss'], array('public_keys' => $PK, 'site_id' => 'site1', 'previous' => $prev)); } catch (TokenlockSelfVerifyError $e) { $c = $e->tlcode; }
rk($c === 'policy_downgrade', 'H1 client: tokenlock_sv_verify_policy_bundle(previous) refuses the downgrade', (string) $c);
$s = src_of(array($B['registered_v7_revoked'], $B['token_v8_turned_off'], $B['registered_v9_back_on']), 'c');
$m = array(); for ($i = 0; $i < 3; $i++) { $p = pget($s); $m[] = $p['mode'] ?? ('thrown ' . ($p['thrown'] ?? '?')); usleep(2000); }
rk($m === array('registered_keys', 'token', 'registered_keys'), 'H1 client control: a legitimate turn-off (higher state_version) is accepted; turning back on works', json_encode($m));
// S2
$k = array('routes' => array('*'), 'methods' => array('*'), 'environments' => array('*'));
$P = function ($keys) { return array('v' => 1, 'typ' => 'tokenlock.policy', 'site_id' => 's', 'seq' => 1, 'issued_at' => gmdate('Y-m-d\TH:i:s\Z', time() - 10), 'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 600), 'mode' => 'registered_keys', 'orgs' => array(), 'revoked_assets' => array(), 'keys' => $keys); };
$dup = $P(array(array('id' => 'k1', 'address' => 'bc1qx', 'status' => 'active', 'permissions' => $k), array('id' => 'k2', 'address' => 'bc1qx', 'status' => 'revoked', 'permissions' => $k)));
$r = tokenlock_sv_evaluate($dup, 'bc1qx', array('CLUB'), array('path' => '/admin', 'method' => 'POST'));
rk(empty($r['allowed']) && ($r['reason'] ?? '') === 'policy_invalid', 'S2 poc5: duplicate address (active, then revoked) → policy_invalid', json_encode($r));
$r = tokenlock_sv_evaluate($P(array(array('id' => 'k1', 'address' => 'bc1qa', 'status' => 'active', 'permissions' => $k), array('id' => 'k1', 'address' => 'bc1qb', 'status' => 'active', 'permissions' => $k))), 'bc1qa', array('CLUB'), array('path' => '/admin', 'method' => 'POST'));
rk(empty($r['allowed']) && ($r['reason'] ?? '') === 'policy_invalid', 'S2: duplicate key id → policy_invalid', json_encode($r));
$r = tokenlock_sv_evaluate($P(array(array('id' => 'k1', 'address' => 'bc1qabc', 'status' => 'active', 'permissions' => $k), array('id' => 'k2', 'address' => 'BC1QABC', 'status' => 'revoked', 'permissions' => $k))), 'bc1qabc', array('CLUB'), array('path' => '/admin', 'method' => 'POST'));
rk(empty($r['allowed']) && ($r['reason'] ?? '') === 'policy_invalid', 'S2: duplicate address differing only in case → policy_invalid', json_encode($r));
$r = tokenlock_sv_evaluate($P(array(array('id' => 'k1', 'address' => 'bc1qa', 'status' => 'active', 'permissions' => $k), array('id' => 'k2', 'address' => 'bc1qb', 'status' => 'revoked', 'permissions' => $k))), 'bc1qa', array('CLUB'), array('path' => '/admin', 'method' => 'POST'));
rk(!empty($r['allowed']), 'S2 control: distinct addresses and ids still evaluate', json_encode($r));
// RC5 deep review: seq and state_version accept exactly the same values as Node (an integer 0 .. 2^53-1, also written as
// an integral JSON number such as 1e0); PHP accepted 2^53 .. 2^63-1 (Node refuses) and refused 1e0 (Node accepts).
$PV = array('0' => true, '-0' => true, '1e0' => true, '9007199254740991' => true, '9007199254740992' => false, '9223372036854775807' => false, '-1' => false, '1.5' => false, '"3"' => false, 'true' => false, 'null' => false, '1e20' => false);
foreach (array('seq', 'state_version') as $field) {
  $got = array();
  foreach ($PV as $raw => $want) {
    $pol = array('v' => 1, 'typ' => 'tokenlock.policy', 'site_id' => 's', 'seq' => 1, 'issued_at' => '2026-01-01T00:00:00.000Z', 'expires_at' => '2099-01-01T00:00:00.000Z', 'mode' => 'registered_keys', 'orgs' => array(), 'revoked_assets' => array(), 'keys' => array());
    $pol[$field] = json_decode((string) $raw, true);
    $ok = true; try { tokenlock_sv_validate_policy($pol); } catch (Throwable $e) { $ok = false; }
    if ($ok !== $want) $got[] = "$raw: " . ($ok ? 'accepted' : 'refused');
  }
  rk(!$got, "parity: $field accepts exactly what Node accepts", implode(', ', $got));
}
// RC5 deep review: asset-name normalization parity (same table as test/rc5-045.test.mjs and the hosted deep test).
$NT = json_decode('{"pepecash":"PEPECASH"," PEPECASH\\t\\n":"PEPECASH","PEPECASH\\u000b":"PEPECASH","pepecash.Sub":"PEPECASH.Sub","a123456789012":"A123456789012","pepeca\\u017fh":null,"p\\u0131zza":null,"stra\\u00dfe":null,"PEPECASH\\u00a0":null,"\\ufeffPEPECASH":null,"PEPECASH\\u0000":null,"pepecash.\\u017fub":null}', true); $NS = json_decode('[true, ["PEPECASH"], 42, {}, null, ""]', true); $bad = array();
set_error_handler(function ($n, $m) { throw new ErrorException($m); });
foreach ($NT as $raw => $want) { try { $got = tokenlock_sv_normalize_asset((string) $raw); } catch (TokenlockSelfVerifyError $e) { $got = null; } catch (Throwable $e) { $got = 'error ' . $e->getMessage(); } if ($got !== $want) $bad[] = json_encode($raw) . ' -> ' . json_encode($got); }
foreach ($NS as $raw) { try { $got = tokenlock_sv_normalize_asset($raw); } catch (TokenlockSelfVerifyError $e) { $got = null; } catch (Throwable $e) { $got = 'error ' . $e->getMessage(); } if ($got !== null) $bad[] = json_encode($raw) . ' -> ' . json_encode($got); }
restore_error_handler();
rk(!$bad, 'parity: tokenlock_sv_normalize_asset is ASCII-only and string-only', implode(', ', $bad));
echo "$passed passed, $failed failed\n";
exit($failed ? 1 : 0);
