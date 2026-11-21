<?php
// 0.5.0 RC6 (second reviewer's RC5 finding, reproduced in review): the PHP policy cache must never fall behind the newest
// bundle any request accepted.
//   C1 overlapping refreshes: worker X fetches seq 2000 (key active); before X stores it, worker Y fetches and stores seq
//      3000 (key revoked). RC5: X wrote last, the disk held 2000, later requests allowed the revoked key (and a replayed
//      seq 2500 passed the rollback check). Now: the higher seq wins, X returns 3000.
//   C2 cache write fails: RC5 returned the new (revoked) bundle once but kept the old (active) one on disk, and used it as
//      the fallback during an API outage. Now: with an unwritable cache there is no fallback (policy_unavailable).
//   C3 control: a normal cache still falls back to the newest stored bundle during an outage.
// Failing first on 10cfc26 (RC5).
error_reporting(E_ALL & ~E_DEPRECATED);
require_once dirname(__DIR__) . '/tokenlock/tokenlock.php';
require_once dirname(__DIR__) . '/tokenlock/self-verify.php';
$passed = 0; $failed = 0;
function rk($cond, $name, $detail = '') { global $failed, $passed; if ($cond) { $passed++; echo "  ✔ $name\n"; return; } $failed++; echo "  ✖ $name" . ($detail !== '' ? " — $detail" : '') . "\n"; }
$F = json_decode(file_get_contents(__DIR__ . '/fixtures/rc6-bundles.json'), true);
$B = $F['bundles']; $PK = $F['public_keys']; $ADDR = $F['address'];
function fresh_dir($tag) { $d = sys_get_temp_dir() . '/tl-rc6-' . getmypid() . '-' . $tag; @mkdir($d, 0700, true); foreach (array_merge(glob($d . '/*') ?: array(), glob($d . '/.*') ?: array()) as $f) { if (is_file($f)) { @unlink($f); } } return $d; }
function src($dir, $load) { global $PK; return tokenlock_sv_signed_policy(array('site_id' => 'site1', 'secret_key' => 'sk_x', 'public_keys' => $PK, 'cache_dir' => $dir, 'refresh_seconds' => 60, 'load' => $load)); }
function pget($s) { try { return call_user_func($s); } catch (TokenlockSelfVerifyError $e) { return array('thrown' => $e->tlcode); } }
function decide($p) { global $ADDR; if (isset($p['thrown'])) { return 'thrown ' . $p['thrown']; } $r = tokenlock_sv_evaluate($p, $ADDR, array('CLUB'), array('path' => '/members/x', 'method' => 'GET', 'environment' => 'production')); return $r['allowed'] ? 'allowed' : $r['reason']; }
function cache_file($dir) { $f = glob($dir . '/tokenlock_policy_*.json'); return $f ? $f[0] : null; }
function age_cache($dir) { $f = cache_file($dir); $c = json_decode(file_get_contents($f), true); $c['fetched_at'] -= 3600 * 1000; file_put_contents($f, json_encode($c)); }
function down() { throw new RuntimeException('API down'); }

// C1
$d = fresh_dir('c1');
pget(src($d, function () use ($B) { return $B['active_1000']; })); age_cache($d);
$y = null;
$x = pget(src($d, function () use ($B, $d, &$y) {
    $y = pget(src($d, function () use ($B) { return $B['revoked_3000']; })); // worker Y refreshes and stores first
    return $B['active_2000'];
}));
rk(decide($y) === 'key_revoked', 'C1 worker Y accepts seq 3000 (key revoked)', decide($y));
rk(($x['seq'] ?? null) === 3000 && decide($x) === 'key_revoked', 'C1 worker X, finishing last with seq 2000, returns the newer stored seq 3000', json_encode(array($x['seq'] ?? null, decide($x))));
$c = json_decode(file_get_contents(cache_file($d)), true);
rk(($c['seq'] ?? null) === 3000, 'C1 the cache keeps seq 3000 (never overwritten by the older 2000)', 'cache seq ' . json_encode($c['seq'] ?? null));
$n = pget(src($d, function () { throw new RuntimeException('not called'); }));
rk(decide($n) === 'key_revoked', 'C1 the next request (cache fresh, no refetch) denies the revoked key', decide($n));
age_cache($d);
$r = pget(src($d, function () use ($B) { return $B['active_2500']; }));
rk(($r['thrown'] ?? null) === 'policy_rollback', 'C1 a replayed seq 2500 (older than the accepted 3000) is refused as a rollback', json_encode($r['thrown'] ?? $r['seq'] ?? null));

// C2
$d = fresh_dir('c2');
pget(src($d, function () use ($B) { return $B['active_1000']; })); age_cache($d);
$locked = 'chmod';
@chmod($d, 0555); clearstatcache();
if (is_writable($d)) { @chmod($d, 0700); $locked = (@exec('chattr +i ' . escapeshellarg($d) . ' 2>/dev/null', $o, $rc) !== false && $rc === 0) ? 'chattr' : null; clearstatcache(); }
rk($locked !== null && !is_writable($d), 'C2 setup: the cache directory is not writable (' . ($locked ?? 'could not make it read-only') . ')');
$p = pget(src($d, function () use ($B) { return $B['revoked_3000']; }));
rk(decide($p) === 'key_revoked' || ($p['thrown'] ?? null) === 'policy_cache_failed', 'C2 the refresh to seq 3000 (revoked) either answers with it or fails closed; it never allows', decide($p));
$q = pget(src($d, function () { down(); }));
rk(($q['thrown'] ?? null) === 'policy_unavailable', 'C2 API down afterwards: no fallback to the stale seq 1000 on disk (policy_unavailable)', decide($q));
if ($locked === 'chattr') { @exec('chattr -i ' . escapeshellarg($d)); } else { @chmod($d, 0700); }

// C3 (control)
$d = fresh_dir('c3');
pget(src($d, function () use ($B) { return $B['active_1000']; })); age_cache($d);
pget(src($d, function () use ($B) { return $B['revoked_3000']; })); age_cache($d);
$q = pget(src($d, function () { down(); }));
rk(($q['seq'] ?? null) === 3000 && decide($q) === 'key_revoked', 'C3 control: a writable cache still falls back to the newest stored bundle (seq 3000) during an outage', decide($q));

echo "\n$passed passed, $failed failed\n";
exit($failed ? 1 : 0);
