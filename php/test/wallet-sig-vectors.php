<?php
// 0.5.4: the PHP verifier against the shared wallet-signature vectors (test/fixtures/wallet-sig-vectors.json, the same file
// the TypeScript SDK and the hosted TOKENLOCK check are tested against). Every non-slot vector must give the same answer.
// Run: php php/test/wallet-sig-vectors.php (needs GMP). Offline, throwaway keys plus the public Freewallet vector.
require_once dirname(__DIR__) . '/tokenlock/btcsig.php';

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

echo "wallet signature vectors (PHP)\n";
$raw = file_get_contents(dirname(__DIR__, 2) . '/test/fixtures/wallet-sig-vectors.json');
$doc = json_decode($raw, true);
ok(is_array($doc) && $doc['version'] === 1, 'vector file loads (version 1)');

$slots = 0;
$wrong = array();
$n = 0;
foreach ($doc['vectors'] as $v) {
    if ($v['source'] === 'slot') {
        $slots++;
        continue;
    }
    $n++;
    $got = tokenlock_verify_message_signature($v['address'], $v['message'], $v['signature']);
    if ($got !== $v['valid']) {
        $wrong[] = $v['id'] . ' (want ' . var_export($v['valid'], true) . ')';
    }
}
ok($n >= 80, "at least 80 non-slot vectors ($n)");
ok($slots === 2, 'Electrum and Sparrow slots present and skipped');
ok(count($wrong) === 0, 'tokenlock_verify_message_signature agrees with every non-slot vector', implode(', ', $wrong));

$addr = '13Hnmhs5gy2yXKVBx4wSM5HCBdKnaSBZJH';
$sig = 'H+Xyciqy//n27mlTymwBBeFz5wNeTqZKNhqW9ASfcSNqS5FXUn/4D0tJ2m9HHRxOtVZrbJ3gWNn8S6KAoZOtXQs=';
$lines = array('Sign in with your Token', 'Site: https://pepeproject.com', 'Requires: TOKENLOCK', 'Via: tokenlock.ai', 'Nonce: 396555173588b1f81ef0a69a2af927f7',
    'Issued: 2026-11-25T15:10:10.816Z', 'Expires: 2026-11-25T15:20:10.816Z', 'Signing proves you control this address. It moves no funds.');
$lf = implode("\n", $lines);
$crlf = implode("\r\n", $lines);
ok(tokenlock_verify_message_signature($addr, $lf, $sig) === true, 'Freewallet: LF challenge verifies');
ok(tokenlock_verify_message_signature($addr, $crlf, $sig) === true, 'Freewallet: CRLF form verifies');
ok(tokenlock_verify_message_signature($addr, $lf . "\n", $sig) === false, 'trailing LF on the message fails');
ok(tokenlock_verify_message_signature($addr, $lf . ' ', $sig) === false, 'trailing space on the message fails');
ok(tokenlock_verify_message_signature($addr, $lf, bin2hex(base64_decode($sig))) === true, 'hex signature verifies');
ok(tokenlock_verify_message_signature($addr, $lf, '0x' . strtoupper(bin2hex(base64_decode($sig)))) === true, '0x upper-case hex verifies');
ok(tokenlock_verify_message_signature($addr, $lf, null) === false && tokenlock_verify_message_signature($addr, null, $sig) === false, 'null input is false, no throw');
$bad = 0;
for ($h = 0; $h < 256; $h++) {
    if ($h >= 27 && $h <= 42) {
        continue;
    }
    $x = base64_decode($sig);
    $x[0] = chr($h);
    if (tokenlock_verify_message_signature($addr, $lf, base64_encode($x))) {
        $bad++;
    }
}
ok($bad === 0, 'headers outside 27-42 never verify');
ok(tokenlock_verify_message_signature($addr, $lf, substr($sig, 0, 40) . "\x85" . substr($sig, 40)) === false, 'a raw 0x85 byte inside the signature is not whitespace');
ok(tokenlock_verify_message_signature($addr, $lf, substr($sig, 0, 40) . "\x0B\x0C" . substr($sig, 40)) === true, 'VT and FF inside the signature are whitespace');


// Named format problems (0.5.4): the same codes as the hosted check, for every vector.
$fwrong = array();
foreach ($doc['vectors'] as $v) {
    if ($v['source'] === 'slot') {
        continue;
    }
    $f = tokenlock_signature_format_problem($v['address'], $v['signature']);
    if ($f !== $v['format']) {
        $fwrong[] = $v['id'] . ' (got ' . var_export($f, true) . ' want ' . var_export($v['format'], true) . ')';
    }
}
ok(count($fwrong) === 0, 'tokenlock_signature_format_problem names the expected format for every vector', implode(', ', $fwrong));
$codes = array_keys(tokenlock_format_problems());
$covered = array();
foreach ($doc['vectors'] as $v) {
    if ($v['format'] !== null) {
        $covered[$v['format']] = true;
    }
}
ok(count(array_diff($codes, array_keys($covered))) === 0, 'every format code is covered by a vector');

// The real Freewallet signature passes the strict rules; its lenient variants are named.
$byId = array();
foreach ($doc['vectors'] as $v) {
    $byId[$v['id']] = $v;
}
ok(preg_match('/^[A-Za-z0-9+\/]{86}[A-Za-z0-9+\/=]=$/', $byId['freewallet-crlf-p2pkh-h31']['signature']) === 1, 'Freewallet: standard padded base64');
foreach (array('freewallet-crlf-p2pkh-h31', 'freewallet-crlf-p2pkh-h31-given-crlf', 'freewallet-strict-hex', 'freewallet-strict-wrapped') as $id) {
    $v = $byId[$id];
    ok(tokenlock_verify_message_signature($v['address'], $v['message'], $v['signature']) === true && tokenlock_signature_format_problem($v['address'], $v['signature']) === null, "Freewallet must-pass: $id");
}
foreach (array('freewallet-unpadded', 'freewallet-urlsafe') as $id) {
    $v = $byId[$id];
    ok(tokenlock_verify_message_signature($v['address'], $v['message'], $v['signature']) === false && tokenlock_signature_format_problem($v['address'], $v['signature']) === 'base64_variant', "Freewallet lenient variant named: $id");
}

// Sign-in result: a format refusal carries signature_format and says so.
require_once dirname(__DIR__) . '/tokenlock/self-verify.php';
$SI = json_decode(file_get_contents(dirname(__DIR__, 2) . '/test/fixtures/signin-vectors.json'), true);
$mk = function () use ($SI) {
    $st = tokenlock_sv_memory_store();
    call_user_func($st['put'], $SI['record']['nonce'], $SI['record'], $SI['now'] + 600000);
    return array('store' => $st, 'holdings' => tokenlock_sv_static_provider(array($SI['signers'][0]['address'] => array('GOTPROOF'))), 'pass_secret' => $SI['pass_secret']);
};
$in = array('challenge_id' => $SI['record']['nonce'], 'address' => $SI['signers'][0]['address'], 'signature' => rtrim($SI['signers'][0]['signature'], '='));
$r = tokenlock_sv_verify_sign_in($in, $mk(), $SI['now'] + 1000);
ok($r['code'] === 'bad_signature' && ($r['signature_format'] ?? null) === 'base64_variant' && strpos($r['reason'], 'Unsupported signature format: ') === 0, 'sign-in: unpadded signature is a named format problem', json_encode($r));
$in['signature'] = $SI['signers'][1]['signature'];
$r = tokenlock_sv_verify_sign_in($in, $mk(), $SI['now'] + 1000);
ok($r['code'] === 'bad_signature' && !array_key_exists('signature_format', $r) && $r['reason'] === 'The signature does not match this address and message.', 'sign-in: wrong-key signature keeps the plain reason', json_encode($r));

echo "\n$passed passed, $failed failed\n";
exit($failed ? 1 : 0);
