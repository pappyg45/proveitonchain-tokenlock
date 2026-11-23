<?php
// Shared authorization matrix (test/fixtures/authz-matrix.json, same file as the Node SDK's) for PHP self-verify.
// Usage: php test/authz-matrix.php [out.json]
require __DIR__ . '/../tokenlock/self-verify.php';

$M = json_decode(file_get_contents(__DIR__ . '/fixtures/authz-matrix.json'), true);
$SECRET = str_repeat('m', 40);
$ADDR = 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq';
$NOW = 1795024800000; // 2026-11-18T18:00:00Z
$ok = 0; $bad = 0; $out = array();
foreach ($M['cases'] as $c) {
    $k = $c['policy'] === 'registered_keys' ? 'key_1' : null;
    $pass = tokenlock_sv_issue_pass(array('sub' => $ADDR, 'h' => array('TOKENLOCK'), 'k' => $k, 'n' => str_repeat('a', 32), 's' => 'https://app.example', 'i' => $NOW - 1000, 'e' => $c['pass'] === 'expired' ? $NOW - 1 : $NOW + 900000), $SECRET);
    if ($c['pass'] === 'forged') {
        $pass = substr($pass, 0, -4) . (substr($pass, -4) === 'AAAA' ? 'BBBB' : 'AAAA');
    }
    $opts = array('pass_secret' => $SECRET, 'now' => $NOW) + ($c['resource'] === null ? array('identity_only' => true) : array('resource' => $c['resource'])); // 0.4.3: identity-only is explicit
    if ($c['policy'] === 'registered_keys') {
        $opts['policy'] = tokenlock_sv_local_policy(array('keys' => array(array('id' => 'key_1', 'address' => $ADDR, 'status' => isset($c['key']) && $c['key'] === 'revoked' ? 'revoked' : 'active', 'permissions' => array('routes' => $M['key']['routes'], 'methods' => $M['key']['methods'], 'environments' => $M['key']['environments'])))));
    } elseif ($c['policy'] === 'token') {
        $opts['policy'] = tokenlock_sv_local_policy(array('mode' => 'token'));
    }
    $v = tokenlock_sv_verify_local_pass($pass, $opts);
    $allow = !empty($v['valid']) && (!isset($v['allowed']) || $v['allowed'] !== false);
    $got = array('allow' => $allow, 'code' => $allow ? 'ok' : $v['code']);
    $out[$c['id']] = $got;
    if ($got === $c['expect']) { $ok++; echo "  ✓ {$c['id']}\n"; }
    else { $bad++; echo "  ✖ {$c['id']}: got " . json_encode($got) . ' want ' . json_encode($c['expect']) . "\n"; }
}
if (isset($argv[1])) {
    file_put_contents($argv[1], json_encode(array('integration' => 'php-self-verify', 'results' => $out), JSON_PRETTY_PRINT));
}
echo "$ok passed, $bad failed\n";
exit($bad ? 1 : 0);
