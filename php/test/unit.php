<?php
/**
 * In-process tests for helpers, verifyPass, and the cache.
 * Run: php test/unit.php
 */
error_reporting(E_ALL);
require_once dirname(__DIR__) . '/tokenlock/tokenlock.php';

$failed = 0;
$passed = 0;

function expect($cond, $name, $detail = '')
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

function eq($a, $b, $name)
{
    expect($a === $b, $name, 'got ' . var_export($a, true) . ' expected ' . var_export($b, true));
}

$SK = 'sk_' . str_repeat('a', 43);
$GOOD = 'pp1.' . str_repeat('Z', 40) . '.' . str_repeat('Q', 43);
$FORGED = 'pp1.' . str_repeat('Y', 40) . '.' . str_repeat('Q', 43);
$cacheDir = sys_get_temp_dir() . '/tokenlock-php-unit-' . getmypid();
@mkdir($cacheDir, 0700, true);

$calls = array();
$future = gmdate('Y-m-d\TH:i:s\Z', time() + 3600);

$handler = function ($method, $url, $headers, $body) use (&$calls, $SK, $GOOD, $future) {
    $calls[] = array('url' => $url, 'method' => $method, 'headers' => $headers, 'body' => $body);
    $j = $body ? json_decode($body, true) : array();
    if (substr($url, -strlen('/api/v1/gate/verify')) === '/api/v1/gate/verify') {
        $auth = isset($headers['Authorization']) ? $headers['Authorization'] : '';
        if ($auth !== 'Bearer ' . $SK) {
            return array('status' => 200, 'body' => json_encode(array('valid' => false, 'code' => 'bad_secret_key')));
        }
        if (isset($j['pass']) && $j['pass'] === $GOOD) {
            return array('status' => 200, 'body' => json_encode(array(
                'valid' => true,
                'address' => 'bc1qtest',
                'assets_held' => array('TOKENLOCK'),
                'site_id' => 's1',
                'origin' => 'https://example.com',
                'expires_at' => $future,
            )));
        }
        return array('status' => 200, 'body' => json_encode(array('valid' => false, 'code' => 'bad_pass', 'reason' => 'Not a valid pass.')));
    }
    return array('status' => 404, 'body' => json_encode(array('error' => 'no')));
};

tokenlock_configure(array(
    'secret_key' => $SK,
    'site_key' => 'pk_good',
    'api_base' => 'https://tokenlock.ai',
    'cache_dir' => $cacheDir,
    'http_handler' => $handler,
    'sign_in_page' => '/tokenlock/signin.php',
    'after_sign_in' => '/holders/',
));
tokenlock_clear_cache();

echo "helpers\n";
eq(tokenlock_safe_next('/members?x=1'), '/members?x=1', 'safeNext keeps a same-site path');
foreach (array('//evil.com', 'https://evil.com', '/\\evil.com', '', null, 'http://evil.com', '//evil.com/x') as $v) {
    eq(tokenlock_safe_next($v), '/', 'safeNext blocks ' . var_export($v, true));
}
eq(tokenlock_safe_next("/holders/\r\nLocation: https://evil.com"), '/', 'safeNext rejects CR/LF (header injection) instead of stripping it');
$NV = json_decode(file_get_contents(__DIR__ . '/fixtures/next-vectors.json'), true);
$bad = array();
foreach ($NV['allowed'] as $v) { if (tokenlock_safe_next($v) !== $v) { $bad[] = $v; } }
foreach ($NV['rejected'] as $v) { if (tokenlock_safe_next($v) !== '/') { $bad[] = $v; } }
eq($bad, array(), 'safeNext matches the shared next vectors (' . (count($NV['allowed']) + count($NV['rejected'])) . ')');
eq(tokenlock_wants_secure('http://localhost:8080/x'), false, 'http://localhost is not Secure');
eq(tokenlock_wants_secure('http://127.0.0.1/x'), false, 'http://127.0.0.1 is not Secure');
eq(tokenlock_wants_secure('https://pepeproject.com'), true, 'https is Secure');
eq(tokenlock_wants_secure('http://pepeproject.com'), true, 'http on a public host is still Secure');

echo "cookies\n";
$c = tokenlock_pass_cookie($GOOD, array('valid' => true, 'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 600)), 'https://pepeproject.com/holders/');
expect((bool) preg_match('/^tokenlock_pass=pp1\./', $c), 'cookie starts with tokenlock_pass=');
expect(strpos($c, 'HttpOnly') !== false, 'cookie is HttpOnly');
expect(strpos($c, 'Secure') !== false, 'https cookie is Secure');
expect(strpos($c, 'SameSite=Lax') !== false, 'cookie is SameSite=Lax');
if (preg_match('/Max-Age=(\d+)/', $c, $m)) {
    $age = (int) $m[1];
    expect($age > 590 && $age <= 600, 'Max-Age follows the pass expiry (~600s)', 'Max-Age=' . $age);
} else {
    expect(false, 'Max-Age present');
}
$cLocal = tokenlock_pass_cookie($GOOD, array('valid' => true, 'expires_at' => $future), 'http://localhost:8080/holders/');
expect(strpos($cLocal, 'Secure') === false, 'http://localhost cookie is not Secure');
$clear = tokenlock_clear_cookie('https://pepeproject.com/');
expect(strpos($clear, 'Max-Age=0') !== false, 'clear cookie Max-Age=0');
expect(strpos($clear, 'HttpOnly') !== false, 'clear cookie is HttpOnly');

echo "pass format\n";
expect(tokenlock_pass_looks_valid($GOOD), 'good pass accepted');
expect(!tokenlock_pass_looks_valid('not-a-pass'), 'malformed pass rejected');
expect(!tokenlock_pass_looks_valid(''), 'empty pass rejected');
expect(!tokenlock_pass_looks_valid(str_repeat('a', 5000)), 'oversized pass rejected');

echo "verifyPass\n";
$calls = array();
$v = tokenlock_verify_pass($GOOD, array('identity_only' => true));
expect(!empty($v['valid']) && $v['address'] === 'bc1qtest', 'good pass is valid');
expect(isset($calls[0]['headers']['Authorization']) && $calls[0]['headers']['Authorization'] === 'Bearer ' . $SK, 'Bearer secret key sent');
expect($calls[0]['method'] === 'POST', 'verify uses POST');
$token = isset($calls[0]['headers']['x-tokenlock-sdk']) ? $calls[0]['headers']['x-tokenlock-sdk'] : '';
expect(strpos($token, 'php/') === 0, 'x-tokenlock-sdk is php/…');
$n = count($calls);
$v2 = tokenlock_verify_pass($GOOD, array('identity_only' => true));
expect($v2['valid'] === true && count($calls) === $n, 'second check served from cache');

$bad = tokenlock_verify_pass($FORGED, array('identity_only' => true));
expect(empty($bad['valid']) && isset($bad['code']) && $bad['code'] === 'bad_pass', 'forged pass rejected');
$mal = tokenlock_verify_pass('not-a-pass', array('identity_only' => true));
expect(empty($mal['valid']) && $mal['code'] === 'bad_pass', 'malformed pass is bad_pass without an API call');

tokenlock_configure(array(
    'secret_key' => 'sk_' . str_repeat('b', 43),
    'api_base' => 'https://tokenlock.ai',
    'cache_dir' => $cacheDir,
    'http_handler' => $handler,
));
$wrong = tokenlock_verify_pass($GOOD, array('identity_only' => true));
expect(empty($wrong['valid']), 'wrong secret key is never valid');

$threw = false;
tokenlock_configure(array(
    'secret_key' => '',
    'api_base' => 'https://tokenlock.ai',
    'cache_dir' => $cacheDir,
    'http_handler' => $handler,
));
try {
    tokenlock_verify_pass($GOOD, array('identity_only' => true));
} catch (TokenlockException $e) {
    $threw = ($e->error_code === 'bad_config');
}
expect($threw, 'missing secret key throws bad_config (0.4.2; was no_secret_key)');

tokenlock_configure(array(
    'secret_key' => $SK,
    'api_base' => 'https://tokenlock.ai',
    'cache_dir' => $cacheDir,
    'http_handler' => function () {
        return array('status' => 200, 'body' => json_encode(array('valid' => true, 'address' => 'x')));
    },
));
tokenlock_clear_cache();
$short = tokenlock_verify_pass($GOOD, array('identity_only' => true));
expect(empty($short['valid']), 'a "valid" answer without site_id is treated as invalid');

$net = false;
tokenlock_configure(array(
    'secret_key' => $SK,
    'api_base' => 'https://tokenlock.ai',
    'cache_dir' => $cacheDir,
    'http_handler' => function () {
        throw new TokenlockException('Could not reach the TOKENLOCK API.', 0, 'network');
    },
));
tokenlock_clear_cache();
try {
    tokenlock_verify_pass($GOOD, array('identity_only' => true));
} catch (TokenlockException $e) {
    $net = ($e->error_code === 'network');
}
expect($net, 'network failure throws TokenlockException(network)');

// cache never past expiry
tokenlock_configure(array(
    'secret_key' => $SK,
    'api_base' => 'https://tokenlock.ai',
    'cache_dir' => $cacheDir,
    'http_handler' => function () {
        return array('status' => 200, 'body' => json_encode(array(
            'valid' => true,
            'address' => 'bc1qtest',
            'site_id' => 's1',
            'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() - 10),
        )));
    },
));
tokenlock_clear_cache();
$exp = tokenlock_verify_pass($GOOD, array('identity_only' => true));
// expired "valid" from API with site_id and address would be cached only if until > now; expires in the past so not cached. It's still valid===true from API though — our code trusts the API's valid flag plus site_id and address, not expiry locally (the server already checks expiry). That's what the SDK does too. Just assert we didn't write a cache file that lasts.
$files = glob($cacheDir . '/tokenlock_v1_*');
expect(!$files, 'expired pass is not cached');

// ---------------------------------------------------------------- 0.2.0 enterprise access controls
$ENT = 'pp1.' . str_repeat('E', 40) . '.' . str_repeat('Q', 43);
$acalls = array();
$revoked = false;
tokenlock_configure(array(
    'secret_key' => $SK,
    'api_base' => 'https://tokenlock.ai',
    'cache_dir' => $cacheDir,
    'http_handler' => function ($method, $url, $headers, $body) use (&$acalls, &$revoked, $future) {
        $j = json_decode($body, true);
        $acalls[] = $j;
        $res = array('path' => isset($j['path']) ? $j['path'] : null, 'method' => isset($j['method']) ? $j['method'] : null, 'environment' => isset($j['environment']) ? $j['environment'] : null);
        $base = array('address' => 'bc1qagent', 'site_id' => 's1', 'expires_at' => $future, 'correlation_id' => 'c0ffee', 'assets_held' => array('TOKENLOCK'), 'resource' => $res);
        if ($revoked) {
            return array('status' => 200, 'body' => json_encode(array_merge($base, array('valid' => false, 'allowed' => false, 'code' => 'key_revoked', 'access' => array('mode' => 'registered_keys', 'allowed' => false, 'reason' => 'key_revoked'), 'cache_max_s' => 0))));
        }
        if (isset($j['path']) && strpos($j['path'], '/api/') !== 0) {
            return array('status' => 200, 'body' => json_encode(array_merge($base, array('valid' => false, 'allowed' => false, 'code' => 'route_not_allowed', 'access' => array('mode' => 'registered_keys', 'allowed' => false, 'reason' => 'route_not_allowed'), 'cache_max_s' => 0))));
        }
        return array('status' => 200, 'body' => json_encode(array_merge($base, array('valid' => true, 'allowed' => true, 'access' => array('mode' => 'registered_keys', 'allowed' => true, 'reason' => 'ok'), 'cache_max_s' => 5))));
    },
));
tokenlock_clear_cache();
$r = tokenlock_verify_pass($ENT, array('path' => '/api/x?y=1', 'method' => 'get', 'environment' => 'production'));
expect(!empty($r['valid']), '0.2.0: allowed resource is valid');
eq($acalls[0]['path'], '/api/x', '0.2.0: path sent without query');
eq($acalls[0]['method'], 'GET', '0.2.0: method upper-cased');
eq($acalls[0]['environment'], 'production', '0.2.0: environment sent');
$r = tokenlock_verify_pass($ENT, array('path' => '/admin', 'method' => 'GET'));
expect(empty($r['valid']) && $r['code'] === 'route_not_allowed', '0.2.0: out-of-scope route denied with reason');
eq(count($acalls), 2, '0.2.0: different resource is checked, not cached');
tokenlock_verify_pass($ENT, array('path' => '/api/x', 'method' => 'GET', 'environment' => 'production'));
eq(count($acalls), 3, '0.2.1: strict (default) never caches registered-key answers');
$threw = false;
try { tokenlock_verify_pass($ENT, array('path' => '/api/x', 'method' => 'GET', 'environment' => 'production'), array('strict' => false)); } catch (TokenlockException $e) { $threw = $e->error_code === 'bad_config'; }
expect($threw, "0.4.2: array('strict' => false) (loose mode, which cached registered-key answers) is a configuration error");
eq(count($acalls), 3, '0.4.2: no API call for a refused option');
expect(!glob($cacheDir . '/tokenlock_v1_*'), '0.4.2: registered-key answers are never cached');
$revoked = true;
tokenlock_clear_cache();
$r = tokenlock_verify_pass($ENT, array('path' => '/api/x', 'method' => 'GET'));
expect(empty($r['valid']) && $r['code'] === 'key_revoked', '0.2.0: revoked key is denied on the next check');
eq(in_array('route_not_allowed', tokenlock_forbidden_codes(), true), true, '0.2.0: route denials answer 403, not a sign-in redirect');
eq(TOKENLOCK_PHP, '0.5.4', 'version 0.5.4');
// 0.5.1: the default hosted origin is tokenlock.ai; an explicit api_base still overrides it (trailing slash trimmed).
$tl051 = tokenlock_defaults();
eq($tl051['api_base'], 'https://tokenlock.ai', '0.5.1 default api_base is https://tokenlock.ai');
$tl051 = tokenlock_configure(array('secret_key' => $SK));
eq($tl051['api_base'], 'https://tokenlock.ai', '0.5.1 api_base omitted -> https://tokenlock.ai');
$tl051 = tokenlock_configure(array('secret_key' => $SK, 'api_base' => 'https://api.example.com/'));
eq($tl051['api_base'], 'https://api.example.com', '0.5.1 api_base override still wins');
tokenlock_configure(null);

// ---------------------------------------------------------------- 0.2.1 security patch
echo "0.2.1\n";
$V = json_decode(file_get_contents(dirname(__DIR__) . '/test/fixtures/path-vectors.json'), true);
$bad = array();
foreach ($V['vectors'] as $v) {
    if (tokenlock_canonical_path($v[0]) !== $v[1]) {
        $bad[] = $v[0];
    }
}
eq($bad, array(), '0.2.1: canonical path matches the shared vectors (' . count($V['vectors']) . ')');
$prot = array();
foreach ($V['protected_case']['must_be_protected_or_rejected'] as $p) {
    $c = tokenlock_canonical_path($p);
    if ($c !== null && !tokenlock_path_matches($V['protected_case']['protect'], $c)) {
        $prot[] = $p;
    }
}
eq($prot, array(), '0.2.1: every alternate form of /admin is protected or rejected');
foreach ($V['protected_case']['not_protected'] as $p) {
    expect(!tokenlock_path_matches($V['protected_case']['protect'], tokenlock_canonical_path($p)), '0.2.1: not protected ' . $p);
}
$shape = null;
tokenlock_configure(array(
    'secret_key' => $SK, 'api_base' => 'https://tokenlock.ai', 'cache_dir' => $cacheDir,
    'http_handler' => function ($method, $url, $headers, $body) use (&$shape, &$acalls, $future) {
        $j = json_decode($body, true);
        $acalls[] = $j;
        $res = array('path' => isset($j['path']) ? $j['path'] : null, 'method' => isset($j['method']) ? $j['method'] : null, 'environment' => isset($j['environment']) ? $j['environment'] : null);
        $b = array('address' => 'bc1qagent', 'site_id' => 's1', 'expires_at' => $future, 'assets_held' => array('TOKENLOCK'));
        // 0.4.0: a resource is granted only by a route policy, so the default answer is a registered key allowed everywhere
        $o = $shape ? $shape($b, $res) : array_merge($b, array('valid' => true, 'allowed' => true, 'resource' => $res, 'access' => array('mode' => 'registered_keys', 'allowed' => true, 'reason' => 'ok', 'resource' => $res)));
        return array('status' => 200, 'body' => json_encode($o));
    },
));
$cases = array(
    'no_allowed' => function ($b, $r) { return array_merge($b, array('valid' => true)); },
    'no_echo' => function ($b, $r) { return array_merge($b, array('valid' => true, 'allowed' => true)); },
    'mismatch' => function ($b, $r) { $r['path'] = '/api/other'; return array_merge($b, array('valid' => true, 'allowed' => true, 'resource' => $r)); },
    'unknown_mode' => function ($b, $r) { return array_merge($b, array('valid' => true, 'allowed' => true, 'resource' => $r, 'access' => array('mode' => 'future', 'allowed' => true))); },
    'no_address' => function ($b, $r) { $b['address'] = ''; return array_merge($b, array('valid' => true, 'allowed' => true, 'resource' => $r)); },
    'expired' => function ($b, $r) { $b['expires_at'] = gmdate('Y-m-d\TH:i:s\Z', time() - 5); return array_merge($b, array('valid' => true, 'allowed' => true, 'resource' => $r)); },
);
foreach ($cases as $name => $fn) {
    $shape = $fn;
    tokenlock_clear_cache();
    $r = tokenlock_verify_pass($ENT, array('path' => '/api/x', 'method' => 'GET'));
    expect(empty($r['valid']) && $r['allowed'] === false, '0.2.1 strict denies: ' . $name);
}
$shape = function ($b, $r) { return array_merge($b, array('valid' => true, 'allowed' => true, 'access' => array('mode' => 'registered_keys', 'allowed' => true, 'reason' => 'ok'))); };
tokenlock_clear_cache();
expect(empty(tokenlock_verify_pass($ENT, array('path' => '/api/x', 'method' => 'GET'))['valid']), '0.4.2: the 0.2.0 answer shape (no echo) is denied (loose mode removed)');
$shape = $cases['no_echo'];
tokenlock_clear_cache();
$x = tokenlock_verify_pass($ENT, array('path' => '/api/x', 'method' => 'GET'));
expect(empty($x['valid']) && $x['code'] === 'policy_required' && !empty($x['identity_valid']), '0.4.0: no route policy (token-only answer) → policy_required');
foreach (array(true, null) as $st) {
    tokenlock_clear_cache();
    $x = tokenlock_verify_pass($ENT, array('path' => '/api/x', 'method' => 'GET'), array('strict' => $st));
    expect($x['code'] === 'policy_required' && $x['allowed'] === false, '0.4.0: token-only resource check denied (strict=' . var_export($st, true) . ')');
}
tokenlock_clear_cache();
$x = tokenlock_verify_pass($ENT, array('identity_only' => true));
expect(!empty($x['valid']), '0.4.0: identity-only check on a token-only site stays valid');
$shape = null;
$r = tokenlock_verify_pass($ENT, array('path' => '/api%2f..%2fx', 'method' => 'GET'));
eq($r['code'], 'bad_path', '0.2.1: encoded slash → bad_path, no API call');
// clear_cache($pass) removes that pass's entries only (identity answers: the only cached kind since 0.4.2)
$P2 = 'pp1.' . str_repeat('F', 40) . '.' . str_repeat('Q', 43);
$shape = function ($b, $r) { return array_merge($b, array('valid' => true)); };
tokenlock_clear_cache();
$acalls = array();
tokenlock_verify_pass($ENT, array('identity_only' => true));
tokenlock_verify_pass($P2, array('identity_only' => true));
tokenlock_verify_pass($ENT, array('identity_only' => true));
tokenlock_verify_pass($P2, array('identity_only' => true));
eq(count($acalls), 2, '0.2.1: identity answers cached per pass');
tokenlock_clear_cache($ENT);
tokenlock_verify_pass($ENT, array('identity_only' => true));
tokenlock_verify_pass($P2, array('identity_only' => true));
eq(count($acalls), 3, '0.2.1: clear_cache($pass) drops its entries, others stay');
tokenlock_verify_pass($P2, array('identity_only' => true), array('cache' => false));
eq(count($acalls), 4, '0.2.1: cache => false always asks');
$shape = null;
tokenlock_verify_pass($ENT, array('path' => '/a', 'method' => 'GET'));
tokenlock_verify_pass($ENT, array('path' => '/a', 'method' => 'GET'));
eq(count($acalls), 6, '0.4.2: registered-key resource answers are asked every time');
// config-time checks (0.4.2: removed options and strict => false are configuration errors)
$cfgBase = tokenlock_config();
foreach (array(array('strict' => true, 'fail_open' => true), array('fail_open' => true), array('fail_open' => false), array('strict' => true, 'check_resource' => false), array('check_resource' => true), array('strict' => false)) as $bad) {
    tokenlock_configure(array_merge($cfgBase, $bad));
    $threw = false;
    try { tokenlock_strict(); } catch (TokenlockException $e) { $threw = $e->error_code === 'bad_config'; }
    expect($threw, '0.4.2: ' . json_encode($bad) . ' is a configuration error');
}
tokenlock_configure($cfgBase);
eq(tokenlock_strict(), true, '0.2.1: strict is the default (0.4.2: always)');
$_SERVER['HTTP_ACCEPT'] = 'application/json';
expect(tokenlock_is_api_request('/x'), '0.2.1: Accept: application/json → API mode');
$_SERVER['HTTP_ACCEPT'] = 'text/html,application/json';
expect(!tokenlock_is_api_request('/x'), '0.2.1: browsers are not API mode');
tokenlock_configure(array_merge($cfgBase, array('api_paths' => '/api, /v1')));
expect(tokenlock_is_api_request('/API/x') && tokenlock_is_api_request('/v1'), '0.2.1: api_paths (case-insensitive prefixes)');
unset($_SERVER['HTTP_ACCEPT']);

echo "second review (cache key, resource case)\n";
// 0.4.0: a registered key allowed everywhere (token-only answers are now policy_required). Loose answers are cached;
// 0.2.1 kept case in the resource, so /Admin and /admin were separate entries with case-sensitive echoes.
$tcalls = array();
$echo = null;
tokenlock_configure(array_merge($cfgBase, array(
    'http_handler' => function ($method, $url, $headers, $body) use (&$tcalls, &$echo, $future) {
        $j = json_decode($body, true);
        $tcalls[] = $j;
        $r = array('path' => isset($j['path']) ? $j['path'] : null, 'method' => isset($j['method']) ? $j['method'] : null, 'environment' => isset($j['environment']) ? $j['environment'] : null);
        if ($echo) {
            $r = $echo($r);
        }
        return array('status' => 200, 'body' => json_encode(array('valid' => true, 'allowed' => true, 'address' => 'bc1qtest', 'site_id' => 's1', 'expires_at' => $future, 'cache_max_s' => 60, 'resource' => $r, 'access' => array('mode' => 'registered_keys', 'allowed' => true, 'reason' => 'ok', 'resource' => $r))));
    },
)));
tokenlock_clear_cache();
$a = tokenlock_verify_pass($GOOD, array('path' => '/Admin', 'method' => 'GET'));
$b = tokenlock_verify_pass($GOOD, array('path' => '/admin', 'method' => 'GET'));
expect(!empty($a['valid']) && !empty($b['valid']), 'review2: /Admin then /admin both valid');
expect(count($tcalls) === 2 && $tcalls[0]['path'] === '/admin' && $tcalls[1]['path'] === '/admin', 'review2: one canonical lowercased resource; 0.4.2 asks every time (registered keys never cached)');
expect($b['resource']['path'] === '/admin', 'review2: the answer for /admin echoes /admin');
// a cached identity entry that no longer holds (expired, or suddenly naming a resource) is dropped and asked again
$tcalls = array();
$idOnly = true;
tokenlock_configure(array_merge($cfgBase, array(
    'http_handler' => function ($method, $url, $headers, $body) use (&$tcalls, $future) {
        $tcalls[] = json_decode($body, true);
        return array('status' => 200, 'body' => json_encode(array('valid' => true, 'address' => 'bc1qtest', 'site_id' => 's1', 'expires_at' => $future, 'cache_max_s' => 60)));
    },
)));
tokenlock_clear_cache();
tokenlock_verify_pass($GOOD, array('identity_only' => true));
tokenlock_verify_pass($GOOD, array('identity_only' => true));
expect(count($tcalls) === 1, 'review2: identity answer cached');
$ck = $GOOD . "\n" . $cfgBase['api_base'] . "\ns\n";
$row = tokenlock_cache_get($ck, $SK);
expect(is_array($row), 'review2: cache entry found');
$row['resource'] = array('path' => '/public', 'method' => 'GET');
tokenlock_cache_put($ck, $SK, $row);
$c = tokenlock_verify_pass($GOOD, array('identity_only' => true));
expect(!empty($c['valid']) && count($tcalls) === 2 && !isset($c['resource']), 'review2: a cache hit that names a resource is not used');
tokenlock_configure(array_merge($cfgBase, array(
    'http_handler' => function ($method, $url, $headers, $body) use (&$tcalls, &$echo, $future) {
        $j = json_decode($body, true);
        $tcalls[] = $j;
        $r = array('path' => isset($j['path']) ? $j['path'] : null, 'method' => isset($j['method']) ? $j['method'] : null, 'environment' => isset($j['environment']) ? $j['environment'] : null);
        if ($echo) {
            $r = $echo($r);
        }
        return array('status' => 200, 'body' => json_encode(array('valid' => true, 'allowed' => true, 'address' => 'bc1qtest', 'site_id' => 's1', 'expires_at' => $future, 'cache_max_s' => 60, 'resource' => $r, 'access' => array('mode' => 'registered_keys', 'allowed' => true, 'reason' => 'ok', 'resource' => $r))));
    },
)));
// an echo for another path is refused, an upper-case echo of the same path is fine
$echo = function ($r) { $r['path'] = '/public'; return $r; };
tokenlock_clear_cache();
$x = tokenlock_verify_pass($GOOD, array('path' => '/admin', 'method' => 'GET'));
expect(empty($x['valid']) && $x['code'] === 'resource_mismatch', 'review2: echo for another path refused');
$echo = function ($r) { $r['path'] = strtoupper($r['path']); return $r; };
tokenlock_clear_cache();
$x = tokenlock_verify_pass($GOOD, array('path' => '/admin', 'method' => 'GET'), array('strict' => true));
expect(!empty($x['valid']), 'review2: an upper-case echo of the same path is the same resource');
$echo = null;
expect(tokenlock_resource_path('/Caf%C3%A9/X/') === '/café/x' && tokenlock_resource_path('/admin/..') === null, 'review2: resource path is canonical + lowercased');
tokenlock_configure($cfgBase);

// cleanup cache dir
tokenlock_clear_cache();
@rmdir($cacheDir);

echo "\n$passed passed, $failed failed\n";
exit($failed ? 1 : 0);
