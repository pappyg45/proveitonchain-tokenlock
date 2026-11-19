<?php
/**
 * 0.4.2 hardening tests: a stub TOKENLOCK API (no network). Registered-keys site: the key may GET /members/* in
 * production; identity checks (no resource) are allowed. Token-only site: resource checks answer policy_required.
 */
function hm_base()
{
    return array('address' => 'bc1qagent', 'assets_held' => array('TOKENLOCK'), 'site_id' => 's1', 'origin' => 'https://example.com',
        'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 3600), 'correlation_id' => 'cid');
}
function hm_echo($j)
{
    return array('path' => isset($j['path']) ? $j['path'] : null, 'method' => isset($j['method']) ? $j['method'] : null, 'environment' => isset($j['environment']) ? $j['environment'] : null);
}
function hm_has_res($j)
{
    return !empty($j['path']) || !empty($j['method']) || !empty($j['environment']);
}
function hm_access_ok($j, $extra = array())
{
    $a = array('mode' => 'registered_keys', 'allowed' => true, 'reason' => 'ok', 'key' => array('id' => 'k1'), 'permissions' => array('routes' => array('/members/*'), 'methods' => array('GET'), 'environments' => array('production')), 'key_expires_at' => null);
    if (hm_has_res($j)) {
        $a['resource'] = hm_echo($j);
    }
    return array_merge($a, $extra);
}
function hm_registered($j)
{
    if (!hm_has_res($j)) {
        return array_merge(array('valid' => true, 'allowed' => true), hm_base(), array('access' => hm_access_ok($j), 'cache_max_s' => 5));
    }
    $deny = function ($code) use ($j) {
        return array_merge(array('valid' => false, 'allowed' => false, 'code' => $code, 'reason' => $code), hm_base(), array('access' => hm_access_ok($j, array('allowed' => false, 'reason' => $code)), 'resource' => hm_echo($j), 'cache_max_s' => 0));
    };
    $p = strtolower(isset($j['path']) ? (string) $j['path'] : '');
    if (!empty($j['path']) && !($p === '/members' || strpos($p, '/members/') === 0)) {
        return $deny('route_not_allowed');
    }
    if (!empty($j['method']) && $j['method'] !== 'GET') {
        return $deny('method_not_allowed');
    }
    if (!empty($j['environment']) && $j['environment'] !== 'production') {
        return $deny('environment_not_allowed');
    }
    return array_merge(array('valid' => true, 'allowed' => true), hm_base(), array('access' => hm_access_ok($j), 'resource' => hm_echo($j), 'cache_max_s' => 5));
}
function hm_tokenonly($j)
{
    if (hm_has_res($j)) {
        return array_merge(array('valid' => false, 'allowed' => false, 'identity_valid' => true, 'code' => 'policy_required', 'reason' => 'no policy'), hm_base(),
            array('access' => array('mode' => 'token', 'allowed' => false, 'reason' => 'policy_required'), 'resource' => hm_echo($j), 'cache_max_s' => 0));
    }
    return array_merge(array('valid' => true), hm_base());
}
/** Mutations of a good registered answer, by name (malformed + conflicting tables, same as the Node tests). */
function hm_mutations()
{
    return array(
        'malformed' => array(
            'valid:"true" (string)' => function ($a, $j) { $a['valid'] = 'true'; return $a; },
            'allowed:"true" (string)' => function ($a, $j) { $a['allowed'] = 'true'; return $a; },
            'access.allowed:1' => function ($a, $j) { $a['access']['allowed'] = 1; return $a; },
            'access.mode missing' => function ($a, $j) { unset($a['access']['mode']); return $a; },
            'access:null' => function ($a, $j) { $a['access'] = null; return $a; },
            'access:[] (empty array)' => function ($a, $j) { $a['access'] = array(); return $a; },
            'missing address' => function ($a, $j) { unset($a['address']); return $a; },
            'address is a number' => function ($a, $j) { $a['address'] = 12345; return $a; },
            'missing site_id' => function ($a, $j) { unset($a['site_id']); return $a; },
            'missing expires_at' => function ($a, $j) { unset($a['expires_at']); return $a; },
            'expires_at garbage' => function ($a, $j) { $a['expires_at'] = 'tomorrow'; return $a; },
            'expires_at in the past' => function ($a, $j) { $a['expires_at'] = gmdate('Y-m-d\TH:i:s\Z', time() - 5); return $a; },
            'missing resource echo' => function ($a, $j) { unset($a['resource'], $a['access']['resource']); return $a; },
            'resource echo not an object' => function ($a, $j) { $a['resource'] = '/members/x'; $a['access']['resource'] = '/members/x'; return $a; },
            'extra fields claiming allowed on a deny' => function ($a, $j) { $a['valid'] = false; $a['authorized'] = true; $a['granted'] = true; return $a; },
            'JSON array' => '[{"valid":true}]',
            'JSON null' => 'null',
            'JSON string' => '"valid"',
            'non-JSON 200' => '<html>ok</html>',
            'empty 200' => '',
            'oversized 200 (1 MiB, otherwise valid)' => function ($a, $j) { $a['pad'] = str_repeat('x', 1048576); return $a; },
        ),
        'conflicting' => array(
            'valid:true with code key_revoked' => function ($a, $j) { $a['code'] = 'key_revoked'; return $a; },
            'valid:true allowed:true with code policy_required' => function ($a, $j) { $a['code'] = 'policy_required'; return $a; },
            'valid:true with error' => function ($a, $j) { $a['error'] = 'Unknown secret key.'; return $a; },
            'valid:true with identity_valid:false' => function ($a, $j) { $a['identity_valid'] = false; return $a; },
            'allowed:true but access.allowed:false' => function ($a, $j) { $a['access']['allowed'] = false; $a['access']['reason'] = 'key_revoked'; return $a; },
            'access.allowed:true but allowed:false' => function ($a, $j) { $a['allowed'] = false; return $a; },
            'access.reason route_not_allowed with allowed:true' => function ($a, $j) { $a['access']['reason'] = 'route_not_allowed'; return $a; },
            'top echo matches, access echo names another path' => function ($a, $j) { $a['access']['resource']['path'] = '/members'; return $a; },
            'access echo matches, top echo names another method' => function ($a, $j) { $a['resource']['method'] = 'POST'; return $a; },
            'hosted echoes a different path than PHP asked' => function ($a, $j) { $a['resource']['path'] = '/members'; $a['access']['resource']['path'] = '/members'; return $a; },
            'hosted echoes a different environment' => function ($a, $j) { $a['resource']['environment'] = 'staging'; $a['access']['resource']['environment'] = 'staging'; return $a; },
            'access.mode token with allowed:true' => function ($a, $j) { $a['access']['mode'] = 'token'; return $a; },
        ),
    );
}
/** http_handler for tokenlock_configure(): $answer = 'registered' | 'tokenonly' | 'down' | callable($j) → array|string body. */
function hm_handler($answer, $status = 200)
{
    return function ($method, $url, $headers, $body) use ($answer, $status) {
        if ($answer === 'down') {
            throw new TokenlockException('Could not reach the TOKENLOCK API.', 0, 'network');
        }
        $j = $body ? json_decode($body, true) : array();
        if ($answer === 'registered') {
            $out = hm_registered($j);
        } elseif ($answer === 'tokenonly') {
            $out = hm_tokenonly($j);
        } else {
            $out = call_user_func($answer, $j);
        }
        return array('status' => $status, 'body' => is_string($out) ? $out : json_encode($out));
    };
}
