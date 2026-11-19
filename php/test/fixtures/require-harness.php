<?php
/**
 * 0.4.2 hardening tests: run tokenlock_require() for one request in a fresh PHP process (it exits on a denial).
 * Usage: php require-harness.php '<json case>'   case = { config, env, answer: registered|tokenonly|down|mutation name, path, method }
 * Prints PAGE-SERVED only if tokenlock_require() returned (the protected page would run).
 */
error_reporting(E_ALL);
require_once dirname(__DIR__, 2) . '/tokenlock/tokenlock.php';
require_once __DIR__ . '/hardening-mock.php';
$case = json_decode($argv[1], true);
foreach (isset($case['env']) ? $case['env'] : array() as $k => $v) {
    putenv($k . '=' . $v);
    $_ENV[$k] = $v;
}
$_SERVER['REQUEST_URI'] = isset($case['path']) ? $case['path'] : '/members/x';
$_SERVER['REQUEST_METHOD'] = isset($case['method']) ? $case['method'] : 'GET';
$_SERVER['HTTP_ACCEPT'] = 'application/json';
$_COOKIE['tokenlock_pass'] = 'pp1.' . str_repeat('H', 40) . '.' . str_repeat('Q', 43);
$answer = isset($case['answer']) ? $case['answer'] : 'registered';
if (isset($case['mutation'])) {
    $all = hm_mutations();
    $m = $all[$case['mutation'][0]][$case['mutation'][1]];
    $answer = function ($j) use ($m) {
        return is_string($m) ? $m : call_user_func($m, hm_registered($j), $j);
    };
}
$cfg = tokenlock_configure(null); // config.php (none in tests) + environment
$over = array_merge(isset($case['use_env_only']) ? array() : array('secret_key' => 'sk_' . str_repeat('h', 43), 'cache' => false, 'cache_dir' => sys_get_temp_dir()), isset($case['config']) ? $case['config'] : array());
$merged = array_merge($cfg, $over, array('http_handler' => hm_handler($answer)));
foreach (isset($case['unset']) ? $case['unset'] : array() as $k) {
    unset($merged[$k]);
}
global $_tokenlock_config;
$_tokenlock_config = $merged;
tokenlock_require();
echo "PAGE-SERVED\n";
