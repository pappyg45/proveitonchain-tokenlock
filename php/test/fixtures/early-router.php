<?php
/**
 * 0.4.2 hardening tests: php -S router that runs the early block with a stub API. Case from the TL_CASE env (JSON):
 * { config, answer: registered|down|badkey }. Prints PAGE-SERVED <result> if the early block let the request through.
 */
define('TOKENLOCK_EARLY_MANUAL', 1);
require dirname(__DIR__, 2) . '/tokenlock/early.php';
require_once __DIR__ . '/hardening-mock.php';
$case = json_decode((string) getenv('TL_CASE'), true);
$answer = isset($case['answer']) ? $case['answer'] : 'registered';
if ($answer === 'badkey') {
    $answer = function ($j) { return array('valid' => false, 'code' => 'bad_secret_key', 'reason' => 'Unknown secret key.'); };
    $status = 401;
}
$cfg = tokenlock_configure(null);
global $_tokenlock_config;
$_tokenlock_config = array_merge($cfg, array('secret_key' => 'sk_' . str_repeat('h', 43), 'cache' => false, 'cache_dir' => sys_get_temp_dir()),
    isset($case['config']) ? $case['config'] : array(), array('http_handler' => hm_handler($answer, isset($status) ? $status : 200)));
$r = !empty($case['early_from_config']) ? tokenlock_early(null) : tokenlock_early(isset($case['early']) ? $case['early'] : array('protect' => array('/members/*')));
echo 'PAGE-SERVED ' . $r . "\n";
