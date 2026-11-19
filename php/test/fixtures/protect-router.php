<?php
/**
 * 0.4.3 interface audit: php -S router that runs tokenlock_protect() with a stub API. Case from TL_CASE (JSON):
 * { patterns, public?, answer: registered|down }. Prints PAGE-SERVED if the page was let through.
 */
require dirname(__DIR__, 2) . '/tokenlock/tokenlock.php';
require_once __DIR__ . '/hardening-mock.php';
$case = json_decode((string) getenv('TL_CASE'), true);
$answer = isset($case['answer']) ? $case['answer'] : 'down';
$cfg = tokenlock_configure(null);
global $_tokenlock_config;
$_tokenlock_config = array_merge($cfg, array('secret_key' => 'sk_' . str_repeat('h', 43), 'cache' => false, 'cache_dir' => sys_get_temp_dir()), array('http_handler' => hm_handler($answer, 200)));
tokenlock_protect($case['patterns'], isset($case['public']) ? $case['public'] : array());
echo 'PAGE-SERVED' . "\n";
