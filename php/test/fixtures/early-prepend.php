<?php
// Test-only auto_prepend_file: inject the 'early' settings (from TOKENLOCK_TEST_EARLY), then load the real early.php.
require_once dirname(__DIR__, 2) . '/tokenlock/tokenlock.php';
$c = tokenlock_config();
$c['early'] = json_decode((string) getenv('TOKENLOCK_TEST_EARLY'), true) ?: array();
if (getenv('TOKENLOCK_TEST_API_PATHS')) {
    $c['api_paths'] = explode(',', getenv('TOKENLOCK_TEST_API_PATHS'));
}
tokenlock_configure($c);
require dirname(__DIR__, 2) . '/tokenlock/early.php';
