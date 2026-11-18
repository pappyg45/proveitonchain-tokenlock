<?php
/**
 * TOKENLOCK for PHP 7.4+
 *
 * Lock any page to people who hold a name or token on Bitcoin.
 * Your content stays on your server. We do the Token check.
 *
 * At the top of a locked page (before any HTML):
 *
 *   require_once $_SERVER['DOCUMENT_ROOT'] . '/tokenlock/tokenlock.php';
 *   tokenlock_require();
 *   $visitor = tokenlock_pass(); // address, assets_held, expires_at
 *
 * Keys live in config.php (copy config.sample.php). Never put the secret key
 * in a browser page or in chat.
 *
 * https://proveitonchain.com/tokenlock
 */
if (defined('TOKENLOCK_PHP')) {
    return;
}
define('TOKENLOCK_PHP', '0.3.0');

class TokenlockException extends Exception
{
    public $status;
    public $error_code;

    public function __construct($message, $status = 0, $error_code = null)
    {
        parent::__construct($message);
        $this->status = (int) $status;
        $this->error_code = $error_code;
    }
}

/** @var array|null */
$_tokenlock_config = null;
/** @var array|null verified pass for this request */
$_tokenlock_pass = null;

/**
 * Override config (tests, or a custom bootstrap). Pass null to reload.
 * @param array|null $overrides
 * @return array
 */
function tokenlock_configure($overrides = null)
{
    global $_tokenlock_config;
    if ($overrides === null) {
        $_tokenlock_config = null;
        return tokenlock_config();
    }
    $_tokenlock_config = array_merge(tokenlock_defaults(), is_array($overrides) ? $overrides : array());
    if (!empty($_tokenlock_config['api_base'])) {
        $_tokenlock_config['api_base'] = rtrim($_tokenlock_config['api_base'], '/');
    }
    return $_tokenlock_config;
}

function tokenlock_defaults()
{
    return array(
        'api_base' => 'https://proveitonchain.com',
        'site_key' => '',
        'secret_key' => '',
        'sign_in_page' => '/tokenlock/signin.php',
        'after_sign_in' => '/holders/',
        'after_sign_out' => '/',
        'cookie_name' => 'tokenlock_pass',
        'cookie_path' => '/',
        'max_age_seconds' => 86400,
        'cache_dir' => sys_get_temp_dir(),
        'timeout_seconds' => 8,
        'public_origin' => '',
        // Enterprise access controls: send the page path + method with each pass check (sites with registered
        // keys enforce routes, methods and environments; token-only sites ignore it).
        'check_resource' => true,
        'environment' => '',
        // If our API can't be reached: false (default) = show "try again" (503) and keep the cookie;
        // true = let visitors who have a pass cookie in, unverified. Low-risk content only.
        'fail_open' => false,
        // Strict mode (0.2.1): an answer counts only if complete and allowed === true for exactly this request.
        // null = on, unless fail_open is true or check_resource is false (then off, with a logged warning).
        // true + fail_open / check_resource false = configuration error.
        'strict' => null,
        // Cache good answers on disk. In strict mode, registered-key answers are never cached.
        'cache' => true,
        // Path prefixes that always get JSON 401/403 (API mode). Accept: application/json also does.
        'api_paths' => array(),
        // Early block (0.3.0, early.php): allow/deny before your app boots. See early.php for every key.
        'early' => array(),
    );
}

function tokenlock_env($key)
{
    if (array_key_exists($key, $_ENV) && $_ENV[$key] !== '') {
        return $_ENV[$key];
    }
    $v = getenv($key);
    return ($v !== false && $v !== '') ? $v : null;
}

function tokenlock_config()
{
    global $_tokenlock_config;
    if (is_array($_tokenlock_config)) {
        return $_tokenlock_config;
    }
    $fromFile = array();
    $file = dirname(__FILE__) . '/config.php';
    if (is_readable($file)) {
        $loaded = include $file;
        if (is_array($loaded)) {
            $fromFile = $loaded;
        }
    }
    $cfg = array_merge(tokenlock_defaults(), $fromFile);
    $map = array(
        'TOKENLOCK_API' => 'api_base',
        'TOKENLOCK_SITE_KEY' => 'site_key',
        'TOKENLOCK_SECRET_KEY' => 'secret_key',
        'TOKENLOCK_CACHE_DIR' => 'cache_dir',
        'TOKENLOCK_SIGN_IN_PAGE' => 'sign_in_page',
        'TOKENLOCK_AFTER_SIGN_IN' => 'after_sign_in',
        'TOKENLOCK_AFTER_SIGN_OUT' => 'after_sign_out',
        'TOKENLOCK_PUBLIC_ORIGIN' => 'public_origin',
        'TOKENLOCK_COOKIE_NAME' => 'cookie_name',
        'TOKENLOCK_ENVIRONMENT' => 'environment',
        'TOKENLOCK_FAIL_OPEN' => 'fail_open',
        'TOKENLOCK_STRICT' => 'strict',
    );
    foreach ($map as $env => $key) {
        $v = tokenlock_env($env);
        if ($v !== null) {
            $cfg[$key] = $v;
        }
    }
    $cfg['api_base'] = rtrim($cfg['api_base'], '/');
    if (empty($cfg['cache_dir'])) {
        $cfg['cache_dir'] = sys_get_temp_dir();
    }
    $_tokenlock_config = $cfg;
    return $_tokenlock_config;
}

/** Strip CR/LF so values cannot split HTTP headers. */
function tokenlock_header_safe($s)
{
    return str_replace(array("\r", "\n"), '', (string) $s);
}

/**
 * A safe same-site path to go back to after sign-in
 * (blocks //evil.com and absolute URLs).
 */
function tokenlock_safe_next($v, $fallback = '/')
{
    if (!is_string($v) || $v === '' || strpos($v, '/') !== 0 || strpos($v, '//') === 0 || strpos($v, '/\\') === 0) {
        return $fallback;
    }
    $v = tokenlock_header_safe($v);
    if (strlen($v) > 2000) {
        $v = substr($v, 0, 2000);
    }
    if (strpos($v, '/') !== 0 || strpos($v, '//') === 0 || strpos($v, '/\\') === 0) {
        return $fallback;
    }
    return $v;
}

/** Secure cookies everywhere except plain-http localhost during development. */
function tokenlock_wants_secure($url)
{
    $parts = parse_url($url);
    if (!$parts || empty($parts['scheme'])) {
        return true;
    }
    $host = isset($parts['host']) ? $parts['host'] : '';
    if ($host === '[::1]') {
        $host = '::1';
    }
    if ($parts['scheme'] === 'http' && ($host === 'localhost' || $host === '127.0.0.1' || $host === '::1')) {
        return false;
    }
    return true;
}

function tokenlock_is_https()
{
    $cfg = tokenlock_config();
    if (!empty($cfg['public_origin'])) {
        return strpos($cfg['public_origin'], 'https:') === 0;
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
        $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_PROTO']);
        $p = strtolower(trim($parts[0]));
        if ($p === 'https') {
            return true;
        }
        if ($p === 'http') {
            return false;
        }
    }
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        return true;
    }
    if (isset($_SERVER['SERVER_PORT']) && (int) $_SERVER['SERVER_PORT'] === 443) {
        return true;
    }
    return false;
}

function tokenlock_request_url()
{
    $cfg = tokenlock_config();
    $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
    if (!empty($cfg['public_origin'])) {
        return rtrim($cfg['public_origin'], '/') . $uri;
    }
    $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost';
    return (tokenlock_is_https() ? 'https' : 'http') . '://' . $host . $uri;
}

function tokenlock_self_origin()
{
    $cfg = tokenlock_config();
    if (!empty($cfg['public_origin'])) {
        return rtrim($cfg['public_origin'], '/');
    }
    $parts = parse_url(tokenlock_request_url());
    if (!$parts || empty($parts['scheme']) || empty($parts['host'])) {
        return '';
    }
    $port = isset($parts['port']) ? ':' . $parts['port'] : '';
    return $parts['scheme'] . '://' . $parts['host'] . $port;
}

/** Path + query of this request, for ?next=. */
function tokenlock_request_path()
{
    $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
    if ($uri === '' || strpos($uri, '/') !== 0) {
        $uri = '/' . ltrim($uri, '/');
    }
    return $uri;
}

function tokenlock_pass_looks_valid($pass)
{
    return is_string($pass)
        && $pass !== ''
        && strlen($pass) <= 4000
        && preg_match('/^pp1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $pass);
}

function tokenlock_read_pass()
{
    $cfg = tokenlock_config();
    $name = $cfg['cookie_name'];
    if (!empty($_COOKIE[$name]) && is_string($_COOKIE[$name])) {
        return $_COOKIE[$name];
    }
    if (!empty($_SERVER['HTTP_COOKIE'])) {
        foreach (explode(';', $_SERVER['HTTP_COOKIE']) as $part) {
            $i = strpos($part, '=');
            if ($i === false) {
                continue;
            }
            $k = trim(substr($part, 0, $i));
            if ($k !== $name) {
                continue;
            }
            $v = trim(substr($part, $i + 1));
            $decoded = rawurldecode($v);
            return $decoded;
        }
    }
    return null;
}

/** Set-Cookie value for a verified pass: HttpOnly, Secure, SameSite=Lax, ends when the pass ends. */
function tokenlock_pass_cookie($pass, $info, $requestUrl = null)
{
    $cfg = tokenlock_config();
    $exp = 0;
    if (!empty($info['expires_at'])) {
        $exp = strtotime($info['expires_at']);
        if ($exp === false) {
            $exp = 0;
        }
    }
    $left = (int) floor(($exp - time()));
    $maxAge = max(0, min($left, (int) $cfg['max_age_seconds']));
    $url = $requestUrl !== null ? $requestUrl : tokenlock_request_url();
    $secure = tokenlock_wants_secure($url);
    $parts = array(
        $cfg['cookie_name'] . '=' . rawurlencode($pass),
        'Path=' . (isset($cfg['cookie_path']) && $cfg['cookie_path'] !== '' ? $cfg['cookie_path'] : '/'),
        'Max-Age=' . $maxAge,
        'HttpOnly',
    );
    if ($secure) {
        $parts[] = 'Secure';
    }
    $parts[] = 'SameSite=Lax';
    return implode('; ', $parts);
}

function tokenlock_clear_cookie($requestUrl = null)
{
    $cfg = tokenlock_config();
    $url = $requestUrl !== null ? $requestUrl : tokenlock_request_url();
    $secure = tokenlock_wants_secure($url);
    $parts = array(
        $cfg['cookie_name'] . '=',
        'Path=' . (isset($cfg['cookie_path']) && $cfg['cookie_path'] !== '' ? $cfg['cookie_path'] : '/'),
        'Max-Age=0',
        'HttpOnly',
    );
    if ($secure) {
        $parts[] = 'Secure';
    }
    $parts[] = 'SameSite=Lax';
    return implode('; ', $parts);
}

function tokenlock_send_cookie($cookie)
{
    header('Set-Cookie: ' . tokenlock_header_safe($cookie), false);
}

function tokenlock_cache_path($pass, $secret)
{
    $cfg = tokenlock_config();
    $dir = rtrim($cfg['cache_dir'], '/\\');
    // $pass may carry the resource (path/method/environment) so each resource is cached on its own.
    // File name = <pass hash>_<entry hash>, so tokenlock_clear_cache($pass) removes every resource entry for a pass.
    $parts = explode("\n", (string) $pass, 2);
    return $dir . '/tokenlock_v1_' . tokenlock_cache_prefix($parts[0], $secret) . '_' . substr(hash('sha256', $secret . "\0" . $pass), 0, 32);
}

function tokenlock_cache_prefix($pass, $secret)
{
    return substr(hash('sha256', 'pass' . "\0" . $secret . "\0" . $pass), 0, 16);
}

function tokenlock_cache_get($pass, $secret)
{
    $file = tokenlock_cache_path($pass, $secret);
    if (!is_readable($file)) {
        return null;
    }
    $fh = @fopen($file, 'rb');
    if (!$fh) {
        return null;
    }
    $raw = '';
    if (flock($fh, LOCK_SH)) {
        $raw = stream_get_contents($fh);
        flock($fh, LOCK_UN);
    }
    fclose($fh);
    $row = json_decode($raw, true);
    if (!is_array($row) || empty($row['until']) || empty($row['key_hash']) || empty($row['info'])) {
        return null;
    }
    if (!hash_equals($row['key_hash'], hash('sha256', $secret))) {
        return null;
    }
    if ((int) $row['until'] <= time()) {
        @unlink($file);
        return null;
    }
    return $row['info'];
}

function tokenlock_cache_put($pass, $secret, $info)
{
    $exp = 0;
    if (!empty($info['expires_at'])) {
        $exp = strtotime($info['expires_at']);
        if ($exp === false) {
            $exp = 0;
        }
    }
    // Registered keys: the server says how long the answer may be reused (cache_max_s, 5 s) so revocation is fast.
    $maxS = 60;
    if (isset($info['cache_max_s']) && is_numeric($info['cache_max_s'])) {
        $maxS = max(0, min(60, (int) $info['cache_max_s']));
    }
    if ($maxS <= 0) {
        return;
    }
    $until = min(time() + $maxS, $exp);
    if ($until <= time()) {
        return;
    }
    $cfg = tokenlock_config();
    $dir = rtrim($cfg['cache_dir'], '/\\');
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    if (!is_dir($dir) || !is_writable($dir)) {
        return;
    }
    $file = tokenlock_cache_path($pass, $secret);
    $payload = json_encode(array(
        'until' => $until,
        'key_hash' => hash('sha256', $secret),
        'info' => $info,
    ));
    $fh = @fopen($file, 'cb');
    if (!$fh) {
        return;
    }
    if (flock($fh, LOCK_EX)) {
        ftruncate($fh, 0);
        fwrite($fh, $payload);
        fflush($fh);
        flock($fh, LOCK_UN);
    }
    fclose($fh);
    @chmod($file, 0600);
    tokenlock_cache_prune($dir);
}

function tokenlock_cache_prune($dir)
{
    $files = @glob($dir . '/tokenlock_v1_*');
    if (!is_array($files) || count($files) <= 500) {
        return;
    }
    $now = time();
    foreach ($files as $f) {
        if (count($files) <= 500) {
            break;
        }
        if (is_file($f) && filemtime($f) + 60 < $now) {
            @unlink($f);
        }
    }
}

function tokenlock_clear_cache($pass = null)
{
    $cfg = tokenlock_config();
    $dir = rtrim($cfg['cache_dir'], '/\\');
    if ($pass !== null) {
        $secret = isset($cfg['secret_key']) ? $cfg['secret_key'] : '';
        $files = @glob($dir . '/tokenlock_v1_' . tokenlock_cache_prefix($pass, $secret) . '_*');
        foreach (is_array($files) ? $files : array() as $f) {
            if (is_file($f)) {
                @unlink($f);
            }
        }
        return;
    }
    $files = @glob($dir . '/tokenlock_v1_*');
    if (is_array($files)) {
        foreach ($files as $f) {
            if (is_file($f)) {
                @unlink($f);
            }
        }
    }
}

/**
 * HTTP call. Prefers curl; falls back to file_get_contents.
 * @return array{status:int, body:string}
 */
function tokenlock_http($method, $url, $headers, $body, $timeout)
{
    $cfg = tokenlock_config();
    if (!empty($cfg['http_handler']) && is_callable($cfg['http_handler'])) {
        return call_user_func($cfg['http_handler'], $method, $url, $headers, $body, $timeout);
    }
    $headerLines = array();
    foreach ($headers as $k => $v) {
        $headerLines[] = $k . ': ' . $v;
    }
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        $opts = array(
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        );
        if ($body !== null) {
            $opts[CURLOPT_POSTFIELDS] = $body;
        }
        curl_setopt_array($ch, $opts);
        $raw = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($raw === false) {
            throw new TokenlockException($err ? 'Could not reach the TOKENLOCK API.' : 'Could not reach the TOKENLOCK API.', 0, 'network');
        }
        return array('status' => $status, 'body' => $raw);
    }
    if (!ini_get('allow_url_fopen')) {
        throw new TokenlockException('Could not reach the TOKENLOCK API.', 0, 'network');
    }
    $http = array(
        'method' => $method,
        'header' => implode("\r\n", $headerLines),
        'timeout' => $timeout,
        'follow_location' => 0,
        'ignore_errors' => true,
    );
    if ($body !== null) {
        $http['content'] = $body;
    }
    $ctx = stream_context_create(array(
        'http' => $http,
        'ssl' => array(
            'verify_peer' => true,
            'verify_peer_name' => true,
        ),
    ));
    $raw = @file_get_contents($url, false, $ctx);
    if ($raw === false) {
        throw new TokenlockException('Could not reach the TOKENLOCK API.', 0, 'network');
    }
    $status = 0;
    if (isset($http_response_header) && is_array($http_response_header) && isset($http_response_header[0])) {
        if (preg_match('/\s(\d{3})\s/', $http_response_header[0], $m)) {
            $status = (int) $m[1];
        }
    }
    return array('status' => $status, 'body' => $raw);
}

function tokenlock_request($method, $path, $body = null)
{
    $cfg = tokenlock_config();
    $headers = array(
        'Accept' => 'application/json',
        'x-tokenlock-sdk' => 'php/' . TOKENLOCK_PHP,
        'User-Agent' => 'TOKENLOCK-PHP/' . TOKENLOCK_PHP,
    );
    if (!empty($cfg['secret_key'])) {
        $headers['Authorization'] = 'Bearer ' . $cfg['secret_key'];
    }
    $payload = null;
    if ($body !== null) {
        $headers['Content-Type'] = 'application/json';
        $payload = json_encode($body);
    }
    $timeout = isset($cfg['timeout_seconds']) ? (int) $cfg['timeout_seconds'] : 8;
    if ($timeout < 1) {
        $timeout = 8;
    }
    try {
        $r = tokenlock_http($method, $cfg['api_base'] . $path, $headers, $payload, $timeout);
    } catch (TokenlockException $e) {
        throw $e;
    } catch (Exception $e) {
        throw new TokenlockException('Could not reach the TOKENLOCK API.', 0, 'network');
    }
    $j = json_decode($r['body'], true);
    if ($r['status'] < 200 || $r['status'] >= 300) {
        $msg = (is_array($j) && !empty($j['error'])) ? $j['error'] : ('TOKENLOCK API error ' . $r['status']);
        $code = (is_array($j) && !empty($j['code'])) ? $j['code'] : null;
        throw new TokenlockException($msg, $r['status'], $code);
    }
    return is_array($j) ? $j : array();
}

/**
 * Check a pass with your secret key.
 * Never throws for a bad pass; throws TokenlockException only if the API can't be reached
 * or the secret key is missing.
 */
/**
 * Canonical request path (TOKENLOCK path rules v1, identical to the Node SDK, the Cloudflare example and the API):
 * strip query/fragment; reject backslashes, control bytes and encoded '/', '\\', NUL or '%' (no double decoding);
 * percent-decode once; drop ';params' per segment; collapse '//'; resolve '.' and '..' (above the root = reject);
 * drop the trailing slash. Case is kept; matching is case-insensitive. Returns null when the path must be rejected.
 */
function tokenlock_canonical_path($raw)
{
    $s = (string) $raw;
    if ($s === '' || strlen($s) > 2048) {
        return null;
    }
    $p = preg_split('/[?#]/', $s);
    $s = $p[0];
    if (preg_match('/[\x00-\x1f\x7f\\\\]/', $s) || preg_match('/%(2f|5c|00|25)/i', $s)) {
        return null;
    }
    if (preg_match('/%(?![0-9a-fA-F]{2})/', $s)) {
        return null;
    }
    $s = rawurldecode($s);
    if (!preg_match('//u', $s)) {
        return null; // not valid UTF-8 after decoding (decodeURIComponent would throw)
    }
    if ($s === '' || $s[0] !== '/' || preg_match('/[\x00-\x1f\x7f\\\\]/', $s)) {
        return null;
    }
    $out = array();
    foreach (explode('/', $s) as $seg) {
        $semi = strpos($seg, ';');
        if ($semi !== false) {
            $seg = substr($seg, 0, $semi);
        }
        if ($seg === '' || $seg === '.') {
            continue;
        }
        if ($seg === '..') {
            if (!$out) {
                return null;
            }
            array_pop($out);
            continue;
        }
        $out[] = $seg;
    }
    return '/' . implode('/', $out);
}

/**
 * Does a canonical path match a pattern? '/admin' (exact), '/admin/*' (it and everything under it), '*'. Case-insensitive.
 */
function tokenlock_path_matches($pattern, $path)
{
    $p = strtolower(trim((string) $pattern));
    $q = strtolower((string) $path);
    if ($p === '*' || $p === '/*') {
        return true;
    }
    if (substr($p, -2) === '/*') {
        $base = rtrim(substr($p, 0, -2), '/');
        return $q === $base || strpos($q, $base . '/') === 0 || ($base === '' && strpos($q, '/') === 0);
    }
    $base = rtrim($p, '/');
    if ($base === '') {
        return $q === '/';
    }
    return $q === $base;
}

function tokenlock_clean_resource($resource)
{
    if (!is_array($resource)) {
        return null;
    }
    $out = array();
    if (!empty($resource['path']) && is_string($resource['path'])) {
        $c = tokenlock_canonical_path($resource['path']);
        if ($c === null) {
            throw new TokenlockException('Not a valid path.', 400, 'bad_path');
        }
        $out['path'] = $c;
    }
    if (!empty($resource['method']) && is_string($resource['method'])) {
        $out['method'] = strtoupper(substr($resource['method'], 0, 10));
    }
    if (!empty($resource['environment']) && is_string($resource['environment'])) {
        $out['environment'] = substr($resource['environment'], 0, 30);
    }
    return $out ? $out : null;
}

/** The resource for this request (path + method + configured environment), or null when check_resource is off. */
function tokenlock_current_resource()
{
    $cfg = tokenlock_config();
    if (isset($cfg['check_resource']) && !$cfg['check_resource']) {
        return null;
    }
    return array(
        'path' => tokenlock_request_path(),
        'method' => isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET',
        'environment' => isset($cfg['environment']) ? (string) $cfg['environment'] : '',
    );
}

/** Deny reasons a new sign-in can't fix: answer 403 instead of redirecting to sign-in. */
function tokenlock_forbidden_codes()
{
    return array('route_not_allowed', 'method_not_allowed', 'environment_not_allowed', 'bad_path', 'resource_mismatch');
}

/** Deny reasons meaning "signed in, but not allowed": API mode answers 403 (anything else is 401). */
function tokenlock_denied_codes()
{
    return array_merge(tokenlock_forbidden_codes(), array('key_revoked', 'key_expired', 'pending_approval', 'not_registered', 'org_not_approved', 'org_required', 'entitlement_revoked', 'not_allowed', 'lookup_failed'));
}

function tokenlock_bool($v)
{
    if (is_bool($v) || $v === null) {
        return $v;
    }
    $s = strtolower(trim((string) $v));
    if ($s === '') {
        return null;
    }
    return in_array($s, array('1', 'true', 'yes', 'on'), true);
}

/**
 * Effective strict mode. Throws a TokenlockException (bad_config) for strict + fail_open or strict + no resource check;
 * logs a loud warning when strict is off.
 */
function tokenlock_strict()
{
    static $warned = false;
    $cfg = tokenlock_config();
    $failOpen = (bool) tokenlock_bool(isset($cfg['fail_open']) ? $cfg['fail_open'] : false);
    $checkRes = !(isset($cfg['check_resource']) && tokenlock_bool($cfg['check_resource']) === false);
    $strict = tokenlock_bool(isset($cfg['strict']) ? $cfg['strict'] : null);
    if ($strict === true && $failOpen) {
        throw new TokenlockException('TOKENLOCK: fail_open cannot be used with strict = true.', 0, 'bad_config');
    }
    if ($strict === true && !$checkRes) {
        throw new TokenlockException('TOKENLOCK: check_resource = false cannot be used with strict = true.', 0, 'bad_config');
    }
    if ($strict === null) {
        $strict = !$failOpen && $checkRes;
    }
    if (!$strict && !$warned) {
        $warned = true;
        error_log('[TOKENLOCK] WARNING: strict mode is OFF' . ($failOpen ? '; fail_open lets visitors in UNVERIFIED when the API is down' : '') . (!$checkRes ? '; routes, methods and environments are NOT checked' : '') . '. Use only for low-risk content.');
    }
    return $strict;
}

/** Strict answer check: complete, allowed === true, for exactly this resource. Returns null if good, else a deny code. */
function tokenlock_strict_problem($info, $res)
{
    if (!is_array($info)) {
        return 'bad_answer';
    }
    if (!isset($info['valid']) || $info['valid'] !== true) {
        return !empty($info['code']) ? $info['code'] : 'bad_pass';
    }
    if (empty($info['address']) || !is_string($info['address']) || empty($info['site_id']) || !is_string($info['site_id'])) {
        return 'incomplete_answer';
    }
    $exp = !empty($info['expires_at']) ? strtotime($info['expires_at']) : false;
    if ($exp === false || $exp <= time()) {
        return 'expired';
    }
    if (array_key_exists('access', $info)) {
        $a = $info['access'];
        if (!is_array($a) || !isset($a['mode']) || $a['mode'] !== 'registered_keys' || !isset($a['allowed']) || $a['allowed'] !== true) {
            return (is_array($a) && !empty($a['reason'])) ? $a['reason'] : 'not_allowed';
        }
    }
    if ($res) {
        if (!isset($info['allowed']) || $info['allowed'] !== true) {
            return 'not_allowed';
        }
        $e = isset($info['resource']) ? $info['resource'] : (isset($info['access']['resource']) ? $info['access']['resource'] : null);
        if (!is_array($e)) {
            return 'incomplete_answer';
        }
        foreach (array('path', 'method', 'environment') as $k) {
            $want = isset($res[$k]) ? $res[$k] : null;
            $got = isset($e[$k]) ? $e[$k] : null;
            if ($want !== $got) {
                return 'resource_mismatch';
            }
        }
    } elseif (array_key_exists('allowed', $info) && $info['allowed'] === false) {
        return 'not_allowed';
    }
    return null;
}

/**
 * Check a pass with your secret key. Optional $resource = array('path' => ..., 'method' => ..., 'environment' => ...)
 * for sites with registered keys (the answer then has 'allowed' and 'access').
 */
function tokenlock_verify_pass($pass, $resource = null, $opts = array())
{
    $cfg = tokenlock_config();
    if (empty($cfg['secret_key'])) {
        throw new TokenlockException('Missing secret key. Set it in config.php or TOKENLOCK_SECRET_KEY.', 0, 'no_secret_key');
    }
    if (!tokenlock_pass_looks_valid($pass)) {
        return array('valid' => false, 'code' => 'bad_pass', 'reason' => 'Not a valid pass.');
    }
    try {
        $res = tokenlock_clean_resource($resource);
    } catch (TokenlockException $e) {
        return array('valid' => false, 'allowed' => false, 'code' => 'bad_path', 'reason' => 'Not a valid path.');
    }
    $strict = array_key_exists('strict', $opts) ? (bool) $opts['strict'] : ($res ? tokenlock_strict() : false);
    $useCache = array_key_exists('cache', $opts) ? (bool) $opts['cache'] : (tokenlock_bool(isset($cfg['cache']) ? $cfg['cache'] : true) !== false);
    $ck = $pass . "\n" . ($res ? json_encode($res) : '') . ($strict ? "\ns" : '');
    if ($useCache) {
        $hit = tokenlock_cache_get($ck, $cfg['secret_key']);
        if (is_array($hit)) {
            return $hit;
        }
    }
    $info = tokenlock_request('POST', '/api/v1/gate/verify', array_merge(array('pass' => $pass), $res ? $res : array()));
    if ($strict) {
        $why = tokenlock_strict_problem($info, $res);
        if ($why !== null) {
            if (!is_array($info)) {
                $info = array();
            }
            $keep = isset($info['valid']) && $info['valid'] === false && !empty($info['code']);
            $info['valid'] = false;
            $info['allowed'] = false;
            if (!$keep) {
                $info['code'] = $why;
            }
            return $info;
        }
        if ($useCache && !array_key_exists('access', $info)) {
            tokenlock_cache_put($ck, $cfg['secret_key'], $info);
        }
        return $info;
    }
    $ok = is_array($info) && !empty($info['valid']) && $info['valid'] === true && !empty($info['site_id']) && !empty($info['address'])
        && !(array_key_exists('allowed', $info) && $info['allowed'] === false)
        && !(isset($info['access']['allowed']) && $info['access']['allowed'] === false);
    if (!$ok) {
        if (!is_array($info)) {
            $info = array();
        }
        $info['valid'] = false;
        if (empty($info['code'])) {
            $info['code'] = 'bad_pass';
        }
        return $info;
    }
    if ($useCache) {
        tokenlock_cache_put($ck, $cfg['secret_key'], $info);
    }
    return $info;
}

/** Is this an API request? Accept: application/json (without text/html), or a configured api_paths prefix. */
function tokenlock_is_api_request($path = null)
{
    $cfg = tokenlock_config();
    $path = $path === null ? tokenlock_canonical_path(tokenlock_request_path()) : $path;
    $list = isset($cfg['api_paths']) ? $cfg['api_paths'] : array();
    if (is_string($list)) {
        $list = array_filter(array_map('trim', explode(',', $list)));
    }
    foreach ((array) $list as $p) {
        if ($path !== null && tokenlock_path_matches(rtrim($p, '/') . '/*', $path)) {
            return true;
        }
    }
    $a = strtolower(isset($_SERVER['HTTP_ACCEPT']) ? $_SERVER['HTTP_ACCEPT'] : '');
    return strpos($a, 'application/json') !== false && strpos($a, 'text/html') === false;
}

/**
 * Front-controller helper: lock this request if its canonical path matches one of $patterns ('/admin/*', '/members').
 * Matching is case-insensitive on the canonical path; malformed paths are rejected with 400.
 */
function tokenlock_protect($patterns, $public = array())
{
    $path = tokenlock_canonical_path(tokenlock_request_path());
    if ($path === null) {
        tokenlock_send_json(400, array('error' => 'Not a valid path.', 'code' => 'bad_path', 'reason' => 'Not a valid path.'));
    }
    foreach ((array) $public as $p) {
        if (tokenlock_path_matches($p, $path)) {
            return null;
        }
    }
    foreach ((array) $patterns as $p) {
        if (tokenlock_path_matches($p, $path)) {
            return tokenlock_require();
        }
    }
    return null;
}

/**
 * The signed-in visitor for this request, or null.
 * Does not redirect. Re-checks the cookie with your secret key.
 * @return array|null
 */
function tokenlock_pass()
{
    global $_tokenlock_pass;
    if (is_array($_tokenlock_pass) && (!empty($_tokenlock_pass['valid']) || !empty($_tokenlock_pass['fail_open']))) {
        return $_tokenlock_pass;
    }
    $pass = tokenlock_read_pass();
    if (!$pass) {
        return null;
    }
    try {
        $info = tokenlock_verify_pass($pass, tokenlock_current_resource());
    } catch (TokenlockException $e) {
        throw $e;
    }
    if (!empty($info['valid'])) {
        $_tokenlock_pass = $info;
        return $info;
    }
    return null;
}

/**
 * Call at the top of a locked page. If there is no valid pass, redirect to the
 * sign-in page with ?next=. If our API is unreachable, show a friendly
 * "try again" page and do not let the visitor in.
 * @return array visitor info
 */
function tokenlock_require()
{
    global $_tokenlock_pass;
    $strict = tokenlock_strict(); // throws on unsafe strict configuration
    $path = tokenlock_canonical_path(tokenlock_request_path());
    if ($path === null) {
        tokenlock_send_json(400, array('error' => 'Not a valid path.', 'code' => 'bad_path', 'reason' => 'Not a valid path.'));
    }
    $api = tokenlock_is_api_request($path);
    $pass = tokenlock_read_pass();
    try {
        $info = null;
        if ($pass) {
            $info = tokenlock_verify_pass($pass, tokenlock_current_resource(), array('strict' => $strict));
        }
    } catch (TokenlockException $e) {
        $cfg0 = tokenlock_config();
        $unavailable = ($e->error_code === 'network' || $e->getCode() >= 500 || (int) $e->status >= 500);
        if (!$unavailable) {
            throw $e;
        }
        if (!$strict && tokenlock_bool($cfg0['fail_open'])) {
            if (!headers_sent()) {
                header('X-Tokenlock: fail-open');
            }
            $_tokenlock_pass = array('valid' => false, 'fail_open' => true);
            return $_tokenlock_pass;
        }
        if ($api) {
            if (!headers_sent()) {
                header('Retry-After: 15');
            }
            tokenlock_send_json(503, array('error' => 'Could not check your sign-in right now. Try again in a moment.', 'code' => 'tokenlock_unavailable', 'reason' => 'The verification service did not answer; protected access is denied until it does.'));
        }
        tokenlock_send_unavailable();
    }
    if (is_array($info) && !empty($info['valid'])) {
        $_tokenlock_pass = $info;
        return $info;
    }
    $code = is_array($info) ? (!empty($info['code']) ? $info['code'] : 'bad_pass') : 'signin_required';
    $reason = (is_array($info) && !empty($info['reason'])) ? $info['reason'] : ($info ? 'Not allowed.' : 'Sign in first.');
    if ($api) {
        $status = in_array($code, tokenlock_denied_codes(), true) ? 403 : 401;
        $body = array('error' => $reason, 'code' => $code, 'reason' => $reason, 'correlation_id' => isset($info['correlation_id']) ? $info['correlation_id'] : null);
        tokenlock_send_json($status, $body, ($pass && $status === 401) ? tokenlock_clear_cookie() : null);
    }
    if (in_array($code, tokenlock_forbidden_codes(), true)) {
        tokenlock_send_forbidden(is_array($info) ? $info : array());
    }
    if ($pass) {
        tokenlock_send_cookie(tokenlock_clear_cookie());
    }
    $cfg = tokenlock_config();
    $next = tokenlock_safe_next(tokenlock_request_path(), $cfg['after_sign_in']);
    $signIn = $cfg['sign_in_page'];
    $sep = (strpos($signIn, '?') === false) ? '?' : '&';
    $to = $signIn . $sep . 'next=' . rawurlencode($next);
    if (!headers_sent()) {
        header('Cache-Control: no-store');
        header('Location: ' . tokenlock_header_safe($to), true, 302);
        exit;
    }
    $safe = htmlspecialchars($to, ENT_QUOTES, 'UTF-8');
    echo '<!doctype html><meta charset="utf-8"><title>Sign in</title>';
    echo '<p>Please <a href="' . $safe . '">sign in with your Token</a> to continue.</p>';
    exit;
}

/** JSON response helper for session.php */
function tokenlock_send_json($status, $body, $cookie = null)
{
    if (!headers_sent()) {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        if ($cookie !== null) {
            tokenlock_send_cookie($cookie);
        }
    }
    echo json_encode($body);
    exit;
}

/**
 * POST a pass here (from the sign-in page). Verifies it, sets the cookie, returns JSON.
 * Refuses requests from other sites (Origin check). Fail closed if the API is down.
 */
function tokenlock_handle_session()
{
    if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] !== 'POST') {
        tokenlock_send_json(405, array('ok' => false, 'code' => 'method', 'error' => 'POST only.'));
    }
    $origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : null;
    $self = tokenlock_self_origin();
    if ($origin && $origin !== $self) {
        tokenlock_send_json(403, array('ok' => false, 'code' => 'bad_origin', 'error' => 'Wrong site.'));
    }
    $pass = tokenlock_read_body_pass();
    try {
        $info = tokenlock_verify_pass($pass);
    } catch (TokenlockException $e) {
        tokenlock_send_json(503, array(
            'ok' => false,
            'code' => $e->error_code ? $e->error_code : 'unavailable',
            'error' => 'Could not check the pass right now. Try again.',
        ));
    }
    if (empty($info['valid'])) {
        tokenlock_send_json(401, array(
            'ok' => false,
            'code' => isset($info['code']) ? $info['code'] : 'bad_pass',
            'error' => isset($info['reason']) ? $info['reason'] : 'Not signed in.',
        ));
    }
    $cookie = tokenlock_pass_cookie($pass, $info);
    tokenlock_send_json(200, array(
        'ok' => true,
        'address' => isset($info['address']) ? $info['address'] : null,
        'assets_held' => isset($info['assets_held']) ? $info['assets_held'] : array(),
        'expires_at' => isset($info['expires_at']) ? $info['expires_at'] : null,
    ), $cookie);
}

function tokenlock_read_body_pass()
{
    $ct = isset($_SERVER['CONTENT_TYPE']) ? $_SERVER['CONTENT_TYPE'] : (isset($_SERVER['HTTP_CONTENT_TYPE']) ? $_SERVER['HTTP_CONTENT_TYPE'] : '');
    if (!empty($_POST['pass']) && is_string($_POST['pass'])) {
        return $_POST['pass'];
    }
    $raw = file_get_contents('php://input');
    if (is_string($raw) && strlen($raw) > 16384) {
        return '';
    }
    if ($raw && stripos($ct, 'application/x-www-form-urlencoded') !== false) {
        $parsed = array();
        parse_str($raw, $parsed);
        return (isset($parsed['pass']) && is_string($parsed['pass'])) ? $parsed['pass'] : '';
    }
    $j = json_decode($raw, true);
    if (is_array($j) && isset($j['pass']) && is_string($j['pass'])) {
        return $j['pass'];
    }
    return '';
}

/** Clear the pass cookie and redirect. */
function tokenlock_handle_signout()
{
    $cfg = tokenlock_config();
    $to = tokenlock_safe_next($cfg['after_sign_out'], '/');
    if (!headers_sent()) {
        tokenlock_send_cookie(tokenlock_clear_cookie());
        header('Cache-Control: no-store');
        header('Location: ' . tokenlock_header_safe($to), true, 303);
        exit;
    }
    echo '<!doctype html><meta charset="utf-8"><title>Signed out</title>';
    echo '<p>Signed out. <a href="' . htmlspecialchars($to, ENT_QUOTES, 'UTF-8') . '">Continue</a></p>';
    exit;
}

function tokenlock_send_unavailable()
{
    if (!headers_sent()) {
        http_response_code(503);
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store');
        header('Retry-After: 15');
    }
    $retry = htmlspecialchars(tokenlock_request_path(), ENT_QUOTES, 'UTF-8');
    echo '<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Please try again</title>
  <style>
    body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; background: #f6f4f0; color: #1a1a1a; }
    main { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 32px 16px; }
    .card { background: #fff; max-width: 420px; width: 100%; padding: 36px 32px; border-radius: 16px; box-shadow: 0 10px 40px rgba(40, 20, 0, .08); }
    h1 { font-size: 1.4rem; margin: 0 0 12px; }
    p { margin: 0 0 20px; color: #5c574e; line-height: 1.5; }
    a { display: inline-block; background: #e45a12; color: #fff; text-decoration: none; font-weight: 600; padding: 12px 18px; border-radius: 10px; }
    a:hover { background: #cc4e0e; }
  </style>
</head>
<body>
  <main>
    <div class="card">
      <h1>Please try again</h1>
      <p>We couldn&rsquo;t check your sign-in just now. Nothing on this page was opened. Wait a moment and try again.</p>
      <a href="' . $retry . '">Try again</a>
    </div>
  </main>
</body>
</html>';
    exit;
}

/** 403 for a signed-in key that isn't allowed on this page (registered keys). Keeps the cookie. */
function tokenlock_send_forbidden($info)
{
    if (!headers_sent()) {
        http_response_code(403);
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store');
    }
    $why = htmlspecialchars(isset($info['reason']) ? $info['reason'] : 'Not allowed.', ENT_QUOTES, 'UTF-8');
    $cid = htmlspecialchars(isset($info['correlation_id']) ? (string) $info['correlation_id'] : '', ENT_QUOTES, 'UTF-8');
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Not allowed</title></head>'
        . '<body style="font-family:system-ui,sans-serif;background:#000;color:#f5f5f7;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0">'
        . '<div style="max-width:420px;padding:32px;border:1px solid #333;border-radius:16px"><h1 style="font-size:1.3rem;margin:0 0 10px">Not allowed here</h1>'
        . '<p style="color:#c7c7cc;line-height:1.5;margin:0 0 10px">' . $why . '</p>'
        . ($cid !== '' ? '<p style="color:#86868b;font:12px ui-monospace,monospace;margin:0">Reference: ' . $cid . '</p>' : '')
        . '</div></body></html>';
    exit;
}

function tokenlock_h($s)
{
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}
