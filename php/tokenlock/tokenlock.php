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
define('TOKENLOCK_PHP', '0.4.3');

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
    if (!empty($_tokenlock_config['api_base']) && is_string($_tokenlock_config['api_base'])) {
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
        // Token-only sites (registered keys off): true = every holder of your site's token may open every protected
        // page. Passes are then checked for identity and token only; if the site has registered keys after all, its
        // routes, methods and environments are still enforced. Default false (0.4.0).
        'token_only' => false,
        // Enterprise access controls: the page path, method and this environment are sent with every pass check
        // (always, since 0.4.2). 0.4.0: a token-only site has no route policy, so these checks are denied with
        // policy_required unless token_only is true.
        'environment' => '',
        // Strict mode is always on since 0.4.2: an answer counts only if complete, unambiguous and allowed === true
        // for exactly this request. null or true are accepted; false (loose mode) is a configuration error.
        // 0.4.2 removed 'fail_open' and 'check_resource': setting either (any value) is a configuration error.
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
        // Removed in 0.4.2, still read so that setting them is reported as a configuration error (never ignored).
        'TOKENLOCK_FAIL_OPEN' => 'fail_open',
        'TOKENLOCK_CHECK_RESOURCE' => 'check_resource',
        'TOKENLOCK_STRICT' => 'strict',
        'TOKENLOCK_TOKEN_ONLY' => 'token_only',
    );
    foreach ($map as $env => $key) {
        $v = tokenlock_env($env);
        if ($v !== null) {
            $cfg[$key] = $v;
        }
    }
    $cfg['api_base'] = is_string($cfg['api_base']) ? rtrim($cfg['api_base'], '/') : $cfg['api_base'];
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
    // Same rules as safeNext() in the JS SDK and the copy in signin.php: a relative path with a single leading '/'.
    // Rejected: '//', '/\', any backslash, control characters (browsers strip tabs/newlines, so "/\t/evil.com" would
    // become "//evil.com"), U+0080-U+009F, U+2028/2029, and anything that turns into one of those after decoding up
    // to three times ('/%2f%2fevil.com', '/%5cevil.com'). Schemes ('javascript:', 'https://') fail the leading '/'.
    if (!is_string($v) || $v === '' || strlen($v) > 2000) {
        return $fallback;
    }
    $d = $v;
    for ($i = 0; $i < 4; $i++) {
        if ($d[0] !== '/' || (strlen($d) > 1 && ($d[1] === '/' || $d[1] === '\\')) || strpos($d, '\\') !== false
            || preg_match('/[\x00-\x1f\x7f]|\xc2[\x80-\x9f]|\xe2\x80[\xa8\xa9]/', $d)) {
            return $fallback;
        }
        if (!preg_match('/%[0-9a-fA-F]{2}/', $d)) {
            return $v;
        }
        if (preg_match('/%(?![0-9a-fA-F]{2})/', $d)) {
            return $fallback; // decodeURIComponent would throw
        }
        $n = rawurldecode($d);
        if (!preg_match('//u', $n)) {
            return $fallback;
        }
        if ($n === $d) {
            return $v;
        }
        $d = $n;
    }
    return $fallback;
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

/** Remove one cache entry (used when a cached answer no longer checks out). */
function tokenlock_cache_drop($pass, $secret)
{
    $file = tokenlock_cache_path($pass, $secret);
    if (is_file($file)) {
        @unlink($file);
    }
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
    // 0.4.2: answers are capped at 64 KiB and a 2xx answer must be a JSON object; anything else is a bad answer
    // (502, so protected access is denied with 503 like an outage).
    if (!is_array($r) || !isset($r['body']) || !is_string($r['body'])) {
        throw new TokenlockException('TOKENLOCK API answered with something unreadable.', 502, 'bad_answer');
    }
    if (strlen($r['body']) > TOKENLOCK_MAX_ANSWER_BYTES) {
        throw new TokenlockException('TOKENLOCK API answer is too large.', 502, 'bad_answer');
    }
    $j = json_decode($r['body'], true);
    $status = isset($r['status']) ? (int) $r['status'] : 0;
    if ($status < 200 || $status >= 300) {
        $msg = (is_array($j) && !empty($j['error']) && is_string($j['error'])) ? $j['error'] : ('TOKENLOCK API error ' . $status);
        $code = (is_array($j) && !empty($j['code']) && is_string($j['code'])) ? $j['code'] : null;
        throw new TokenlockException($msg, $status, $code);
    }
    if (!tokenlock_is_obj($j)) {
        throw new TokenlockException('TOKENLOCK API answered with something that is not a JSON object.', 502, 'bad_answer');
    }
    return $j;
}

/**
 * Check a pass with your secret key.
 * Never throws for a bad pass; throws TokenlockException only if the API can't be reached
 * or the secret key is missing.
 */
/**
 * Canonical request path (TOKENLOCK path rules v1.1, identical to the Node SDK, the Cloudflare example and the API):
 * strip query/fragment; reject backslashes, control bytes and encoded '/', '\\', NUL, '%', '.' or ';' (no double
 * decoding); percent-decode once; collapse '//'; drop the trailing slash. Ambiguous forms are rejected outright
 * instead of being resolved: any ';' (path parameters) and any '.' or '..' segment, because servers and frameworks
 * resolve them differently ('/admin/..' is '/' here but may be served by an '/admin' route). Case is kept; matching
 * and the resource sent to the API are case-insensitive. Returns null when the path must be rejected (answer 400).
 */
function tokenlock_canonical_path($raw)
{
    $s = (string) $raw;
    if ($s === '' || strlen($s) > 2048) {
        return null;
    }
    $p = preg_split('/[?#]/', $s);
    $s = $p[0];
    if (preg_match('/[\x00-\x1f\x7f\\\\;]/', $s) || preg_match('/%(2f|5c|00|25|2e|3b)/i', $s)) {
        return null;
    }
    if (preg_match('/%(?![0-9a-fA-F]{2})/', $s)) {
        return null;
    }
    $s = rawurldecode($s);
    if (!preg_match('//u', $s)) {
        return null; // not valid UTF-8 after decoding (decodeURIComponent would throw)
    }
    if ($s === '' || $s[0] !== '/' || preg_match('/[\x00-\x1f\x7f\\\\;]/', $s)) {
        return null;
    }
    $out = array();
    foreach (explode('/', $s) as $seg) {
        if ($seg === '.' || $seg === '..') {
            return null;
        }
        if ($seg !== '') {
            $out[] = $seg;
        }
    }
    return '/' . implode('/', $out);
}

/** The one form used for the resource sent to the API, the cache key and the answer check: canonical, lowercased. */
function tokenlock_resource_path($raw)
{
    $c = tokenlock_canonical_path($raw);
    return $c === null ? null : tokenlock_lower($c);
}

/** Lowercase the same way as JavaScript's toLowerCase() where mbstring is available (ASCII-only otherwise). */
function tokenlock_lower($s)
{
    return function_exists('mb_strtolower') ? mb_strtolower((string) $s, 'UTF-8') : strtolower((string) $s);
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
    $r = tokenlock_validate_resource($resource);
    if ($r[1] !== null) {
        throw new TokenlockException($r[1] === 'bad_path' ? 'Not a valid path.' : 'Malformed authorization request.', 400, $r[1]);
    }
    return $r[0];
}

/**
 * 0.4.3: the one schema for an authorization request (same rules as the Node SDK, the Cloudflare worker and the hosted
 * API). Returns array(resource, null) for a route check, array(null, null) for an explicit identity-only request
 * (array('identity_only' => true) and nothing else), or array(null, 'bad_resource' | 'bad_path'). Refused: anything that
 * is not a keyed array, unknown keys, a path without a method (or the reverse), values that are not strings or are
 * empty, whitespace-only or padded, null values, over-long methods / environments (never truncated), relative paths
 * and paths that fail the canonical path rules. A malformed request can never become an identity-only check.
 */
function tokenlock_validate_resource($r)
{
    if (!is_array($r) || ($r && tokenlock_is_list($r))) {
        return array(null, 'bad_resource');
    }
    foreach (array_keys($r) as $k) {
        if (!in_array($k, array('path', 'method', 'environment', 'identity_only'), true)) {
            return array(null, 'bad_resource');
        }
    }
    if (array_key_exists('identity_only', $r)) {
        return ($r['identity_only'] === true && count($r) === 1) ? array(null, null) : array(null, 'bad_resource');
    }
    if (!array_key_exists('path', $r) || !array_key_exists('method', $r)) {
        return array(null, 'bad_resource');
    }
    foreach ($r as $v) {
        if (!is_string($v) || $v === '' || trim($v) !== $v) {
            return array(null, 'bad_resource');
        }
    }
    if (!preg_match('/^[A-Za-z]{1,10}$/D', $r['method'])) {
        return array(null, 'bad_resource');
    }
    if (array_key_exists('environment', $r) && !preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,29}$/D', $r['environment'])) {
        return array(null, 'bad_resource');
    }
    if ($r['path'][0] !== '/') {
        return array(null, 'bad_path');
    }
    $c = tokenlock_resource_path($r['path']);
    if ($c === null) {
        return array(null, 'bad_path');
    }
    $out = array('path' => $c, 'method' => strtoupper($r['method']));
    if (array_key_exists('environment', $r)) {
        $out['environment'] = $r['environment'];
    }
    return array($out, null);
}

/** The resource for this request (path + method + configured environment). Always sent since 0.4.2. */
function tokenlock_current_resource()
{
    $cfg = tokenlock_config();
    $r = array(
        'path' => tokenlock_request_path(),
        'method' => isset($_SERVER['REQUEST_METHOD']) ? (string) $_SERVER['REQUEST_METHOD'] : 'GET',
    );
    if (isset($cfg['environment']) && is_string($cfg['environment']) && $cfg['environment'] !== '') {
        $r['environment'] = $cfg['environment']; // '' = no environment configured (the key is omitted, never sent empty)
    }
    return $r;
}

/** Deny reasons a new sign-in can't fix: answer 403 instead of redirecting to sign-in. */
function tokenlock_forbidden_codes()
{
    return array('route_not_allowed', 'method_not_allowed', 'environment_not_allowed', 'bad_path', 'resource_mismatch', 'policy_required');
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

if (!defined('TOKENLOCK_MAX_ANSWER_BYTES')) {
    define('TOKENLOCK_MAX_ANSWER_BYTES', 65536);
}

/** A JSON list (sequential keys)? */
function tokenlock_is_list($a)
{
    if (!is_array($a)) {
        return false;
    }
    $i = 0;
    foreach ($a as $k => $unused) {
        if ($k !== $i++) {
            return false;
        }
    }
    return true;
}

/** A JSON object (decoded as an associative array; {} decodes to array())? */
function tokenlock_is_obj($a)
{
    return is_array($a) && ($a === array() || !tokenlock_is_list($a));
}

/** Strict boolean-ish: true/false/null for recognised values, the string 'invalid' for anything else. */
function tokenlock_boolish($v)
{
    if (is_bool($v) || $v === null) {
        return $v;
    }
    if ($v === 1 || $v === 0) {
        return $v === 1;
    }
    if (!is_string($v)) {
        return 'invalid';
    }
    $s = strtolower(trim($v));
    if ($s === '') {
        return null;
    }
    if (in_array($s, array('1', 'true', 'yes', 'on'), true)) {
        return true;
    }
    if (in_array($s, array('0', 'false', 'no', 'off'), true)) {
        return false;
    }
    return 'invalid';
}

function tokenlock_str_list_ok($v)
{
    if (is_string($v)) {
        return true;
    }
    if (!is_array($v)) {
        return false;
    }
    foreach ($v as $x) {
        if (!is_string($x)) {
            return false;
        }
    }
    return true;
}

/** Keys allowed in 'early' (early.php). */
function tokenlock_early_keys()
{
    return array('protect', 'public', 'exclude_paths', 'admin_ips', 'deny_ips', 'trusted_proxies');
}

/**
 * 0.4.3: path patterns ('/members/*', '/api', '*') must be paths. A pattern without a leading '/' (e.g. 'members/*')
 * or an empty one matched nothing, which silently left pages unprotected; it is a configuration error now.
 * Returns null when every pattern is usable, else why not.
 */
function tokenlock_patterns_problem($list)
{
    foreach ((array) $list as $p) {
        $t = is_string($p) ? trim($p) : '';
        if ($t === '' || ($t !== '*' && $t[0] !== '/')) {
            return "path patterns must start with '/' (e.g. '/members/*'); got " . (is_string($p) ? "'" . substr($p, 0, 60) . "'" : gettype($p)) . '.';
        }
    }
    return null;
}

/** null if the 'early' settings are usable, else why not. */
function tokenlock_early_problem($e)
{
    if ($e === null || $e === array()) {
        return null;
    }
    if (!is_array($e)) {
        return "'early' must be an array of settings.";
    }
    foreach ($e as $k => $v) {
        if (!in_array($k, tokenlock_early_keys(), true)) {
            return "unknown 'early' setting '" . (is_string($k) ? $k : 'index ' . $k) . "' (allowed: " . implode(', ', tokenlock_early_keys()) . ').';
        }
        if (!tokenlock_str_list_ok($v)) {
            return "'early' setting '$k' must be a path/IP or a list of them.";
        }
        if (in_array($k, array('protect', 'public', 'exclude_paths'), true)) {
            $bad = tokenlock_patterns_problem($v);
            if ($bad !== null) {
                return "'early' setting '$k': " . $bad;
            }
        }
    }
    return null;
}

/**
 * 0.4.2 configuration check. Returns null when the configuration is usable, else the reason. Removed options
 * (fail_open, check_resource), strict = false, unknown options (typos), wrong types and a missing or malformed secret
 * key are all configuration errors: they are reported, never silently ignored or guessed.
 */
function tokenlock_config_problem($cfg = null)
{
    $cfg = $cfg === null ? tokenlock_config() : $cfg;
    if (!is_array($cfg)) {
        return 'the configuration is not an array.';
    }
    $removed = array(
        'fail_open' => "'fail_open' was removed in 0.4.2: protected pages are always denied while the TOKENLOCK API cannot answer. Remove it (and TOKENLOCK_FAIL_OPEN).",
        'check_resource' => "'check_resource' was removed in 0.4.2: the path, method and environment are always checked. Remove it (and TOKENLOCK_CHECK_RESOURCE); token-only sites set 'token_only' => true.",
    );
    foreach ($removed as $k => $why) {
        if (array_key_exists($k, $cfg)) {
            return $why;
        }
    }
    $known = array_merge(array_keys(tokenlock_defaults()), array('http_handler'));
    foreach ($cfg as $k => $v) {
        if (!in_array($k, $known, true)) {
            return "unknown option '" . (is_string($k) ? $k : 'index ' . $k) . "'. Check the spelling: unknown options are refused so a typo can't weaken protection.";
        }
    }
    if (!isset($cfg['secret_key']) || !is_string($cfg['secret_key']) || !preg_match('/^sk_[A-Za-z0-9_-]{20,200}$/', $cfg['secret_key'])) {
        return "'secret_key' must be your sk_… secret key (config.php or TOKENLOCK_SECRET_KEY).";
    }
    $st = isset($cfg['strict']) ? tokenlock_boolish($cfg['strict']) : null;
    if ($st !== null && $st !== true) {
        return "'strict' => false (loose mode) was removed in 0.4.2; strict mode is always on. Remove the 'strict' setting.";
    }
    foreach (array('token_only', 'cache') as $k) {
        if (array_key_exists($k, $cfg) && tokenlock_boolish($cfg[$k]) === 'invalid') {
            return "'$k' must be true or false.";
        }
    }
    $t = isset($cfg['timeout_seconds']) ? $cfg['timeout_seconds'] : 8;
    if (!((is_int($t) || (is_string($t) && ctype_digit($t))) && (int) $t >= 1 && (int) $t <= 60)) {
        return "'timeout_seconds' must be a whole number of seconds from 1 to 60.";
    }
    $m = isset($cfg['max_age_seconds']) ? $cfg['max_age_seconds'] : 86400;
    if (!((is_int($m) || (is_string($m) && ctype_digit($m))) && (int) $m >= 0)) {
        return "'max_age_seconds' must be a whole number of seconds.";
    }
    $api = isset($cfg['api_base']) ? $cfg['api_base'] : '';
    $u = is_string($api) ? @parse_url($api) : false;
    if (!is_array($u) || !isset($u['scheme'], $u['host']) || !in_array(strtolower($u['scheme']), array('https', 'http'), true) || preg_match('/\s/', $api)) {
        return "'api_base' must be an http(s) URL.";
    }
    foreach (array('site_key', 'sign_in_page', 'after_sign_in', 'after_sign_out', 'cookie_name', 'cookie_path', 'cache_dir', 'public_origin', 'environment') as $k) {
        if (isset($cfg[$k]) && !is_string($cfg[$k])) {
            return "'$k' must be a string.";
        }
    }
    if (isset($cfg['environment']) && is_string($cfg['environment']) && $cfg['environment'] !== '' && !preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,29}$/D', $cfg['environment'])) {
        return "'environment' must be 1-30 letters, digits, '_', '.' or '-' (no spaces), or '' for none.";
    }
    if (isset($cfg['api_paths']) && !tokenlock_str_list_ok($cfg['api_paths'])) {
        return "'api_paths' must be a path or a list of paths.";
    }
    $ep = tokenlock_early_problem(isset($cfg['early']) ? $cfg['early'] : null);
    if ($ep !== null) {
        return $ep;
    }
    if (!empty($cfg['http_handler']) && !is_callable($cfg['http_handler'])) {
        return "'http_handler' must be callable.";
    }
    return null;
}

/** Throw TokenlockException('bad_config') when the configuration is not usable. */
function tokenlock_assert_config()
{
    $why = tokenlock_config_problem();
    if ($why !== null) {
        throw new TokenlockException('TOKENLOCK configuration error: ' . $why, 0, 'bad_config');
    }
}

/**
 * Strict mode is always on since 0.4.2. Kept for callers of 0.2.x-0.4.1: checks the configuration (throws a
 * TokenlockException with error_code 'bad_config' when it is not usable) and returns true.
 */
function tokenlock_strict()
{
    tokenlock_assert_config();
    return true;
}

/** Is the echoed resource this request's resource? Paths compare in the lowercased canonical form. */
function tokenlock_same_resource($res, $e)
{
    if (!is_array($e)) {
        return false;
    }
    foreach (array('path', 'method', 'environment') as $k) {
        $want = isset($res[$k]) ? $res[$k] : null;
        $got = isset($e[$k]) ? $e[$k] : null;
        if ($k === 'path' && is_string($got)) {
            $got = tokenlock_lower($got);
        }
        if ($want !== $got) {
            return false;
        }
    }
    return true;
}

/** 0.4.0: a valid answer for a resource with no access block means no route policy applied (token-only). */
function tokenlock_no_policy($info)
{
    return is_array($info) && isset($info['valid']) && $info['valid'] === true && !array_key_exists('access', $info);
}

/** A policy_required denial; identity_valid = the pass itself (identity and token) is good. */
function tokenlock_policy_required($info)
{
    $info = is_array($info) ? $info : array();
    $info['valid'] = false;
    $info['allowed'] = false;
    $info['identity_valid'] = true;
    $info['code'] = 'policy_required';
    $info['reason'] = 'No route policy applies (registered keys are off), so this path, method or environment cannot be authorized. Check identity only, or turn on registered keys and grant the route. Token-only sites: set token_only = true.';
    return $info;
}

/**
 * Strict answer check (the only mode since 0.4.2): complete, unambiguous, allowed === true for exactly this resource.
 * Returns null if good, else a deny code. Wrong types, missing fields and contradictions are all a no.
 */
function tokenlock_strict_problem($info, $res)
{
    if (!tokenlock_is_obj($info)) {
        return 'bad_answer';
    }
    $a = array_key_exists('access', $info) ? $info['access'] : null;
    if (!isset($info['valid']) || $info['valid'] !== true) {
        if (!empty($info['code']) && is_string($info['code'])) {
            return $info['code'];
        }
        return (is_array($a) && !empty($a['reason']) && is_string($a['reason'])) ? $a['reason'] : 'bad_pass';
    }
    // contradictions: a "yes" that also carries an error, a denial code or a failed identity → no
    if ((array_key_exists('code', $info) && $info['code'] !== null && $info['code'] !== 'ok') || array_key_exists('error', $info)
        || (array_key_exists('identity_valid', $info) && $info['identity_valid'] !== true)) {
        return (isset($info['code']) && is_string($info['code']) && preg_match('/^[a-z_]{1,64}$/', $info['code']) && $info['code'] !== 'ok') ? $info['code'] : 'conflicting_answer';
    }
    if (empty($info['address']) || !is_string($info['address']) || empty($info['site_id']) || !is_string($info['site_id'])) {
        return 'incomplete_answer';
    }
    if (array_key_exists('assets_held', $info) && !tokenlock_is_list($info['assets_held'])) {
        return 'incomplete_answer';
    }
    if (!isset($info['expires_at']) || !is_string($info['expires_at']) || !preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/', $info['expires_at'])) {
        return 'incomplete_answer';
    }
    $exp = strtotime($info['expires_at']);
    if ($exp === false || $exp <= time()) {
        return 'expired';
    }
    if ($res && !array_key_exists('access', $info)) {
        return 'policy_required';
    }
    if (array_key_exists('allowed', $info) && $info['allowed'] !== true) {
        return (is_array($a) && isset($a['reason']) && is_string($a['reason']) && $a['reason'] !== 'ok' && $a['reason'] !== '') ? $a['reason'] : 'not_allowed';
    }
    if (array_key_exists('access', $info)) {
        if (!tokenlock_is_obj($a) || !isset($a['mode']) || $a['mode'] !== 'registered_keys' || !isset($a['allowed']) || $a['allowed'] !== true) {
            return (is_array($a) && !empty($a['reason']) && is_string($a['reason'])) ? $a['reason'] : 'not_allowed';
        }
        if (array_key_exists('reason', $a) && $a['reason'] !== 'ok') {
            return 'conflicting_answer';
        }
    }
    $echoes = array();
    if (array_key_exists('resource', $info) && $info['resource'] !== null) {
        $echoes[] = $info['resource'];
    }
    if (is_array($a) && array_key_exists('resource', $a) && $a['resource'] !== null) {
        $echoes[] = $a['resource'];
    }
    if ($res) {
        if (!isset($info['allowed']) || $info['allowed'] !== true) {
            return 'not_allowed';
        }
        if (!$echoes) {
            return 'incomplete_answer';
        }
        foreach ($echoes as $e) {
            if (!tokenlock_is_obj($e)) {
                return 'incomplete_answer';
            }
            if (!tokenlock_same_resource($res, $e)) {
                return 'resource_mismatch';
            }
        }
    } else {
        // an identity answer must not name a resource
        foreach ($echoes as $e) {
            if (!tokenlock_is_obj($e) || isset($e['path']) || isset($e['method']) || isset($e['environment'])) {
                return 'conflicting_answer';
            }
        }
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
        throw new TokenlockException('Missing secret key. Set it in config.php or TOKENLOCK_SECRET_KEY.', 0, 'bad_config');
    }
    tokenlock_assert_config();
    if (!is_array($opts)) {
        $opts = array();
    }
    if (array_key_exists('strict', $opts) && $opts['strict'] !== null && $opts['strict'] !== true) {
        throw new TokenlockException("TOKENLOCK configuration error: 'strict' => false (loose mode) was removed in 0.4.2.", 0, 'bad_config');
    }
    if (array_key_exists('cache', $opts) && !is_bool($opts['cache'])) {
        throw new TokenlockException("TOKENLOCK configuration error: 'cache' must be true or false.", 0, 'bad_config');
    }
    foreach (array_keys($opts) as $k) {
        if (!in_array($k, array('strict', 'cache'), true)) {
            throw new TokenlockException("TOKENLOCK configuration error: unknown option '$k' for tokenlock_verify_pass().", 0, 'bad_config');
        }
    }
    // 0.4.3: the authorization request is validated first. A malformed one is refused and never sent as an
    // identity-only check; an identity-only check must be asked for with array('identity_only' => true).
    list($res, $rerr) = tokenlock_validate_resource($resource);
    if ($rerr === 'bad_path') {
        return array('valid' => false, 'allowed' => false, 'code' => 'bad_path', 'reason' => 'Not a valid path.');
    }
    if ($rerr !== null) {
        throw new TokenlockException("Malformed authorization request: pass array('path' => ..., 'method' => ...) (environment optional) or array('identity_only' => true).", 400, 'bad_resource');
    }
    if (!tokenlock_pass_looks_valid($pass)) {
        return array('valid' => false, 'code' => 'bad_pass', 'reason' => 'Not a valid pass.');
    }
    $strict = true; // 0.4.2: always strict
    $useCache = array_key_exists('cache', $opts) ? $opts['cache'] : (tokenlock_boolish(isset($cfg['cache']) ? $cfg['cache'] : true) !== false);
    // One cache entry per (API, secret key, pass, mode, method, canonical lowercased path, environment). The file name
    // also hashes the secret key. Every hit is checked again against this request's resource before it is used.
    $ck = $pass . "\n" . $cfg['api_base'] . "\n" . ($strict ? 's' : 'l') . "\n" . ($res ? json_encode($res) : '');
    if ($useCache) {
        $hit = tokenlock_cache_get($ck, $cfg['secret_key']);
        if (is_array($hit)) {
            $again = tokenlock_strict_problem($hit, $res) === null && !array_key_exists('access', $hit);
            if ($again) {
                return $hit;
            }
            tokenlock_cache_drop($ck, $cfg['secret_key']);
        }
    }
    $info = tokenlock_request('POST', '/api/v1/gate/verify', $res ? array_merge(array('pass' => $pass), $res) : array('pass' => $pass, 'identity_only' => true));
    $why = tokenlock_strict_problem($info, $res);
    if ($why === 'policy_required' && tokenlock_no_policy($info)) {
        return tokenlock_policy_required($info);
    }
    if ($why !== null) {
        if (!is_array($info)) {
            $info = array();
        }
        $keep = isset($info['valid']) && $info['valid'] === false && !empty($info['code']) && is_string($info['code']);
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

/**
 * The pass check used by tokenlock_require() and tokenlock_pass(): this request's resource, or (token_only) identity
 * and token first, then the resource only if the site turns out to have a route policy.
 */
function tokenlock_check_request($pass, $opts = array())
{
    static $warned = false;
    $cfg = tokenlock_config();
    $res = tokenlock_current_resource();
    tokenlock_assert_config();
    if (tokenlock_boolish(isset($cfg['token_only']) ? $cfg['token_only'] : false) === true) {
        $info = tokenlock_verify_pass($pass, array('identity_only' => true), $opts);
        if (is_array($info) && !empty($info['valid']) && array_key_exists('access', $info) && $res) {
            $info = tokenlock_verify_pass($pass, $res, $opts);
        }
        return $info;
    }
    $info = tokenlock_verify_pass($pass, $res, $opts);
    if (is_array($info) && isset($info['code']) && $info['code'] === 'policy_required' && !empty($info['identity_valid']) && !$warned) {
        $warned = true;
        error_log('[TOKENLOCK] This site has no route policy (registered keys are off), so protected pages are denied with policy_required. If every token holder may open them, set token_only = true. See https://proveitonchain.com/security/advisories/2026-11-18');
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
    $bad = (!is_array($patterns) && !is_string($patterns)) || (!is_array($public) && !is_string($public)) || (array) $patterns === array() ? 'tokenlock_protect() needs a non-empty list of path patterns.' : tokenlock_patterns_problem($patterns);
    if ($bad === null) {
        $bad = tokenlock_patterns_problem($public);
    }
    if ($bad !== null) {
        // 0.4.3: an unusable pattern list never means "nothing is protected" (500, logged; the reason is not shown).
        error_log('[TOKENLOCK] configuration error in tokenlock_protect(), page refused: ' . $bad);
        tokenlock_send_bad_config($path !== null && tokenlock_is_api_request($path));
    }
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
    if (is_array($_tokenlock_pass) && isset($_tokenlock_pass['valid']) && $_tokenlock_pass['valid'] === true) {
        return $_tokenlock_pass;
    }
    $pass = tokenlock_read_pass();
    if (!$pass) {
        return null;
    }
    try {
        $info = tokenlock_check_request($pass);
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
    $path = tokenlock_canonical_path(tokenlock_request_path());
    $api = $path !== null && tokenlock_is_api_request($path);
    $bad = tokenlock_config_problem();
    if ($bad !== null) {
        // 0.4.2: an unusable configuration never opens a protected page (500, logged; the reason is not shown to visitors).
        error_log('[TOKENLOCK] configuration error, protected page refused: ' . $bad);
        tokenlock_send_bad_config($api);
    }
    $strict = true;
    if ($path === null) {
        tokenlock_send_json(400, array('error' => 'Not a valid path.', 'code' => 'bad_path', 'reason' => 'Not a valid path.'));
    }
    $pass = tokenlock_read_pass();
    try {
        $info = null;
        if ($pass) {
            $info = tokenlock_check_request($pass, array('strict' => $strict));
        }
    } catch (TokenlockException $e) {
        if ($e->error_code === 'bad_config') {
            error_log('[TOKENLOCK] configuration error, protected page refused: ' . $e->getMessage());
            tokenlock_send_bad_config($api);
        }
        $unavailable = ($e->error_code === 'network' || $e->getCode() >= 500 || (int) $e->status >= 500);
        if (!$unavailable) {
            throw $e;
        }
        // 0.4.2: fail_open was removed; an unreachable API or an unreadable answer always denies.
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

/** 500 for an unusable configuration (0.4.2). Never opens the page; the details go to the error log only. */
function tokenlock_send_bad_config($api)
{
    if ($api) {
        tokenlock_send_json(500, array('error' => 'This site\'s sign-in settings are invalid, so protected access is refused.', 'code' => 'bad_config', 'reason' => 'Configuration error (see the server error log).'));
    }
    if (!headers_sent()) {
        http_response_code(500);
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store');
    }
    echo '<!doctype html><meta charset="utf-8"><title>Configuration error</title><p>This page is locked and the site&rsquo;s sign-in settings are invalid, so it was not opened. The site owner can find the reason in the server error log.</p>';
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
        $info = tokenlock_verify_pass($pass, array('identity_only' => true));
    } catch (TokenlockException $e) {
        if ($e->error_code === 'bad_config') {
            error_log('[TOKENLOCK] configuration error, sign-in refused: ' . $e->getMessage());
        }
        tokenlock_send_json($e->error_code === 'bad_config' ? 500 : 503, array(
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
