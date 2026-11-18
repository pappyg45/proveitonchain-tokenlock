<?php
/**
 * TOKENLOCK early block (0.3.0): allow/deny before your app boots.
 *
 * Runs before WordPress/Laravel/your index.php loads, so locked paths cost almost nothing and app code never runs
 * for visitors without a valid pass. Two ways to install (pick one):
 *
 *   1. php.ini / .user.ini (cPanel: "MultiPHP INI Editor"):   auto_prepend_file = "/home/you/public_html/tokenlock/early.php"
 *   2. First line of your front controller (index.php):       <?php require __DIR__ . '/tokenlock/early.php';
 *
 * Settings live in tokenlock/config.php under 'early' (see config.sample.php):
 *   'early' => array(
 *     'protect'         => array('/members/*', '/api/*'),   // paths that need a pass (nothing else is touched)
 *     'public'          => array('/members/join'),          // carve-outs inside protect
 *     'exclude_paths'   => array('/wp-admin/*', '/wp-login.php'), // never blocked here (your admin login keeps working)
 *     'admin_ips'       => array('203.0.113.7', '2001:db8::/48'), // always let through (your office/VPN)
 *     'deny_ips'        => array('198.51.100.0/24'),          // always 403
 *     'trusted_proxies' => array(),                           // only then is X-Forwarded-For read
 *   )
 *
 * Order: CLI → kill switch → bad path (400 if any reading of it could reach a protected path; else left to your app) → built-in + exclude_paths → admin_ips → deny_ips → public → protect.
 * Lockout safety: the TOKENLOCK folder (sign-in, session, sign-out) is always excluded; exclude_paths and admin_ips
 * win over everything else; and you can switch the early block off without code by creating tokenlock/early.off
 * (e.g. over FTP) or setting TOKENLOCK_EARLY=off.
 * Outages follow your existing policy: fail closed (503) by default; fail_open only when strict mode is off.
 * A broken configuration (missing keys, unsafe strict settings) also fails closed on protected paths only.
 */
if (defined('TOKENLOCK_EARLY_RAN')) {
    return;
}
define('TOKENLOCK_EARLY_RAN', 1);
require_once __DIR__ . '/tokenlock.php';

/** Does $ip fall in $cidr ("1.2.3.4", "1.2.3.0/24", "2001:db8::/32")? */
function tokenlock_ip_in($ip, $cidr)
{
    $cidr = trim((string) $cidr);
    $bits = null;
    if (strpos($cidr, '/') !== false) {
        list($cidr, $b) = explode('/', $cidr, 2);
        if (!ctype_digit($b)) {
            return false;
        }
        $bits = (int) $b;
    }
    $a = @inet_pton((string) $ip);
    $n = @inet_pton($cidr);
    if ($a === false || $n === false || strlen($a) !== strlen($n)) {
        return false;
    }
    $max = strlen($a) * 8;
    $bits = $bits === null ? $max : $bits;
    if ($bits < 0 || $bits > $max) {
        return false;
    }
    $full = intdiv($bits, 8);
    if (substr($a, 0, $full) !== substr($n, 0, $full)) {
        return false;
    }
    $rem = $bits % 8;
    if ($rem === 0) {
        return true;
    }
    $mask = (0xff << (8 - $rem)) & 0xff;
    return (ord($a[$full]) & $mask) === (ord($n[$full]) & $mask);
}

function tokenlock_ip_in_any($ip, $list)
{
    foreach ((array) $list as $c) {
        if (tokenlock_ip_in($ip, $c)) {
            return true;
        }
    }
    return false;
}

/** Client IP: REMOTE_ADDR, or the right-most X-Forwarded-For hop that is not a trusted proxy. */
function tokenlock_client_ip($trusted = array())
{
    $ip = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '';
    if ($trusted && tokenlock_ip_in_any($ip, $trusted) && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $hops = array_reverse(array_map('trim', explode(',', (string) $_SERVER['HTTP_X_FORWARDED_FOR'])));
        foreach ($hops as $h) {
            if (@inet_pton($h) === false) {
                break;
            }
            $ip = $h;
            if (!tokenlock_ip_in_any($h, $trusted)) {
                break;
            }
        }
    }
    return $ip;
}

/**
 * Could any reasonable reading of this malformed raw path reach a protected pattern? Readings: raw, decoded once and
 * twice; backslash as slash; with and without ;params; with dot segments kept (every prefix) and resolved. Errs on
 * the side of "yes".
 */
function tokenlock_early_could_hit($raw, $patterns)
{
    $raw = (string) $raw;
    $cut = strcspn($raw, '?#');
    $raw = substr($raw, 0, $cut);
    $once = rawurldecode($raw);
    $reads = array($raw, $once, rawurldecode($once));
    $cands = array();
    foreach ($reads as $v) {
        $v = str_replace('\\', '/', $v);
        $v = preg_replace('/[\x00-\x1f\x7f]/', '', $v);
        foreach (array(false, true) as $strip) {
            $segs = array();
            foreach (explode('/', $v) as $seg) {
                if ($strip && ($i = strpos($seg, ';')) !== false) {
                    $seg = substr($seg, 0, $i);
                }
                if ($seg !== '') {
                    $segs[] = $seg;
                }
            }
            // every prefix, dot segments kept literally
            $acc = '';
            $cands[] = '/';
            foreach ($segs as $seg) {
                $acc .= '/' . $seg;
                $cands[] = $acc;
            }
            // dot segments resolved, every prefix
            $st = array();
            foreach ($segs as $seg) {
                $t = strtolower($seg);
                if ($t === '.' || $t === '%2e') {
                    continue;
                }
                if ($t === '..' || $t === '.%2e' || $t === '%2e.' || $t === '%2e%2e') {
                    array_pop($st);
                    continue;
                }
                $st[] = $seg;
                $cands[] = '/' . implode('/', $st);
            }
        }
    }
    foreach (array_unique($cands) as $c) {
        foreach ((array) $patterns as $p) {
            if (tokenlock_path_matches($p, $c)) {
                return true;
            }
        }
    }
    return false;
}

function tokenlock_early_off()
{
    $v = tokenlock_env('TOKENLOCK_EARLY');
    return ($v !== null && in_array(strtolower($v), array('off', '0', 'false', 'no'), true)) || is_file(__DIR__ . '/early.off');
}

function tokenlock_early_deny($status, $code, $reason, $api)
{
    if (!headers_sent()) {
        header('Cache-Control: no-store');
        header('X-Tokenlock-Early: ' . $code);
    }
    if ($api) {
        tokenlock_send_json($status, array('error' => $reason, 'code' => $code, 'reason' => $reason));
    }
    http_response_code($status);
    if (!headers_sent()) {
        header('Content-Type: text/html; charset=utf-8');
    }
    echo '<!doctype html><meta charset="utf-8"><title>' . (int) $status . '</title><p>' . htmlspecialchars($reason, ENT_QUOTES, 'UTF-8') . '</p>';
    exit;
}

/**
 * Decide for this request. Returns 'skip' | 'admin' | 'public' | 'allow' | 'fail_open' (or exits with 400/403/503 or a redirect).
 * @param array|null $early overrides config('early')
 */
function tokenlock_early($early = null)
{
    if (PHP_SAPI === 'cli' || tokenlock_early_off()) {
        return 'skip';
    }
    $cfg = tokenlock_config();
    $e = array_merge(array('protect' => array(), 'public' => array(), 'exclude_paths' => array(), 'admin_ips' => array(), 'deny_ips' => array(), 'trusted_proxies' => array()),
        is_array($early) ? $early : (isset($cfg['early']) && is_array($cfg['early']) ? $cfg['early'] : array()));
    if (!$e['protect'] && !$e['deny_ips']) {
        return 'skip';
    }
    $raw = tokenlock_request_path();
    $path = tokenlock_canonical_path($raw);
    $api = $path !== null && tokenlock_is_api_request($path);
    if ($path === null) {
        // Malformed or ambiguous path: 400 only if some reading of it could reach a protected path (strict, the
        // same rules as 0.2.2). Anything else is left to your app, so the early block never breaks unprotected URLs.
        if (tokenlock_early_could_hit($raw, $e['protect'])) {
            tokenlock_early_deny(400, 'bad_path', 'Not a valid path.', true);
        }
        $ip = tokenlock_client_ip($e['trusted_proxies']);
        if (tokenlock_ip_in_any($ip, $e['admin_ips'])) {
            return 'admin';
        }
        if (tokenlock_ip_in_any($ip, $e['deny_ips'])) {
            tokenlock_early_deny(403, 'ip_denied', 'Access from this network is blocked.', false);
        }
        return 'skip';
    }
    // Built-in exclusions: our own sign-in/session/sign-out pages.
    $signin = parse_url((string) $cfg['sign_in_page'], PHP_URL_PATH);
    $own = array(rtrim(str_replace('\\', '/', dirname($signin ? $signin : '/tokenlock/signin.php')), '/') . '/*');
    foreach (array_merge($own, (array) $e['exclude_paths']) as $p) {
        if (tokenlock_path_matches($p, $path)) {
            return 'skip';
        }
    }
    $ip = tokenlock_client_ip($e['trusted_proxies']);
    if (tokenlock_ip_in_any($ip, $e['admin_ips'])) {
        if (!headers_sent()) {
            header('X-Tokenlock-Early: admin');
        }
        return 'admin';
    }
    if (tokenlock_ip_in_any($ip, $e['deny_ips'])) {
        tokenlock_early_deny(403, 'ip_denied', 'Access from this network is blocked.', $api);
    }
    foreach ((array) $e['public'] as $p) {
        if (tokenlock_path_matches($p, $path)) {
            return 'public';
        }
    }
    $hit = false;
    foreach ((array) $e['protect'] as $p) {
        if (tokenlock_path_matches($p, $path)) {
            $hit = true;
            break;
        }
    }
    if (!$hit) {
        return 'skip';
    }
    try {
        $info = tokenlock_require(); // pass check; honors strict / fail_open; redirects or exits when denied
        return !empty($info['fail_open']) ? 'fail_open' : 'allow';
    } catch (Throwable $ex) {
        // Misconfiguration (missing keys, unsafe strict combo, bad secret key): fail closed unless fail_open is
        // explicitly on AND strict mode is off.
        error_log('[TOKENLOCK early] ' . get_class($ex) . ': ' . $ex->getMessage());
        $open = false;
        try {
            $open = tokenlock_bool($cfg['fail_open']) && !tokenlock_strict();
        } catch (Throwable $ignored) {
            $open = false;
        }
        if ($open) {
            if (!headers_sent()) {
                header('X-Tokenlock: fail-open');
            }
            return 'fail_open';
        }
        if (!headers_sent()) {
            header('Retry-After: 30');
        }
        tokenlock_early_deny(503, 'tokenlock_unavailable', 'Could not check your sign-in right now. Try again in a moment.', $api);
    }
    return 'skip';
}

if (!defined('TOKENLOCK_EARLY_MANUAL')) {
    tokenlock_early();
}
