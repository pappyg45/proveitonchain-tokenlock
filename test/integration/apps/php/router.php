<?php
// A simple PHP front controller (php -S 127.0.0.1:8080 router.php) protected by the TOKENLOCK drop-in.
// Routing uses the decoded path, case-insensitively, the way many small PHP routers do.
require getenv('TOKENLOCK_PHP_FILE');
tokenlock_protect(array('/admin/*', '/members/*'));
$path = rawurldecode((string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
if (preg_match('#^/admin(/|$)#i', $path)) {
    echo 'ROUTE:admin';
} elseif (preg_match('#^/members(/|$)#i', $path)) {
    echo 'ROUTE:members';
} elseif (preg_match('#^/public(/|$)#i', $path)) {
    echo 'ROUTE:public';
} elseif ($path === '/') {
    echo 'ROUTE:home';
} else {
    http_response_code(404);
    echo 'ROUTE:none';
}
