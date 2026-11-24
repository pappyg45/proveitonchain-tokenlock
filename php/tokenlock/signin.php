<?php
require_once dirname(__FILE__) . '/tokenlock.php';
$cfg = tokenlock_config();
$fallback = !empty($cfg['after_sign_in']) ? $cfg['after_sign_in'] : '/holders/';
$next = tokenlock_safe_next(isset($_GET['next']) ? $_GET['next'] : null, $fallback);
$siteKey = isset($cfg['site_key']) ? $cfg['site_key'] : '';

// Already signed in? Go on to the safe next path.
if ($siteKey !== '' && !empty($cfg['secret_key'])) {
    try {
        $visitor = tokenlock_pass();
        if ($visitor) {
            header('Cache-Control: no-store');
            header('Location: ' . tokenlock_header_safe($next), true, 302);
            exit;
        }
    } catch (TokenlockException $e) {
        // API down: still show the sign-in page rather than a locked page.
    }
}

$ready = (strpos($siteKey, 'pk_') === 0 && strlen($siteKey) > 8);
?><!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in with your Token</title>
  <link rel="stylesheet" href="/tokenlock/page.css">
</head>
<body data-next="<?php echo tokenlock_h($next); ?>">
  <main>
    <div class="card">
      <h1>Holders only</h1>
      <p class="lead">Sign in with your Token to continue. We do the Token check &mdash; nothing is paid or sent.</p>
<?php if (!$ready) { ?>
      <p class="status err">This sign-in page is not configured yet. Copy <code>config.sample.php</code> to <code>config.php</code> and add your site key and secret key from the TOKENLOCK dashboard.</p>
<?php } else { ?>
      <button type="button" id="tokenlock-go">Sign in with your Token</button>
      <p class="status" id="tokenlock-status" role="status"></p>
<?php } ?>
      <p class="note">A pass proves you held a token on Bitcoin when you signed in. It does not prove who you are.</p>
    </div>
  </main>
<?php if ($ready) { ?>
  <script src="https://tokenlock.ai/gate.js" data-site-key="<?php echo tokenlock_h($siteKey); ?>"></script>
  <script>
  (function () {
    // Same rules as tokenlock_safe_next() and the SDK's safeNext(): same-site relative paths only.
    function safeNext(v, fallback) {
      if (typeof v !== 'string' || !v || v.length > 2000) return fallback;
      var d = v;
      for (var i = 0; i < 4; i++) {
        if (d.charAt(0) !== '/' || d.charAt(1) === '/' || d.charAt(1) === '\\' || /[\u0000-\u001f\u007f-\u009f\\\u2028\u2029]/.test(d)) return fallback;
        if (!/%[0-9a-f]{2}/i.test(d)) return v;
        var n;
        try { n = decodeURIComponent(d); } catch (e) { return fallback; }
        if (n === d) return v;
        d = n;
      }
      return fallback;
    }
    var go = document.getElementById('tokenlock-go');
    var status = document.getElementById('tokenlock-status');
    var fallback = <?php echo json_encode($fallback); ?>;
    var next = safeNext(document.body.getAttribute('data-next'), fallback);
    go.onclick = function () {
      if (!window.ProveItGate) {
        status.className = 'status err';
        status.textContent = 'Sign-in is not available right now. Refresh and try again.';
        return;
      }
      go.disabled = true;
      status.className = 'status';
      status.textContent = 'Opening your wallet\u2026';
      ProveItGate.signIn().then(function (r) {
        return fetch('/tokenlock/session.php', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ pass: r.pass })
        });
      }).then(function (res) {
        if (res.ok) {
          location.assign(next);
          return;
        }
        return res.json().then(function (j) {
          var msg = (j && j.error) ? j.error : 'Could not sign in.';
          throw new Error(msg);
        }, function () { throw new Error('Could not sign in.'); });
      }).catch(function (e) {
        go.disabled = false;
        status.className = 'status err';
        status.textContent = (e && e.message) ? e.message : 'Could not sign in. Try again.';
      });
    };
  })();
  </script>
<?php } ?>
</body>
</html>
