<?php
require_once dirname(__DIR__) . '/tokenlock/tokenlock.php';
tokenlock_require();
$visitor = tokenlock_pass();
$address = isset($visitor['address']) ? $visitor['address'] : '';
$assets = (isset($visitor['assets_held']) && is_array($visitor['assets_held'])) ? $visitor['assets_held'] : array();
$expires = isset($visitor['expires_at']) ? $visitor['expires_at'] : '';
$unverified = !empty($visitor['fail_open']); // TOKENLOCK was unreachable and fail_open is on
if ($unverified) { $address = 'Not verified right now (TOKENLOCK unreachable)'; }
$held = $assets ? implode(', ', $assets) : '';
?><!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Holders only</title>
  <link rel="stylesheet" href="/tokenlock/page.css">
</head>
<body>
  <main>
    <div class="card">
      <div class="check" aria-hidden="true">&#10003;</div>
      <h1>You&rsquo;re in</h1>
      <p class="lead">This page is only shown after we do the Token check.</p>
      <p class="meta">Signed in as</p>
      <p class="addr" title="<?php echo tokenlock_h($address); ?>"><?php echo tokenlock_h($address); ?></p>
<?php if ($held !== '') { ?>
      <p class="meta">Held: <?php echo tokenlock_h($held); ?></p>
<?php } ?>
      <p><a class="signout" href="/tokenlock/signout.php">Sign out</a></p>
    </div>
  </main>
</body>
</html>
