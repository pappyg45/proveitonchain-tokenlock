// HTTP tests against a local `php -S` with a mock TOKENLOCK API (no production, no keys).
import http from 'node:http';
import { spawn } from 'node:child_process';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import net from 'node:net';
// RC5 (disclosed, test harness only): ports come from the OS and a php -S that exits at startup fails the start. Before,
// ports were random in a ~900-port range: two servers could pick the same one, the second failed to bind, and its
// requests reached the first server (seen once in the RC5 final run: early.mjs 'no early settings' got 302).
const freePort = () => new Promise((ok, no) => { const s = net.createServer(); s.on('error', no); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => ok(p)); }); });
const alive = async (proc, what) => { await new Promise((r) => setTimeout(r, 150)); if (proc.exitCode !== null || proc.signalCode) throw new Error(`${what}: php -S exited at startup (port in use?)`); };

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PHP = process.env.PHP || 'php';
const SK = 'sk_' + 'a'.repeat(43);
const PK = 'pk_' + 'b'.repeat(43);
const GOOD = 'pp1.' + 'Z'.repeat(40) + '.' + 'Q'.repeat(43);
const FORGED = 'pp1.' + 'Y'.repeat(40) + '.' + 'Q'.repeat(43);
const DOWN = 'pp1.' + 'D'.repeat(40) + '.' + 'Q'.repeat(43);
const future = () => new Date(Date.now() + 3600e3).toISOString();

const results = [];
async function step(name, fn) {
  try { await fn(); results.push(['PASS', name]); console.log('  ✔', name); }
  catch (e) { results.push(['FAIL', name, e.message]); console.log('  ✖', name, '-', e.message); }
}

function cookie(res, name = 'tokenlock_pass') {
  const raw = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  const list = raw.length ? raw : (res.headers.get('set-cookie') ? [res.headers.get('set-cookie')] : []);
  return list.find((c) => c.startsWith(name + '=')) || list[0] || '';
}

const mock = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const body = Buffer.concat(chunks).toString();
    const j = body ? JSON.parse(body) : {};
    const send = (o, s = 200) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (req.url.endsWith('/api/v1/gate/verify')) {
      const auth = req.headers.authorization || '';
      if (auth !== 'Bearer ' + SK) return send({ valid: false, code: 'bad_secret_key' });
      if (j.pass === DOWN) return send({ error: 'busy', code: 'kv_unavailable' }, 503);
      const echo = j.path || j.method || j.environment ? { allowed: true, resource: { path: j.path ?? null, method: j.method ?? null, environment: j.environment ?? null } } : {};
      if (j.pass === GOOD) return send({ valid: true, address: 'bc1qtest', assets_held: ['TOKENLOCK'], site_id: 's1', origin: 'http://localhost', expires_at: future(), ...echo });
      return send({ valid: false, code: 'bad_pass', reason: 'Not a valid pass.' });
    }
    return send({ error: 'no' }, 404);
  });
});
await new Promise((r) => mock.listen(0, '127.0.0.1', r));
const mockPort = mock.address().port;
const API = `http://127.0.0.1:${mockPort}`;

const php = spawn(PHP, ['-S', '127.0.0.1:0', '-t', root], {
  cwd: root,
  env: {
    ...process.env,
    TOKENLOCK_API: API,
    TOKENLOCK_SITE_KEY: PK,
    TOKENLOCK_SECRET_KEY: SK,
    TOKENLOCK_CACHE_DIR: path.join(root, 'tokenlock', 'cache'),
    TOKENLOCK_TOKEN_ONLY: '1', // 0.4.0: the mock is a token-only site; every holder may open the holders page
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let phpOut = '';
php.stderr.on('data', (d) => { phpOut += d.toString(); });
php.stdout.on('data', (d) => { phpOut += d.toString(); });

let port;
for (let i = 0; i < 50 && !port; i++) {
  await new Promise((r) => setTimeout(r, 50));
  const m = phpOut.match(/Development Server \(http:\/\/127\.0\.0\.1:(\d+)\) started/);
  if (m) port = Number(m[1]);
}
if (!port) {
  // php -S 127.0.0.1:0 may not support port 0 on all builds. Retry with an explicit port.
  php.kill();
  port = 18080;
  const php2 = spawn(PHP, ['-d', 'display_errors=0', '-S', `127.0.0.1:${port}`, '-t', root], {
    cwd: root,
    env: {
      ...process.env,
      TOKENLOCK_API: API,
      TOKENLOCK_SITE_KEY: PK,
      TOKENLOCK_SECRET_KEY: SK,
      TOKENLOCK_CACHE_DIR: path.join(root, 'tokenlock', 'cache'),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  php.killed || null;
  global.__php = php2;
  php2.stderr.on('data', (d) => { phpOut += d.toString(); });
  await new Promise((r) => setTimeout(r, 400));
} else {
  global.__php = php;
}
const LOCAL = `http://127.0.0.1:${port}`;
console.log('php', LOCAL, 'mock api', API);

try {
  await step('no pass → 302 to sign-in page with ?next', async () => {
    const r = await fetch(LOCAL + '/holders/?x=1', { redirect: 'manual' });
    assert.equal(r.status, 302);
    const loc = r.headers.get('location');
    assert.equal(loc, '/tokenlock/signin.php?next=' + encodeURIComponent('/holders/?x=1'));
    assert.doesNotMatch(await r.text(), /Signed in as|bc1qtest/i);
  });
  await step('forged pass cookie → 302 and cookie cleared', async () => {
    const r = await fetch(LOCAL + '/holders/', { redirect: 'manual', headers: { cookie: 'tokenlock_pass=' + FORGED } });
    assert.equal(r.status, 302);
    assert.match(cookie(r), /tokenlock_pass=; .*Max-Age=0/);
  });
  await step('good pass cookie → holders page shows the address', async () => {
    const r = await fetch(LOCAL + '/holders/', { headers: { cookie: 'tokenlock_pass=' + GOOD } });
    assert.equal(r.status, 200);
    const t = await r.text();
    assert.match(t, /bc1qtest/);
    assert.match(t, /You(?:'|\&rsquo;|&apos;).{0,2}re in/);
  });
  await step('0.4.0: token-only site without token_only → holders page 403 policy_required (no route policy)', async () => {
    const port3 = await freePort();
    const p3 = spawn(PHP, ['-d', 'display_errors=0', '-S', `127.0.0.1:${port3}`, '-t', root], { cwd: root, env: { ...process.env, TOKENLOCK_API: API, TOKENLOCK_SITE_KEY: PK, TOKENLOCK_SECRET_KEY: SK, TOKENLOCK_CACHE_DIR: path.join(root, 'tokenlock', 'cache'), TOKENLOCK_TOKEN_ONLY: '' }, stdio: 'ignore' });
    try {
      await new Promise((r) => setTimeout(r, 500)); await alive(p3, 'port3');
      const r = await fetch(`http://127.0.0.1:${port3}/holders/`, { redirect: 'manual', headers: { cookie: 'tokenlock_pass=' + GOOD, accept: 'application/json' } });
      assert.equal(r.status, 403); assert.equal((await r.json()).code, 'policy_required');
    } finally { p3.kill(); }
  });
  await step('forged pass → POST session.php is 401, no cookie', async () => {
    const r = await fetch(LOCAL + '/tokenlock/session.php', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: LOCAL },
      body: JSON.stringify({ pass: FORGED }),
    });
    assert.equal(r.status, 401);
    assert.equal(r.headers.get('set-cookie'), null);
  });
  await step('session exchange from another site → 403', async () => {
    const r = await fetch(LOCAL + '/tokenlock/session.php', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://evil.example' },
      body: JSON.stringify({ pass: GOOD }),
    });
    assert.equal(r.status, 403);
    const j = await r.json();
    assert.equal(j.code, 'bad_origin');
  });
  await step('good pass → POST session.php sets HttpOnly SameSite=Lax cookie (not Secure on localhost)', async () => {
    const r = await fetch(LOCAL + '/tokenlock/session.php', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: LOCAL },
      body: JSON.stringify({ pass: GOOD }),
    });
    assert.equal(r.status, 200);
    const sc = cookie(r);
    assert.match(sc, /tokenlock_pass=pp1\./);
    assert.match(sc, /HttpOnly/);
    assert.match(sc, /SameSite=Lax/);
    assert.doesNotMatch(sc, /Secure/);
    const j = await r.json();
    assert.equal(j.ok, true);
    assert.equal(j.address, 'bc1qtest');
  });
  await step('open redirect blocked on the sign-in page', async () => {
    for (const evil of ['https://evil.com', '//evil.com', '/\\evil.com']) {
      const r = await fetch(LOCAL + '/tokenlock/signin.php?next=' + encodeURIComponent(evil));
      assert.equal(r.status, 200);
      const t = await r.text();
      const m = t.match(/data-next="([^"]*)"/);
      assert.ok(m, 'data-next missing');
      assert.equal(m[1], '/holders/', 'next=' + evil + ' became ' + m[1]);
      assert.doesNotMatch(t, /evil\.com/);
    }
    const ok = await fetch(LOCAL + '/tokenlock/signin.php?next=' + encodeURIComponent('/holders/area?x=1'));
    const t = await ok.text();
    assert.match(t, /data-next="\/holders\/area\?x=1"/);
  });
  await step('sign-in page uses the site key, gate.js, and Sign in with your Token', async () => {
    const r = await fetch(LOCAL + '/tokenlock/signin.php');
    const t = await r.text();
    assert.match(t, /Sign in with your Token/);
    assert.match(t, /We do the Token check/);
    assert.match(t, /proveitonchain\.com\/gate\.js/);
    assert.match(t, new RegExp('data-site-key="' + PK + '"'));
    assert.doesNotMatch(t, /sk_/);
  });
  await step('API unavailable (503) → fail closed: 503 "try again" page, cookie kept, nothing shown', async () => {
    const r = await fetch(LOCAL + '/holders/', { redirect: 'manual', headers: { cookie: 'tokenlock_pass=' + DOWN } });
    assert.equal(r.status, 503); assert.equal(r.headers.get('retry-after'), '15');
    assert.equal(r.headers.get('set-cookie'), null);
    const t = await r.text(); assert.match(t, /Please try again/); assert.doesNotMatch(t, /You(?:'|&rsquo;)re in/);
  });
  await step('0.4.2: TOKENLOCK_FAIL_OPEN=1 (removed option) is a configuration error → 500, nothing shown, outage or not', async () => {
    const port2 = await freePort();
    const p2 = spawn(PHP, ['-d', 'display_errors=1', '-S', `127.0.0.1:${port2}`, '-t', root], { cwd: root, env: { ...process.env, TOKENLOCK_API: API, TOKENLOCK_SITE_KEY: PK, TOKENLOCK_SECRET_KEY: SK, TOKENLOCK_CACHE_DIR: path.join(root, 'tokenlock', 'cache'), TOKENLOCK_FAIL_OPEN: '1' }, stdio: 'ignore' });
    try {
      await new Promise((r) => setTimeout(r, 500)); await alive(p2, 'port2');
      for (const c of [DOWN, GOOD]) {
        const r = await fetch(`http://127.0.0.1:${port2}/holders/`, { redirect: 'manual', headers: { cookie: 'tokenlock_pass=' + c } });
        assert.equal(r.status, 500); assert.equal(r.headers.get('x-tokenlock'), null);
        const body = await r.text(); assert.doesNotMatch(body, /You(?:'|&rsquo;)re in|Not verified right now/); assert.doesNotMatch(body, /Warning|Notice|Fatal|sk_/);
      }
    } finally { p2.kill(); }
  });
  await step('sign-out clears the cookie and 303s', async () => {
    const r = await fetch(LOCAL + '/tokenlock/signout.php', { redirect: 'manual' });
    assert.equal(r.status, 303);
    assert.match(cookie(r), /Max-Age=0/);
    assert.equal(r.headers.get('location'), '/');
  });
} finally {
  if (global.__php) global.__php.kill();
  php.kill();
  mock.close();
}
const failed = results.filter((r) => r[0] === 'FAIL').length;
console.log(`\n${results.length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
