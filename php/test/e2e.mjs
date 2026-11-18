// End-to-end against production (https://proveitonchain.com) and a local PHP server.
// Creates a throwaway account + test site through the dashboard API, runs the failure
// paths, then deletes the site. No funds, no transactions: the account key is random
// and lives only in memory. Secrets are never printed.
import http from 'node:http';
import { spawn } from 'node:child_process';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { secp256k1 } from '../../tokenlock-sdk/node_modules/@noble/curves/secp256k1.js';
import { sha256 } from '../../tokenlock-sdk/node_modules/@noble/hashes/sha2.js';
import { ripemd160 } from '../../tokenlock-sdk/node_modules/@noble/hashes/legacy.js';

const API = process.env.TOKENLOCK_API || 'https://proveitonchain.com';
const PHP = process.env.PHP || 'php';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const A = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ123456789'.split('').sort((a, b) => '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.indexOf(a) - '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.indexOf(b)).join('');
function b58check(payload) {
  const full = new Uint8Array([...payload, ...sha256(sha256(payload)).slice(0, 4)]);
  let n = BigInt('0x' + Buffer.from(full).toString('hex')); let s = '';
  while (n > 0n) { s = A[Number(n % 58n)] + s; n /= 58n; }
  for (const b of full) { if (b === 0) s = '1' + s; else break; }
  return s;
}
const priv = secp256k1.utils.randomSecretKey();
const address = b58check(new Uint8Array([0, ...ripemd160(sha256(secp256k1.getPublicKey(priv, true)))]));
function sign(msg) {
  const m = Buffer.from(msg); const pre = Buffer.from('\x18Bitcoin Signed Message:\n');
  const len = m.length < 253 ? Buffer.from([m.length]) : Buffer.from([253, m.length & 255, m.length >> 8]);
  const s = secp256k1.sign(sha256(sha256(Buffer.concat([pre, len, m]))), priv, { prehash: false, format: 'recovered' });
  return Buffer.concat([Buffer.from([31 + s[0]]), Buffer.from(s.slice(1))]).toString('base64');
}

let cookie = '';
async function dash(method, path, body) {
  const r = await fetch(API + '/api/v1/tokenlock/' + path, { method, headers: { origin: API, 'content-type': 'application/json', cookie }, body: body ? JSON.stringify(body) : undefined });
  const sc = r.headers.get('set-cookie'); if (sc && sc.startsWith('tl_session=')) cookie = sc.split(';')[0];
  const j = await r.json().catch(() => null);
  if (!r.ok) throw new Error(`${path}: ${r.status} ${j?.code || ''}`.trim());
  return j;
}

const results = [];
async function step(name, fn) {
  try { await fn(); results.push(['PASS', name]); console.log('  ✔', name); }
  catch (e) { results.push(['FAIL', name, e.message]); console.log('  ✖', name, '-', e.message); }
}

function setCookie(res, name = 'tokenlock_pass') {
  const raw = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  const list = raw.length ? raw : (res.headers.get('set-cookie') ? [res.headers.get('set-cookie')] : []);
  return list.find((c) => c.startsWith(name + '=')) || list[0] || '';
}

function freePort() {
  return new Promise((resolve) => {
    const s = http.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

const port = await freePort();
const LOCAL = `http://127.0.0.1:${port}`;
let site, php;

try {
  console.log('setup: dashboard sign-in and test site');
  const ch = await dash('POST', 'auth/challenge', {});
  await dash('POST', 'auth/verify', { challenge_id: ch.challenge_id, address, signature: sign(ch.message) });
  const made = await dash('POST', 'sites', { name: 'PHP e2e test (auto-deleted)', origins: LOCAL, assets: 'TOKENLOCK' });
  site = made.site;
  const sk = made.secret_key;
  const pk = site.publishable_key;
  if (!sk || !pk) throw new Error('dashboard did not return keys');
  console.log('  site', site.id, 'origin', LOCAL, 'tokens', (site.assets || []).join(','));

  const cacheDir = path.join(root, 'tokenlock', 'cache');
  php = spawn(PHP, ['-d', 'display_errors=0', '-S', `127.0.0.1:${port}`, '-t', root], {
    cwd: root,
    env: {
      ...process.env,
      TOKENLOCK_API: API,
      TOKENLOCK_SITE_KEY: pk,
      TOKENLOCK_SECRET_KEY: sk,
      TOKENLOCK_CACHE_DIR: cacheDir,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let ready = false;
  const onOut = (d) => { if (String(d).includes('started')) ready = true; };
  php.stderr.on('data', onOut);
  php.stdout.on('data', onOut);
  for (let i = 0; i < 40 && !ready; i++) await new Promise((r) => setTimeout(r, 50));
  // Even if the banner is missed, try a request.
  for (let i = 0; i < 20; i++) {
    try { await fetch(LOCAL + '/tokenlock/page.css'); break; } catch { await new Promise((r) => setTimeout(r, 50)); }
  }

  await step('no pass → 302 to sign-in page with ?next', async () => {
    const r = await fetch(LOCAL + '/holders/area?x=1', { redirect: 'manual' });
    // /holders/area may 404 through require if the file doesn't exist — php -S 404s before PHP runs.
    // Use /holders/ and /holders/index.php, which exist.
    const r2 = await fetch(LOCAL + '/holders/?x=1', { redirect: 'manual' });
    assert.equal(r2.status, 302);
    assert.equal(r2.headers.get('location'), '/tokenlock/signin.php?next=' + encodeURIComponent('/holders/?x=1'));
    assert.doesNotMatch(await r2.text(), /Signed in as|bc1qtest/);
  });
  await step('forged pass cookie → 302 and cookie cleared (checked by production API)', async () => {
    const forged = 'pp1.eyJ2IjoxLCJzdWIiOiIxQSIsImgiOlsiVE9LRU5MT0NLIl0sInMiOiJodHRwOi8vbG9jYWxob3N0Iiwic3QiOiJ4IiwiaSI6MSwiZSI6OTk5OTk5OTk5OTk5OX0.' + 'A'.repeat(43);
    const r = await fetch(LOCAL + '/holders/', { redirect: 'manual', headers: { cookie: 'tokenlock_pass=' + forged } });
    assert.equal(r.status, 302);
    assert.match(setCookie(r), /tokenlock_pass=; .*Max-Age=0/);
  });
  await step('forged pass → POST session.php is 401, no cookie', async () => {
    const r = await fetch(LOCAL + '/tokenlock/session.php', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: LOCAL },
      body: JSON.stringify({ pass: 'pp1.' + 'e'.repeat(60) + '.' + 'A'.repeat(43) }),
    });
    assert.equal(r.status, 401);
    assert.equal(r.headers.get('set-cookie'), null);
    const j = await r.json();
    assert.equal(j.ok, false);
  });
  await step('session exchange from another site → 403', async () => {
    const r = await fetch(LOCAL + '/tokenlock/session.php', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://evil.example' },
      body: JSON.stringify({ pass: 'x' }),
    });
    assert.equal(r.status, 403);
  });
  await step('open redirect blocked', async () => {
    const r = await fetch(LOCAL + '/tokenlock/signin.php?next=' + encodeURIComponent('https://evil.example'));
    const t = await r.text();
    const m = t.match(/data-next="([^"]*)"/);
    assert.ok(m);
    assert.equal(m[1], '/holders/');
    assert.doesNotMatch(t, /evil\.example/);
  });
  await step('wrong origin → challenge refused (403 origin_not_allowed)', async () => {
    const r = await fetch(API + '/api/v1/gate/challenge', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ site_key: pk, origin: 'https://evil.example' }),
    });
    const j = await r.json().catch(() => ({}));
    assert.equal(r.status, 403);
    assert.equal(j.code, 'origin_not_allowed');
  });
  await step('right origin → challenge uses the dashboard token choice (TOKENLOCK); non-holder refused', async () => {
    const r = await fetch(API + '/api/v1/gate/challenge', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: LOCAL },
      body: JSON.stringify({ site_key: pk, origin: LOCAL }),
    });
    const ch2 = await r.json();
    assert.ok(r.ok, 'challenge failed: ' + (ch2.code || r.status));
    assert.deepEqual(ch2.assets, ['TOKENLOCK']);
    assert.equal(ch2.site_id, site.id);
    const s = await fetch(API + '/api/v1/gate/signin', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: LOCAL },
      body: JSON.stringify({ challenge_id: ch2.challenge_id, address, signature: sign(ch2.message) }),
    });
    const out = await s.json();
    assert.equal(out.valid, false);
    assert.equal(out.code, 'not_holder');
  });
  await step('unknown secret key → verify is never valid', async () => {
    const r = await fetch(API + '/api/v1/gate/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer sk_' + 'Z'.repeat(43) },
      body: JSON.stringify({ pass: 'pp1.' + 'e'.repeat(60) + '.' + 'A'.repeat(43) }),
    });
    const v = await r.json();
    assert.equal(v.valid, false);
  });
} finally {
  if (php) { try { php.kill(); } catch {} }
  if (site) {
    try { await dash('POST', `sites/${site.id}/delete`, {}); console.log('cleanup: test site deleted'); }
    catch (e) { console.log('cleanup FAILED', e.message); }
  }
  try { await dash('POST', 'auth/logout', {}); } catch {}
}
const failed = results.filter((r) => r[0] === 'FAIL').length;
console.log(`\n${results.length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
