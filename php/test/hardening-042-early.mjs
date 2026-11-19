// 0.4.2 hardening: the early block (early.php) under php -S with a stub API (no network). Written BEFORE the fixes.
// 0.4.1: with fail_open on, a broken configuration (e.g. a bad secret key) or an outage let requests through, and a
// typo in the 'early' settings silently protected nothing. 0.4.2: fail_open is removed and invalid settings deny.
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PHP = process.env.PHP || 'php';
const PASS = 'pp1.' + 'H'.repeat(40) + '.' + 'Q'.repeat(43);
let failed = 0, passed = 0;
const ok = (c, name, d = '') => { if (c) { passed++; console.log('  ✔', name); } else { failed++; console.log('  ✖', name, d ? '— ' + d : ''); } };

async function run(tlCase, reqPath = '/members/x', env = {}) {
  const php = spawn(PHP, ['-S', '127.0.0.1:0', path.join(root, 'test/fixtures/early-router.php')], { cwd: root, env: { ...process.env, TL_CASE: JSON.stringify(tlCase), ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = ''; php.stderr.on('data', (d) => { out += d; }); php.stdout.on('data', (d) => { out += d; });
  let port;
  for (let i = 0; i < 100 && !port; i++) { await new Promise((r) => setTimeout(r, 30)); port = (out.match(/127\.0\.0\.1:(\d+)\) started/) || [])[1]; }
  try {
    const r = await fetch(`http://127.0.0.1:${port}${reqPath}`, { redirect: 'manual', headers: { cookie: 'tokenlock_pass=' + PASS, accept: 'application/json' } });
    const text = await r.text();
    return { status: r.status, served: text.includes('PAGE-SERVED'), text };
  } finally { php.kill(); }
}

console.log('early block (0.4.2 hardening)');
let r = await run({ answer: 'registered' });
ok(r.served && /allow/.test(r.text), 'control: a valid configuration and a permitted pass open the page', `${r.status} ${r.text.slice(0, 60)}`);
r = await run({ answer: 'down' });
ok(!r.served && r.status === 503, 'API down → 503, nothing served', `${r.status}`);
r = await run({ answer: 'badkey', config: { fail_open: true } });
ok(!r.served, "fail_open => true cannot open pages when the configuration is broken (API says bad_secret_key)", `${r.status} ${r.text.slice(0, 60)}`);
r = await run({ answer: 'down', config: { fail_open: true } });
ok(!r.served, 'fail_open => true cannot open pages during an outage', `${r.status} ${r.text.slice(0, 60)}`);
r = await run({ answer: 'down' }, '/members/x', { TOKENLOCK_FAIL_OPEN: '1' });
ok(!r.served, 'TOKENLOCK_FAIL_OPEN=1 cannot open pages during an outage', `${r.status} ${r.text.slice(0, 60)}`);
r = await run({ answer: 'registered', early_from_config: true, config: { early: { protectt: ['/members/*'] } } });
ok(!r.served, "a typo in 'early' ('protectt') is a configuration error, not 'nothing is protected'", `${r.status} ${r.text.slice(0, 60)}`);
r = await run({ answer: 'registered', config: { check_resource: false } }, '/members/x');
ok(!r.served, 'check_resource (removed option) is a configuration error in the early block', `${r.status} ${r.text.slice(0, 60)}`);
console.log(failed ? `FAILED: ${failed}, passed: ${passed}` : `ALL PASSED: ${passed}`);
process.exit(failed ? 1 : 0);
