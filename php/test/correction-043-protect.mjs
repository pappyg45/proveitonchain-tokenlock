// 0.4.3 interface audit finding (written BEFORE the fix): a protect pattern that is not a path (no leading "/", e.g.
// 'members/*') matched nothing, so tokenlock_protect() and the early block silently left those pages unprotected.
// 0.4.3: such a pattern is a configuration error (500/503 bad_config), never "nothing is protected".
// The stub API is DOWN in every case: a protected page answers 5xx, an unprotected page is served.
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PHP = process.env.PHP || 'php';
const PASS = 'pp1.' + 'H'.repeat(40) + '.' + 'Q'.repeat(43);
let failed = 0, passed = 0;
const ok = (c, name, d = '') => { if (c) { passed++; console.log('  ✔', name); } else { failed++; console.log('  ✖', name, d ? '— ' + d : ''); } };
async function run(router, tlCase, reqPath = '/members/x') {
  const php = spawn(PHP, ['-S', '127.0.0.1:0', path.join(root, 'test/fixtures', router)], { cwd: root, env: { ...process.env, TL_CASE: JSON.stringify(tlCase) }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = ''; php.stderr.on('data', (d) => { out += d; }); php.stdout.on('data', (d) => { out += d; });
  let port;
  for (let i = 0; i < 100 && !port; i++) { await new Promise((r) => setTimeout(r, 30)); port = (out.match(/127\.0\.0\.1:(\d+)\) started/) || [])[1]; }
  try {
    const r = await fetch(`http://127.0.0.1:${port}${reqPath}`, { redirect: 'manual', headers: { cookie: 'tokenlock_pass=' + PASS, accept: 'application/json' } });
    const text = await r.text();
    return { status: r.status, served: text.includes('PAGE-SERVED'), text };
  } finally { php.kill(); }
}
console.log('tokenlock_protect() patterns (0.4.3)');
let r = await run('protect-router.php', { patterns: ['/members/*'] });
ok(!r.served && r.status >= 500, 'control: /members/* protects /members/x (API down → 5xx, nothing served)', `${r.status}`);
r = await run('protect-router.php', { patterns: ['/members/*'] }, '/about');
ok(r.served, 'control: an unprotected page is served', `${r.status}`);
for (const p of ['members/*', 'members', ' /members/*', '']) {
  r = await run('protect-router.php', { patterns: [p] });
  ok(!r.served, `pattern ${JSON.stringify(p)} is a configuration error, /members/x not served`, `${r.status} ${r.text.slice(0, 80)}`);
}
r = await run('protect-router.php', { patterns: ['/members/*'], public: ['members/x'] });
ok(!r.served, "a malformed 'public' pattern is a configuration error (never widens access)", `${r.status} ${r.text.slice(0, 80)}`);
console.log('early block patterns (0.4.3)');
r = await run('early-router.php', { answer: 'down', early: { protect: ['/members/*'] } });
ok(!r.served && r.status >= 500, 'control: early protect /members/* (API down → 5xx)', `${r.status}`);
for (const p of ['members/*', ' /members/*']) {
  r = await run('early-router.php', { answer: 'down', early: { protect: [p] } });
  ok(!r.served, `early protect ${JSON.stringify(p)} is a configuration error, /members/x not served`, `${r.status} ${r.text.slice(0, 80)}`);
}
console.log(failed ? `FAILED: ${failed}, passed: ${passed}` : `ALL PASSED: ${passed}`);
process.exit(failed ? 1 : 0);
