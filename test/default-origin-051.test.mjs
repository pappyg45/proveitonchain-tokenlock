// 0.5.1: the default hosted origin, gate.js URL and dashboard/docs/advisory links are https://tokenlock.ai.
// Overrides (apiBase / api / TOKENLOCK_API / api_base) still win. Not an authorization change. Checks the sources, the
// built dist (run `npm run build` first, as for the rest of the suite), the examples, the PHP drop-in and the docs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => readFileSync(join(ROOT, p), 'utf8');
const NEW = 'https://tokenlock.ai';

test('O1 package.json is 0.5.1 and the PHP drop-in is 0.5.1', () => {
  assert.equal(JSON.parse(read('package.json')).version, '0.5.1');
  const lock = JSON.parse(read('package-lock.json'));
  assert.equal(lock.version, '0.5.1'); assert.equal(lock.packages[''].version, '0.5.1');
  assert.match(read('php/tokenlock/tokenlock.php'), /define\('TOKENLOCK_PHP', '0\.5\.1'\);/);
  assert.match(read('examples/cloudflare-worker/worker.js'), /const VERSION = '0\.5\.1';/);
});

test('O2 source defaults: DEFAULT_API, React apiBase doc, self-verify fallbacks, worker fallback, PHP api_base / api', () => {
  assert.match(read('src/core.ts'), /export const DEFAULT_API = 'https:\/\/tokenlock\.ai';/);
  assert.match(read('src/core.ts'), /\/\*\* API origin\. Default https:\/\/tokenlock\.ai \*\//);
  assert.match(read('src/react.tsx'), /\/\*\* API origin\. Default https:\/\/tokenlock\.ai \*\//);
  assert.equal((read('src/self-verify/index.ts').match(/o\.api \|\| 'https:\/\/tokenlock\.ai'/g) || []).length, 2);
  assert.equal((read('examples/cloudflare-worker/worker.js').match(/env\.TOKENLOCK_API \|\| 'https:\/\/tokenlock\.ai'/g) || []).length, 2);
  assert.match(read('php/tokenlock/tokenlock.php'), /'api_base' => 'https:\/\/tokenlock\.ai',/);
  assert.equal((read('php/tokenlock/self-verify.php').match(/\$o\['api'\] \?\? 'https:\/\/tokenlock\.ai'/g) || []).length, 2);
  assert.match(read('php/tokenlock/signin.php'), /<script src="https:\/\/tokenlock\.ai\/gate\.js"/);
});

test('O3 built dist uses https://tokenlock.ai as the default origin (JS and typings)', async () => {
  const dist = join(ROOT, 'dist');
  assert.ok(existsSync(dist), 'run `npm run build` first');
  const files = readdirSync(dist).filter((f) => /\.(c?js|d\.c?ts)$/.test(f));
  for (const f of ['index.js', 'index.cjs', 'express.cjs', 'react.d.ts']) assert.ok(files.includes(f), `dist/${f}`);
  for (const f of files) assert.doesNotMatch(readFileSync(join(dist, f), 'utf8'), /proveitonchain\.com/, `dist/${f}`);
  for (const f of ['index.js', 'index.cjs']) assert.match(readFileSync(join(dist, f), 'utf8'), /https:\/\/tokenlock\.ai/, `dist/${f}`);
  for (const f of files.filter((x) => /^(index|react)\.d\.c?ts$/.test(x))) assert.match(readFileSync(join(dist, f), 'utf8'), /Default https:\/\/tokenlock\.ai/, `dist/${f}`);
  const core = await import(join(dist, 'index.js'));
  assert.equal(core.DEFAULT_API, NEW);
});

test('O4 repo-wide: proveitonchain.com appears only in the three historical CHANGELOG advisory links', () => {
  const files = execFileSync('git', ['ls-files'], { cwd: ROOT }).toString().split('\n').filter(Boolean);
  const hits = [];
  for (const f of files) {
    let s; try { s = read(f); } catch { continue; }
    s.split('\n').forEach((l, i) => { if (/proveitonchain\.com/.test(l.replace(/github\.com\/pappyg45\/proveitonchain-tokenlock/g, ''))) hits.push(`${f}:${i + 1}`); });
  }
  assert.equal(hits.filter((h) => !h.startsWith('CHANGELOG.md:')).length, 0, hits.join(', '));
  const cl = read('CHANGELOG.md');
  assert.equal((cl.match(/proveitonchain\.com/g) || []).length, 3);
  assert.ok(cl.indexOf('## 0.5.1') < cl.indexOf('## 0.5.0') && cl.indexOf('## 0.5.1') >= 0, '0.5.1 entry on top');
  assert.ok(cl.indexOf('proveitonchain.com') > cl.indexOf('## 0.5.0'), 'old links only in history');
});

test('O5 docs and examples use the new dashboard, gate.js and docs URLs, never /tokenlock as the homepage', () => {
  const docs = ['README.md', 'php/README.md', 'docs/self-verify-spec.md', 'examples/express/README.md', 'examples/next-app/README.md', 'examples/next-app/.env.example', 'examples/express/server.js', 'php/tokenlock/config.sample.php'];
  const all = docs.map(read).join('\n');
  assert.doesNotMatch(all, /https:\/\/tokenlock\.ai\/tokenlock(?![/\w-])/, 'no /tokenlock homepage');
  for (const f of ['README.md', 'php/README.md', 'examples/express/README.md', 'examples/next-app/README.md', 'examples/next-app/.env.example', 'examples/express/server.js', 'php/tokenlock/config.sample.php'])
    assert.match(read(f), /https:\/\/tokenlock\.ai\/dashboard/, f);
  assert.match(read('README.md'), /<script src="https:\/\/tokenlock\.ai\/gate\.js"/);
  assert.match(read('examples/express/server.js'), /<script src="https:\/\/tokenlock\.ai\/gate\.js"/);
  assert.match(read('README.md'), /https:\/\/tokenlock\.ai\/docs\/enterprise#timing/);
  assert.match(read('README.md'), /https:\/\/tokenlock\.ai\/\.well-known\/tokenlock-policy-keys\.json/);
  assert.match(read('docs/self-verify-spec.md'), /Web version: https:\/\/tokenlock\.ai\/docs\/self-verify/);
  assert.match(read('README.md'), /## Upgrading to 0\.5\.1/); assert.match(read('php/README.md'), /## Upgrading to 0\.5\.1/);
});

test('O6 README and PHP README: no Prove It Onchain prose (the package name is fine); public names kept', () => {
  for (const f of ['README.md', 'php/README.md']) assert.doesNotMatch(read(f).replace(/@proveitonchain\/tokenlock/g, ''), /Prove It On ?chain/i, f);
  assert.doesNotMatch(read('src/core.ts'), /Prove It On ?chain/i);
  const pkg = JSON.parse(read('package.json'));
  assert.equal(pkg.name, '@proveitonchain/tokenlock');
  assert.equal(pkg.author, 'Prove It Onchain <gotproof@oplanbtc.com>', 'author unchanged (question for Garrett)');
  assert.match(read('src/self-verify/index.ts'), /export function proveitonchainProvider\b/);
  assert.match(read('src/self-verify/index.ts'), /name: 'proveitonchain'/);
});

test('O7 overrides still win (no behavior change): apiBase, then TOKENLOCK_API, then the tokenlock.ai default', async () => {
  const core = await import(join(ROOT, 'dist/index.js'));
  const fetch = async () => new Response('{}');
  const saved = process.env.TOKENLOCK_API;
  try {
    delete process.env.TOKENLOCK_API;
    assert.equal(new core.TokenlockClient({ fetch }).apiBase, NEW, 'default');
    assert.equal(new core.TokenlockClient({ fetch, apiBase: 'https://api.example.com/' }).apiBase, 'https://api.example.com', 'apiBase');
    process.env.TOKENLOCK_API = 'https://env.example.com';
    assert.equal(new core.TokenlockClient({ fetch }).apiBase, 'https://env.example.com', 'TOKENLOCK_API');
    assert.equal(new core.TokenlockClient({ fetch, apiBase: 'https://api.example.com' }).apiBase, 'https://api.example.com', 'apiBase beats TOKENLOCK_API');
  } finally { if (saved === undefined) delete process.env.TOKENLOCK_API; else process.env.TOKENLOCK_API = saved; }
  assert.equal(core.VERSION, '0.5.1');
});
