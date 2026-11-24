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

test('O1 package.json, JS VERSION and the packed worker example are 0.5.3; the unchanged PHP drop-in stays 0.5.1', () => {
  assert.equal(JSON.parse(read('package.json')).version, '0.5.3');
  const lock = JSON.parse(read('package-lock.json'));
  assert.equal(lock.version, '0.5.3'); assert.equal(lock.packages[''].version, '0.5.3');
  assert.equal(lock.name, '@tokenlock/sdk'); assert.equal(lock.packages[''].name, '@tokenlock/sdk');
  assert.equal(JSON.parse(read('package.json')).homepage, 'https://tokenlock.ai');
  assert.match(read('php/tokenlock/tokenlock.php'), /define\('TOKENLOCK_PHP', '0\.5\.1'\);/);
  assert.match(read('examples/cloudflare-worker/worker.js'), /const VERSION = '0\.5\.3';/);
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

test('O4 repo-wide: the previous hosted origin does not appear except in the GitHub repo path', () => {
  const oldHost = ['proveitonchain', '.com'].join('');
  const self = 'test/default-origin-051.test.mjs';
  const files = execFileSync('git', ['ls-files'], { cwd: ROOT }).toString().split('\n').filter(Boolean);
  const hits = [];
  for (const f of files) {
    if (f === self) continue;
    let s; try { s = read(f); } catch { continue; }
    s.split('\n').forEach((l, i) => { if (l.replace(/github\.com\/pappyg45\/proveitonchain-tokenlock/g, '').includes(oldHost)) hits.push(`${f}:${i + 1}`); });
  }
  assert.deepEqual(hits, [], hits.join(', '));
  const cl = read('CHANGELOG.md');
  assert.ok(cl.indexOf('## 0.5.3') < cl.indexOf('## 0.5.2') && cl.indexOf('## 0.5.2') < cl.indexOf('## 0.5.1') && cl.indexOf('## 0.5.1') < cl.indexOf('## 0.5.0'), '0.5.3 entry on top');
  assert.match(cl, /https:\/\/tokenlock\.ai\/mcp/);
  assert.match(cl, /https:\/\/tokenlock\.ai\/developers#mcp/);
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
  assert.match(read('README.md'), /## Upgrading to 0\.5\.2/);
  assert.match(read('README.md'), /## 0\.5\.3: new package name `@tokenlock\/sdk`/);
  assert.match(read('README.md'), /https:\/\/tokenlock\.ai\/mcp/);
  assert.match(read('README.md'), /https:\/\/tokenlock\.ai\/developers#mcp/);
  assert.match(read('README.md'), /"tokenlock": \{ "url": "https:\/\/tokenlock\.ai\/mcp" \}/);
  assert.doesNotMatch(read('README.md'), /proveitonchain\.com\/mcp/);
  assert.match(read('README.md'), /## Upgrading to 0\.5\.1/); assert.match(read('php/README.md'), /## Upgrading to 0\.5\.1/);
});

test('O6 README and PHP README: no Prove It Onchain prose (the package name is fine); public names kept', () => {
  for (const f of ['README.md', 'php/README.md']) assert.doesNotMatch(read(f).replace(/@proveitonchain\/tokenlock/g, ''), /Prove It On ?chain/i, f);
  assert.doesNotMatch(read('src/core.ts'), /Prove It On ?chain/i);
  const pkg = JSON.parse(read('package.json'));
  assert.equal(pkg.name, '@tokenlock/sdk');
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
  assert.equal(core.VERSION, '0.5.3');
});

test('R053 package renamed to @tokenlock/sdk: same exports map, examples and docs use the new name only', () => {
  const pkg = JSON.parse(read('package.json'));
  assert.equal(pkg.name, '@tokenlock/sdk');
  assert.deepEqual(Object.keys(pkg.exports), ['.', './next', './express', './react', './package.json', './self-verify']);
  assert.match(read('README.md'), /^# @tokenlock\/sdk\n/);
  assert.match(read('README.md'), /npm install @tokenlock\/sdk/);
  const exFiles = ['examples/next-app/package.json', 'examples/express/package.json', 'examples/next-app/middleware.ts', 'examples/next-app/app/signin/page.tsx',
    'examples/next-app/app/api/tokenlock/[action]/route.ts', 'examples/next-app/app/members/page.tsx', 'examples/express/server.js', 'examples/self-verify-enterprise.mjs'];
  for (const f of exFiles) { assert.doesNotMatch(read(f), /@proveitonchain/, f); assert.match(read(f), /@tokenlock\/sdk/, f); }
  // README: the old name appears only in the 0.5.3 migration section
  const readme = read('README.md'); const start = readme.indexOf('## 0.5.3: new package name'); const end = readme.indexOf('## Upgrading to 0.5.2');
  assert.ok(start > 0 && end > start);
  assert.doesNotMatch(readme.slice(0, start) + readme.slice(end), /@proveitonchain/);
});
