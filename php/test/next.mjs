// The browser copy of safeNext in signin.php and the PHP tokenlock_safe_next() agree with the shared next vectors.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const N = JSON.parse(readFileSync(path.join(root, 'test/fixtures/next-vectors.json'), 'utf8'));
const page = readFileSync(path.join(root, 'tokenlock/signin.php'), 'utf8');
let passed = 0;
const step = (name, f) => { f(); passed++; console.log('  ✔', name); };

step('signin.php never assigns location.href from ?next= directly', () => {
  assert.doesNotMatch(page, /location\.href\s*=/);
  assert.match(page, /var next = safeNext\(document\.body\.getAttribute\('data-next'\), fallback\);/);
  assert.match(page, /\$next = tokenlock_safe_next\(isset\(\$_GET\['next'\]\)/);
});
const start = page.indexOf('function safeNext(v, fallback) {');
const end = page.indexOf('\n    }\n', start) + 6;
const safeNext = new Function(page.slice(start, end) + '\nreturn safeNext;')();
step(`browser safeNext matches the shared vectors (${N.allowed.length + N.rejected.length})`, () => {
  for (const v of N.allowed) assert.equal(safeNext(v, '/'), v, JSON.stringify(v));
  for (const v of N.rejected) assert.equal(safeNext(v, '/'), '/', JSON.stringify(v));
});
step('PHP tokenlock_safe_next matches the browser copy on every vector', () => {
  const all = [...N.allowed, ...N.rejected];
  const php = `require ${JSON.stringify(path.join(root, 'tokenlock/tokenlock.php'))}; $in = json_decode(stream_get_contents(STDIN), true); echo json_encode(array_map(function ($v) { return tokenlock_safe_next($v); }, $in), JSON_UNESCAPED_UNICODE);`;
  const out = JSON.parse(execFileSync('php', ['-r', php], { input: JSON.stringify(all) }).toString());
  all.forEach((v, i) => assert.equal(out[i], safeNext(v, '/'), JSON.stringify(v)));
});
console.log(`\n${passed} passed, 0 failed`);
