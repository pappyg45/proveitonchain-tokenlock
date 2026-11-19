// Shared authorization matrix (test/fixtures/authz-matrix.json) for Node self-verify. The PHP drop-in runs the same
// fixture (php/test/authz-matrix.php) and the hosted API runs it in the site repo (tests/tokenlock-access.test.mjs),
// through the raw API, this SDK's hosted client and the PHP hosted client.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import * as SV from '../dist/self-verify.js';

const M = JSON.parse(readFileSync(new URL('./fixtures/authz-matrix.json', import.meta.url), 'utf8'));
const SECRET = 'm'.repeat(40);
const ADDR = 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq';
const NOW = Date.parse('2026-11-18T18:00:00.000Z');
export const norm = (v) => { const allow = v.valid === true && v.allowed !== false; return { allow, code: allow ? 'ok' : v.code }; };

function setup(c) {
  const k = c.policy === 'registered_keys' ? 'key_1' : null;
  let pass = SV.issuePass({ sub: ADDR, h: ['TOKENLOCK'], k, n: 'a'.repeat(32), s: 'https://app.example', i: NOW - 1000, e: c.pass === 'expired' ? NOW - 1 : NOW + 900e3 }, SECRET);
  if (c.pass === 'forged') pass = pass.slice(0, -4) + (pass.endsWith('AAAA') ? 'BBBB' : 'AAAA');
  let policy;
  if (c.policy === 'registered_keys') policy = SV.localPolicy({ keys: [{ id: 'key_1', address: ADDR, status: c.key === 'revoked' ? 'revoked' : 'active', permissions: { routes: M.key.routes, methods: M.key.methods } }] });
  if (c.policy === 'token') policy = SV.localPolicy({ mode: 'token' });
  return { pass, policy };
}

test('authz matrix: Node self-verify matches every expected allow/deny and code', async () => {
  const out = {};
  for (const c of M.cases) {
    const { pass, policy } = setup(c);
    const v = await SV.verifyLocalPass(pass, { passSecret: SECRET, policy, resource: c.resource, now: NOW });
    out[c.id] = norm(v);
    assert.deepEqual(out[c.id], c.expect, c.id);
  }
  if (process.env.AUTHZ_MATRIX_OUT) writeFileSync(process.env.AUTHZ_MATRIX_OUT, JSON.stringify({ integration: 'node-self-verify', results: out }, null, 1));
});

test('policy_required answers say whether the pass itself is good (identity_valid), and never allow', async () => {
  for (const c of M.cases.filter((x) => x.expect.code === 'policy_required')) {
    const { pass, policy } = setup(c);
    for (const resource of [c.resource, { path: '/x' }, { method: 'DELETE' }, { environment: 'production' }]) {
      const v = await SV.verifyLocalPass(pass, { passSecret: SECRET, policy, resource, now: NOW });
      assert.equal(v.valid, false); assert.equal(v.allowed, false); assert.equal(v.code, 'policy_required'); assert.equal(v.identity_valid, true);
      assert.equal(v.address, ADDR);
    }
  }
  const { pass } = setup({ policy: 'none', pass: 'forged' });
  assert.equal((await SV.verifyLocalPass(pass, { passSecret: SECRET, resource: { path: '/x' }, now: NOW })).code, 'bad_pass', 'a forged pass is never reported as policy_required');
});
