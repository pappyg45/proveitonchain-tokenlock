# @proveitonchain/tokenlock

**Zero-trust access for the token era.** An extra layer in front of your login, admin, or API. Only verified token holders get through.

Your content stays on your server. We do the Token check. Built for security teams, AI agents, and mining operations. Self-verify (public spec, no dependence on our API) is included in 0.3.0 for Enterprise or pilot sites: see [Self-verify (0.3.0)](#self-verify-030).

Visitors click **Sign in with your Token**, sign a one-time message in their wallet (nothing is paid or sent), and get a short-lived pass. Your middleware checks the pass with your secret key on every request to a locked path.

- Next.js middleware + route handlers, Express middleware, a React button, and a Cloudflare Worker template
- TypeScript, ESM + CommonJS, zero dependencies
- Which tokens unlock your site is set in your [dashboard](https://proveitonchain.com/tokenlock/dashboard), not in code

## 1. Get your keys

Sign in at **https://proveitonchain.com/tokenlock/dashboard**, add your site (its address, e.g. `https://yoursite.com`, plus `http://localhost:3000` while developing) and pick the tokens that unlock it. You get:

- `pk_…` publishable site key, safe in the browser
- `sk_…` secret key, server only, shown once

```bash
NEXT_PUBLIC_TOKENLOCK_SITE_KEY=pk_…
TOKENLOCK_SECRET_KEY=sk_…
```

## Upgrading to 0.5.0 (security release, behavior changes)

Current release: **0.5.0**. It is the security release prepared as 0.4.5 (never published as 0.4.5) plus fixes from
later reviews. It is a minor version because it **denies sign-ins and passes that 0.4.4 accepted** and adds options
(`site`, owned-name checks). If you use `anyName` (any name on Bitcoin): numeric assets (`A…`), subassets and a balance
of a name the wallet does not own are now refused (`bad_name` / `not_holder`); `site` options and challenges that are
not an `http(s)` origin answer `bad_site`, and a pass for another site `wrong_site`. On the hosted service, an
entitlement revocation on a token-mode site now denies sign-in and verify (`entitlement_revoked`). See the CHANGELOG.
Projects on `^0.4.x` do not pick up 0.5.0 automatically: change the dependency to `^0.5.0`.

**Upgrade from 0.4.4.** An external review found
that a registered key with missing permissions was treated as a wildcard:

| Registered key's `permissions` | 0.4.4 | 0.5.0 |
| --- | --- | --- |
| missing, `null`, `{}`, `{ routes: null, methods: null }`, or `routes` / `methods` missing or `null` | read as `routes: ['*']`, `methods: ['*']`: every route and method allowed | `policy_invalid` for that key (any request with a resource) |
| `routes` / `methods` not a list of strings | `policy_invalid` (hosted: `access_data_invalid`) | `policy_invalid` everywhere |
| `routes: []` or `methods: []` | nothing granted | unchanged |
| explicit `['*']` | wildcard | unchanged (the only wildcard) |

This applies to self-verify `evaluate()` / `verifyLocalPass()`, the PHP drop-in and the hosted access check. Give every
registered key explicit `routes`, `methods` and `environments`. Identity-only checks are unchanged.

**Authorization contract 1.1** ([AUTHORIZATION-CONTRACT.md](AUTHORIZATION-CONTRACT.md); upgrade checklist [UPGRADE-0.4.5.md](UPGRADE-0.4.5.md)) is the one rule for Node, PHP, the
Cloudflare Worker and the hosted API, with shared test vectors (`docs/authorization-vectors-v1.json`). Also in 0.5.0:

| Key / request | 0.4.5 RC1 and earlier | 0.5.0 |
|---|---|---|
| `environments` missing or `null` | any environment | `policy_invalid` for that key (any request with a resource) |
| `environments: ['production']`, request without an environment | allowed | `environment_not_allowed` (set `environment` in your guard / drop-in / worker config) |
| route `'/api/'` (trailing slash) | prefix (`/api/*`) | exact (`/api`); write `'/api/*'` for a prefix |
| `environments: []` | any environment | no environment (`environment_not_allowed`); write `['*']` for any |
| hosted: approving a revoked key | reactivated with its previous grants | `400` unless `routes`, `methods`, `environments` and `expires_at` are sent |
| hosted: a change not stored in every durable store | `200` | `503 not_durable` (in effect now; repeat until `200`) |
| `permissions` with an unknown field (e.g. `route`) | field ignored | `policy_invalid` for that key; hosted write `400 bad_permissions` |
| hosted: restoring an older backup after a revocation | could restore the revoked key | the key is revoked again or held |
| hosted `/api/v1/gate/verify` with path / method / environment and no secret key | answered | `secret_key_required` (the SDK always sends the key) |
| hosted admin API: key created / approved without routes, methods or environments | stored `'*'` | `400 permissions_required`; `'*'` only when sent |

The enterprise example's `checkPass(pass, { path, method })` now works without an `environment`. The starter
projects depend on `^0.5.0`.

## Upgrading to 0.4.4 (security correction)

0.4.4 was a security correction with no new features (superseded by 0.5.0). **0.4.3 is deprecated: upgrade.** An external
review and a widened audit (every exported function fuzzed) found validation that only ran on some paths:

| You call | 0.4.3 | 0.4.4 |
| --- | --- | --- |
| Self-verify `evaluate(tokenModePolicy, { …, resource })` | `allowed: true` (resource never looked at, even `{ pth }` or an array path) | resource validated first, then `policy_required` |
| `evaluate(policy, { address, held })` (no resource, no `identityOnly`) | identity check implied | `bad_resource`: pass `resource` or `identityOnly: true` |
| `evaluate(…, { held: null })` or a `held` that is not a list of strings | holdings check skipped | `bad_input` |
| A `localPolicy` (or any policy) whose `expires_at` has passed | still authorized | `policy_expired`, wherever the policy is used |
| A policy whose `issued_at` is in the future (beyond 5 min skew) | accepted unless it came in a signed bundle | `policy_invalid` |
| `verifyLocalPass(pass, { passSecret: '' })` (or shorter than 32 characters, or missing) | verified passes forged with that key | `bad_secret` |
| `verifyLocalPass('garbage', { …, resource: { path: '/a/../b', … } })` | `valid: true, allowed: false, code: 'bad_path'` (pass never checked) | `valid: false` |
| Cloudflare worker `strictCheck(answer, resource)` with a malformed resource; `verify()` with a resource whose fields are inherited | checked anyway | `bad_resource` |

If you check only `valid`, the `bad_path` row matters: upgrade. The starter projects in `examples/` depend on `^0.4.4`,
set `tokenOnly: true` (holder sites) and call `getPass(undefined, { identityOnly: true })`. Hosted API: the lower-level
functions behind `/api/v1/gate/verify` now validate what they are given, and the "site still accepts this token" check
also runs when a pass is verified without a secret key. PHP drop-in 0.4.4 has the same fixes. Advisory:
https://proveitonchain.com/security/advisories/2026-11-18#correction-044

## Upgrading to 0.4.3 (security correction, breaking: explicit identity-only)

0.4.3 was a security correction with no new features (superseded by 0.4.4). In 0.4.2 a
mistyped, unknown, empty, `null` or non-string resource field (e.g. `{ pth: '/admin' }`, `{ path: '' }`) was dropped
and the call became an identity-only check. Since 0.4.3 every authorization call uses one strict schema:

| You call | 0.4.2 | 0.4.3 |
| --- | --- | --- |
| `verifyPass(pass, { secretKey })` / `getPass(req)` with no resource | identity-only check | throws `bad_resource`: say `{ identityOnly: true }` |
| `{ identityOnly: true }` (alone) | n/a | identity-only check (supported) |
| Unknown field or option (`pth`, `route`, `identity_only`…) | dropped → identity-only | throws `bad_resource` |
| `path` without `method`, or the reverse | partial check | throws `bad_resource` |
| Empty, whitespace-only, padded, `null` or non-string `path`/`method`/`environment` | dropped / sliced | throws `bad_resource` |
| Relative or non-canonical path (`admin`, `/a/../b`, `%2e%2e`, `%252e`) | `bad_path` or identity | `{ valid: false, code: 'bad_path' }` |
| `authorize(req, …)` without `{ path, method }` | identity-only | throws `bad_resource` |

Server-side: the hosted API applies the same schema to `/api/v1/gate/verify` (malformed → `bad_resource` /
`bad_path`). Advisory: https://proveitonchain.com/security/advisories/2026-11-18#correction-043

## Upgrading to 0.4.2 (security hardening, breaking: removed options)

0.4.2 was a security-hardening release with no new features (deprecated; superseded by 0.4.3). It removes every way to weaken the
fail-closed behavior by configuration:

| Removed | What happens now |
| --- | --- |
| `failOpen` (any value) | Configuration error (`TokenlockError`, `code: 'bad_config'`) when the middleware or client is created. A TOKENLOCK API that can't answer always denies protected requests (`503`) |
| `checkResource` (any value) | Configuration error. The path, method and environment are always sent and checked. Token-only sites use `tokenOnly: true` |
| `strict: false` (loose mode) | Configuration error, on the client, the middleware and per call. `strict: true` is still accepted; strict is always on |
| Unknown middleware options (typos such as `tokenonly`), wrong types (e.g. `tokenOnly: 'false'`), a missing or malformed secret key, an empty `protect` | Configuration error at startup instead of being ignored |
| Cloudflare worker: `TOKENLOCK_FAIL_OPEN`, `TOKENLOCK_CHECK_RESOURCE`, `TOKENLOCK_STRICT` set to anything; an invalid `TOKENLOCK_TOKEN_ONLY` / `TOKENLOCK_TIMEOUT_MS` / `TOKENLOCK_API`; a missing or non-`sk_` secret | `500 bad_config` on protected paths, nothing served |

Also new in 0.4.2 (all deny, never allow): answers larger than 64 KiB, answers that are not a JSON object, answers with
wrong types or missing fields, and contradictory answers (`valid: true` together with an error code, `error` or
`identity_valid: false`; `allowed` disagreeing with `access.allowed`; an access `reason` other than `ok`; two resource
echoes naming different resources; an identity answer naming a resource). Self-verify rejects malformed policies
(`policy_invalid`) and holdings answers whose `held` is not a boolean. The Cloudflare worker has a fail-closed fetch
timeout (`TOKENLOCK_TIMEOUT_MS`, default 8000): a slow or hung API is answered `503`. On the hosted side, a storage
error reading a site's settings is an outage (`503`), never a token-only answer. (0.5.0: a site that has never had
access settings, so its site record carries no access-state flag, is answered on its token rules alone while the access
store is down; see the CHANGELOG, RC8.)

What to do: remove `failOpen`, `checkResource` and `strict: false` from your configuration (and the Cloudflare
variables above). Nothing else changes for a correct configuration.

## Upgrading to 0.4.0 (breaking: explicit route authorization)

0.4.0 fixes [security advisory 2026-11-18](https://proveitonchain.com/security/advisories/2026-11-18): **no route,
method or environment is authorized unless a policy explicitly permits it.** Identity and token checks are unchanged.

| You call | 0.3.x | 0.4.0 |
| --- | --- | --- |
| `verifyPass(pass, { identityOnly: true })` / `getPass(req, { identityOnly: true })` (identity only; explicit since 0.4.3) | allowed | allowed (unchanged) |
| A resource (`path`, `method` or `environment`) on a **token-only** site (registered keys off) | `allowed: true`, nothing checked | `{ valid: false, allowed: false, code: 'policy_required', identity_valid: true }` |
| A resource on a site with **registered keys** | checked against the key | checked against the key (unchanged) |
| Self-verify `verifyLocalPass` with a resource and no `policy` (0.3.2 and earlier) or a token-mode policy | `allowed: true` | `policy_required` |
| Next/Express middleware on a token-only site | every holder let in | **`403 policy_required`** unless you set `tokenOnly: true` |

What to do:
- **Token-only site using the middleware** (any holder may open every protected path): add `tokenOnly: true`. The
  middleware then checks identity and token only. If the site later turns on registered keys, every request is
  still checked against the key's routes (`tokenOnly` can't bypass a route policy).
- **Your own calls with a resource** on a token-only site: drop the resource and pass `identityOnly: true` (an explicit identity-only check; since 0.4.3 leaving both out throws `bad_resource`), or turn on registered
  keys and grant the routes. Treat `policy_required` as a configuration error (the middleware answers 403).
- **Self-verify**: pass a registered-keys `policy` whenever you pass a `resource`; use identity-only checks otherwise.
- **PHP drop-in**: upgrade to PHP 0.4.0 or later (current 0.5.0) and set `'token_only' => true` (or `TOKENLOCK_TOKEN_ONLY=1`) on token-only sites.
- **Cloudflare worker example**: set `TOKENLOCK_TOKEN_ONLY = "1"` on token-only sites.

The hosted API answers `policy_required` to every client version, SDK and PHP 0.2.x/0.3.x included (since 18 Nov 2026,
9:03 PM PT), so token-only sites still on 0.2.x/0.3.x middleware deny protected paths until they upgrade.

### Fail-closed guarantee

No protected path, method or environment is authorized unless a policy explicitly permits it. Since 0.4.2 there is
no setting that turns this off. Each of these denies:

| Situation | Answer |
| --- | --- |
| A resource with no applicable route policy (token-only site, no `tokenOnly`) | `403 policy_required` (`identity_valid: true` if the pass is good) |
| SDK/PHP/Cloudflare clients 0.2.x/0.3.x sending a resource to the hosted API on a token-only site | `policy_required` (hosted API, every client version) |
| `tokenOnly: true` on a site that has registered keys | the route, method and environment are still checked against the key |
| TOKENLOCK API unreachable, timing out (`timeoutMs`, default 8 s) or answering 5xx | `503 tokenlock_unavailable`, `retry-after: 15` |
| Self-verify: policy bundle can't be fetched, is expired or has a bad signature | `policy_unavailable` / `policy_expired` |
| Self-verify: holdings source fails or sources disagree | `lookup_failed` / `lookup_disagreement` |
| Self-verify: a resource with no policy, or a token-mode policy | `policy_required` |
| Self-verify: a malformed policy (wrong types, unknown mode or key status, unparseable dates, non-integer `seq`) | `policy_invalid` |
| An invalid configuration (removed or unknown options, wrong types, missing or malformed secret key) | startup error `bad_config` (Cloudflare worker: `500 bad_config`) |
| A malformed, oversized (> 64 KiB), non-JSON or contradictory API answer | denied (`bad_answer` → `503`, or the specific deny code) |

Remaining limits (not configuration switches): on hosted registered-keys sites, a pass younger than
2 × `recheck_holdings_s` keeps working during a holdings-source outage unless `require_fresh_holdings` is on (the route
policy is still enforced). A site switched between token-only and registered keys can take up to 30 s per server
instance to be seen by the hosted API. Identity answers on token-only sites are cached up to 60 s unless `cache: false`.
Self-verify code in versions you installed earlier keeps its old behavior until you upgrade.

## 2. Install

```bash
npm install @proveitonchain/tokenlock
```

## 3. Lock your pages (Next.js)

**`middleware.ts`**

```ts
import { tokenlock } from '@proveitonchain/tokenlock/next';

export default tokenlock({
  protect: ['/members/:path*'], // TOKENLOCK decides which paths are protected (canonical, case-insensitive)
  signInPage: '/signin',
  tokenOnly: true, // any holder may open every protected path (no registered keys). Leave out to require route rules.
});

// Keep this broad. Next's own matcher is case-sensitive and would skip /MEMBERS
// if it were ['/members/:path*']. TOKENLOCK then applies `protect`.
export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
```

**`app/api/tokenlock/[action]/route.ts`**: exchanges the pass for an HttpOnly cookie, and signs out

```ts
import { tokenlockRoutes } from '@proveitonchain/tokenlock/next';
export const { GET, POST } = tokenlockRoutes();
```

## 4. Sign-in page

**`app/signin/page.tsx`**

```tsx
import { SignInWithBitcoin } from '@proveitonchain/tokenlock/react';

export default function SignIn() {
  return <SignInWithBitcoin siteKey={process.env.NEXT_PUBLIC_TOKENLOCK_SITE_KEY!} redirectTo="/members" />;
}
```

The button opens a wallet picker (Unisat, Xverse, Leather, Horizon and other browser wallets when installed) and always lets people paste a signature from any wallet with "Sign message" (Sparrow, Electrum, Bitcoin Core).

## 5. Who is signed in: `getPass`

```tsx
import { getPass } from '@proveitonchain/tokenlock/next';

export default async function Members() {
  const pass = await getPass(undefined, { identityOnly: true }); // null, or { address, assets_held, name, expires_at, … }
  return <p>Signed in as {pass?.address}</p>;
}
```

Sign out: link to `/api/tokenlock/signout`.

## Express

```js
import express from 'express';
import { tokenlock } from '@proveitonchain/tokenlock/express';

const app = express();
app.use(tokenlock({ protect: ['/members/:path*'], signInPage: '/signin', tokenOnly: true }));
app.get('/members', (req, res) => res.send(`Hi ${req.tokenlock.address}`));
```

The Express middleware also serves `POST /api/tokenlock/session` and `/api/tokenlock/signout`. Your sign-in page can use the script tag:

```html
<script src="https://proveitonchain.com/gate.js" data-site-key="pk_…"></script>
<script>
  ProveItGate.signIn().then(({ pass }) =>
    fetch('/api/tokenlock/session', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ pass }) })
  ).then((r) => r.ok && (location.href = '/members'));
</script>
```

## Any server: core API

```ts
import { verifyPass, getPass, createChallenge, TokenlockClient } from '@proveitonchain/tokenlock';

const v = await verifyPass(pass, { secretKey: process.env.TOKENLOCK_SECRET_KEY, identityOnly: true }); // identity only
if (v.valid) { /* v.address, v.assets_held, v.site_id, v.expires_at */ }

const visitor = await getPass(req, { identityOnly: true }); // reads the tokenlock_pass cookie and checks it
const ch = await createChallenge({ siteKey: 'pk_…', origin: 'https://yoursite.com' }); // build your own wallet flow

const client = new TokenlockClient({ secretKey, siteKey }); // low-level REST client
await client.request('POST', '/api/v1/gate/verify', { pass, identity_only: true });
```

| Function | What it does |
| --- | --- |
| `verifyPass(pass, { secretKey, path, method, environment? })` or `verifyPass(pass, { secretKey, identityOnly: true })` | `{ valid, address, assets_held, site_id, expires_at }` or `{ valid: false, code }`. A bad, expired or out-of-scope pass is an answer, not an exception. Throws `TokenlockError` when there is no answer: missing configuration (`no_secret_key`; `no_fetch` on runtimes without `fetch`), a non-2xx HTTP response from the API (`status` = HTTP status, e.g. 429 or 5xx, `code` from the API), or a network error or timeout (`network`, status 0). See [Errors](#errors-tokenlockerror). |
| `getPass(req, opts?)` | The verified pass from the request cookie, or `null`. Pass `{ path, method, environment? }` or `{ identityOnly: true }` (required since 0.4.3; anything else throws `bad_resource`). Works with Fetch `Request`, `NextRequest`, Express/Node `req`. |
| `authorize(req, { path, method, environment })` | Strict, uncached check for one action (agent APIs, sensitive operations). `{ valid: true, allowed: true, … }` or `{ valid: false, allowed: false, code, reason }`. |
| `canonicalPath(path)` | The path used for matching (see Path rules), or `null` to reject. |
| `resourcePath(path)` | The canonical path lowercased: what is sent to the API, cached and compared with the answer. |
| `safeNext(v, fallback?)` | A same-site path to go back to after sign-in, else `fallback`. Ship it to the browser as `${safeNext.toString()}`. |
| `clearCache(pass?)` | Drops every cached answer for that pass (all routes), or everything. |
| `createChallenge({ siteKey, origin })` | Starts a sign-in: `{ challenge_id, message, assets }`. |
| `TokenlockClient` | `verifyPass`, `createChallenge`, `signIn`, and `request()` for any `/api/v1` call (sends `Authorization: Bearer sk_…`). |
| `passCookie`, `clearPassCookie`, `readPass`, `createMatcher`, `safeNext` | Helpers used by the adapters. |

### Errors (`TokenlockError`)

`verifyPass`, `getPass`, `authorize`, `createChallenge` and `TokenlockClient.request` throw `TokenlockError` (`{ message, status, code }`) when they can't get an answer. A denied pass is never thrown; it comes back as `{ valid: false, code }`.

| When | `status` | `code` | `isUnavailable(e)` |
| --- | --- | --- | --- |
| No secret key (option or `TOKENLOCK_SECRET_KEY`); no site key for `createChallenge` | 0 | `no_secret_key` / `no_site_key` | false (fix your config) |
| No `fetch` in this runtime (Node < 18 without `{ fetch }`), thrown when the client is created | 0 | `no_fetch` | true |
| `authorize()` without `{ path, method }`; any call with a missing or malformed resource (`verifyPass`/`getPass` with neither a resource nor `identityOnly: true`, unknown fields such as `pth`) | 400 | `bad_resource` | false (fix the call) |
| The API answered with a non-2xx status (400, 401, 402, 429 rate limited, 5xx …) | the HTTP status | the API's `code`, if any | true only for 5xx |
| Network error or timeout (`timeoutMs`, default 8000) | 0 | `network` | true |

Custom server (Express-style handler; the same pattern works in any framework): fail closed on every error, and tell "can't check right now" apart from a config bug.

```ts
import { verifyPass, TokenlockError, isUnavailable, denialStatus } from '@proveitonchain/tokenlock';

async function requireAccess(req, res, next) {
  const pass = readCookie(req, 'tokenlock_pass');
  try {
    const v = await verifyPass(pass, { secretKey: process.env.TOKENLOCK_SECRET_KEY, path: req.path, method: req.method });
    if (v.valid && v.allowed !== false) { req.tokenlock = v; return next(); }
    return res.status(denialStatus(v.code)).json({ code: v.code, reason: v.reason, correlation_id: v.correlation_id });
  } catch (e) {
    if (!(e instanceof TokenlockError)) throw e;
    if (isUnavailable(e)) {                          // network, timeout, 5xx: deny, ask the client to retry
      res.set('Retry-After', '5');
      return res.status(503).json({ code: 'tokenlock_unavailable' });
    }
    console.error('[tokenlock]', e.status, e.code, e.message); // no_secret_key, 401/402/429 …: config or plan problem
    return res.status(e.status === 429 ? 429 : 500).json({ code: 'tokenlock_error' });
  }
}
```

### Options (Next and Express)

| Option | Default | |
| --- | --- | --- |
| `protect` | (required) | `'/members/:path*'`, `'/admin'`, a `RegExp`, or `(path) => boolean` |
| `signInPage` | (required) | Visitors without a valid pass go here with `?next=<path>` |
| `secretKey` | `process.env.TOKENLOCK_SECRET_KEY` | |
| `cookieName` | `tokenlock_pass` | HttpOnly, Secure, SameSite=Lax, ends when the pass ends |
| `cookiePath` | `/` | |
| `maxAgeSeconds` | `86400` | Upper bound on a sign-in |
| `publicPaths` | none | Paths inside `protect` that stay open |
| `afterSignOut` | `/` | |
| `sessionPath`, `signOutPath` (Express) | `/api/tokenlock/session`, `/api/tokenlock/signout` | |
| `environment` | none | Sent with each check, e.g. `'production'` |
| `strict` | on | Always on since 0.4.2. `strict: true` is accepted; `strict: false` throws `bad_config` |
| `timeoutMs` | `8000` | 1–120000. A slow API denies protected requests with `503` |
| `apiPaths` | none | Paths that always get JSON 401/403 (API mode) |
| `caseSensitive` | `false` | `/ADMIN` is the same as `/admin` unless set |
| `cache` | `true` | `false` asks the API on every request |
| `tokenOnly` | `false` | 0.4.0. Token-only site: any holder may open every protected path (identity + token check). Without it, a site with no route policy answers `403 policy_required`. On a site with registered keys, routes are still enforced. Must be a boolean |

Removed in 0.4.2 (passing them throws `bad_config`): `failOpen`, `checkResource`, `strict: false`. Unknown middleware options are
refused too (`bad_config`). Since 0.4.3 unknown options and authorization fields are refused on every call as well
(`verifyPass`, `getPass`, `authorize`, `client.verifyPass`, `verifyLocalPass`: `bad_resource`), so a typo can't silently weaken protection.

### `<SignInWithBitcoin />` props

`siteKey` (required), `redirectTo` (default: `?next=` or `/`), `sessionUrl` (`/api/tokenlock/session`), `label` (`Sign in with your Token`), `title`, `passTtlSeconds` (3600), `className`, `style`, `onSignedIn`, `onError`. Also exported: `SignOutLink`, `loadGate()`.

## Cloudflare

`examples/cloudflare-worker/worker.js` puts the same check in front of any site, with no dependencies.

## How it stays safe

**Server-side check recommended.** This package checks the pass on your server, so locked content is never sent until we do the Token check. A browser-only setup with `gate.js` that just hides content in the page is a soft gate: the content still reaches the visitor and can be bypassed with an extension or dev tools. Fine for teasers and soft paywalls, not for anything that must stay private.

- The secret key never leaves your server. Passes are checked with it, so a pass made for another site is refused.
- The pass cookie is HttpOnly, Secure and SameSite=Lax, and the session endpoint refuses requests from other sites.
- Good checks are cached in memory (see "Revocation window") and never past the pass's expiry.
- Your dashboard shows every sign-in attempt, and Business plans can get webhook alerts on failure spikes.
- A pass proves the visitor controlled a wallet holding your token when they signed in. It does not prove who they are.

## Plans

Unlimited sign-ins on every plan; plans are priced by monthly active wallets (each wallet that signs in to your sites counts once a month). Free: 1 site, 100 active wallets a month. Starter ($19/mo), Pro ($49/mo or $490/yr) and Business ($149/mo) add sites, active wallets, branding and alerts. Paid in BTC. See https://proveitonchain.com/tokenlock. Going over never breaks your site.

A successful sign-in (`TokenlockClient.signIn`, `ProveItGate.signIn`) also returns `usage`: `{ month, active_wallets, limit, pct, over, new_wallet, site_signins, signins: 'unlimited', note? }` (type `SignInUsage`). `over` is informational only; sign-ins keep working.

MIT © Prove It Onchain

## Enterprise access controls (0.3.0)

Sites with **registered keys** turned on (Business, Enterprise, or a pilot) check every request against the key's routes, methods, environment and expiry. In **strict** mode (the 0.3.0 default) the SDK never caches registered-key answers, so an admin revoke or permission change is visible on the next request. A token transfer is noticed on the next hosted holdings re-check (at most `recheck_holdings_s`, 300 seconds by default), not immediately, even with `cache: false`. See [Revocation window](#revocation-window). Organizations are optional unless the site turns on `require_org`. The same site secret verifies passes and manages access, organizations and keys; separate credentials are planned, not shipped. Token-only sites (registered keys off) have no route rules: since 0.4.0 a check that names a path, method or environment answers `policy_required`; use identity-only checks or the middleware's `tokenOnly: true`. Full docs: https://proveitonchain.com/docs/enterprise

```js
const info = await verifyPass(pass, { secretKey, path: '/api/partner/prices', method: 'GET', environment: 'production' });
if (!info.valid) return res.status(403).json({ code: info.code, correlation_id: info.correlation_id });
info.access; // { mode: 'registered_keys', allowed, reason, key: { id, label, owner_type, owner_name }, permissions, key_expires_at }
```

- The Express and Next.js middleware send the request path and method with each pass check (set `environment: 'production'` to check environments). An out-of-scope route answers `403` JSON instead of redirecting to sign-in.
- `correlation_id` matches the entry in your decision log. See [Decision records: retention, modification and purge](#decision-records-retention-modification-and-purge) for where those records live, who can change or purge them, and why retention is not tamper evidence.

## Security model (0.3.0)

### Sessions: a bearer pass, not a per-request signature

The wallet signature happens once, at sign-in. It gets the visitor (or agent) a **pass**: a signed, expiring bearer token kept in an HttpOnly cookie (or sent by an agent). Each request presents that pass; it is **not** a fresh signature per request. Anyone who steals the pass can use it until it expires or the key is revoked, so keep passes short for agents (`pass_ttl_s`), serve over HTTPS, and never log them. Per-request signing for agent APIs (each request signed by the agent's key over method, path, body hash and a timestamp) is on the roadmap.

### Path rules v1.1 (the same in every adapter and on the API)

Paths are matched in canonical form, case-insensitively: query and fragment dropped; percent-decoded **once**; `//` collapsed; trailing `/` dropped. Requests are **rejected with 400 `bad_path`** if the path has a backslash, a control byte, an encoded `/` `\` NUL `%` `.` or `;` (`%2f`, `%5c`, `%00`, `%25`, `%2e`, `%3b`), invalid encoding, any `;` (path parameters) or any `.` or `..` segment. Ambiguous forms are refused rather than resolved, because frameworks and proxies resolve them differently: `/admin/..` is `/` to a URL parser but is served by an `/admin/*` route in Express or a PHP router. So `/ADMIN`, `/admin/`, `//admin` and `/%61dmin` are all `/admin`, while `/admin;x`, `/./admin`, `/admin/..` and `/admin%2f..` are refused. The resource sent to the API, the cache key and the check of the API's answer all use the canonical path lowercased (`resourcePath()`). Test vectors: `test/fixtures/path-vectors.json`.

**Authorization paths are case-insensitive:** `/Admin`, `/ADMIN` and `/admin` are one authorization identity, even if your app routes them to different pages. A rule for `/admin/*` also covers `/ADMIN/x`, and a public carve-out for `/join` also opens `/JOIN`. Don't rely on case to separate protected and public routes.

**If a proxy, CDN or load balancer sits in front of your app**, make sure it passes the path through unchanged, or normalizes it the same way for both TOKENLOCK and the app: TOKENLOCK must see the same path your app routes on. Don't let a proxy decode `%2f`, strip `;params` or resolve `..` *after* the TOKENLOCK check. Put TOKENLOCK in the app (or in the same worker that forwards the request), not in a separate hop that routes on a different form. Keep your app's own routes as specific as the protected patterns, and protect whole prefixes (`/admin/:path*`) rather than single pages. On Cloudflare Workers and in Next.js the platform hands the code an already-parsed URL (dot segments resolved), and the worker forwards that same URL to your origin, so both see the same path.

What our tests do and don't show: the adapter tests (`npm test`, and `test/integration/` with real Express 4 and 5 apps, a Next.js app with middleware, the PHP built-in server with a router, and the Cloudflare worker in Miniflare) check that every alternate URL form is refused or decided on the route the app actually serves. They run against a local copy of the API. They don't establish the security of the hosted verification service or isolation between tenants; an independent security review is on the roadmap.

Next.js: keep `config.matcher` broad (the quickstart above, or leave it out). Next's own matcher is case-sensitive, so `matcher: ['/members/:path*']` or `['/admin/:path*']` would never run the middleware for `/MEMBERS` or `/ADMIN`. TOKENLOCK's `protect` option is what decides which application paths are locked. Write `protect` / `publicPaths` patterns the way Next routes them: without the `basePath` and without the i18n locale prefix (`'/members/:path*'` also locks `/fr/members` and `/docs/members`). Since 0.5.0 the middleware matches both the app path and the full path, so a pattern that includes the prefix still locks; `publicPaths` are judged on the app path.

### Strict mode (default)

An answer counts only if it is complete, unambiguous and says `allowed: true` for **exactly** the path, method and environment you asked about (the API echoes them back). Anything else (missing fields, wrong types, an unknown access mode, a different resource, an expired pass, a contradiction such as `valid: true` with an error code, an answer over 64 KiB or not a JSON object) is a denial. Since 0.4.2 strict mode is the only mode, for identity checks too; `strict: false`, `failOpen` and `checkResource` were removed and throw `bad_config`. When the API can't answer, protected requests are denied with `503`.

### Revocation window

Three kinds of change reach your server at different speeds. Only admin changes to registered keys can be **0 s**.

**1. Key revocation and expiry** (admin revokes or expires a key, suspends its organization, or revokes an asset):

| Setup | How long the old access can still get in |
| --- | --- |
| **Hosted verification**, strict (default), registered keys | **0 s**: never cached; every protected request asks the API, which reads the key live |
| **Hosted verification**, `cache: false`, registered keys | **0 s** for these admin changes (holdings changes still follow table 3) |
| **Hosted verification**, token-only sites (no registered keys) | No keys to revoke (access controls are off). An existing pass stays good until it expires; good answers are cached in the SDK up to 60 s unless `cache: false` |
| 0.1.x SDKs (hosted) | up to 60 s |
| **Self-verify**, signed policy bundle | On the next successful policy refresh (**60 s** by default). If refreshes fail, the cached bundle is used until it expires (**600 s** by default, the bundle's `ttl`), then access fails closed (`policy_expired`) |
| **Self-verify**, `localPolicy` | On your next `get()` of that policy (you control how fresh it is) |

**2. Permission changes** (routes, methods, environments, key expiry date): same timing as table 1, for each setup.

**3. Holdings changes** (the token is transferred away from the wallet):

| Setup | When the transfer is noticed |
| --- | --- |
| **Hosted verification**, registered keys (strict or `cache: false`) | On the next hosted holdings re-check: up to `recheck_holdings_s` (**300 s** by default; 60–86400, or 0 = only at sign-in) after the last successful check. The key is then paused (`pending_approval`). `cache: false` only turns off the SDK's own cache; it does **not** shorten this hosted re-check interval |
| **Hosted verification**, token-only sites | Holdings are checked at sign-in only. An existing pass stays good until it expires (15 min by default, at most 24 h); the next sign-in is refused |
| **Self-verify** | Holdings are read at sign-in (`verifySignIn`). `verifyLocalPass` does not re-read them, so a pass stays good until it expires (`pass_ttl_s`, 900 s by default, capped by the key and agent TTLs). The policy bundle carries key status, not live holdings; the hosted re-check does not apply. Use short pass lifetimes, or re-check holdings yourself, if a transfer must cut access sooner |

During a holdings-source outage, hosted verification keeps passes younger than 2 × `recheck_holdings_s` working unless `require_fresh_holdings` is on. See https://proveitonchain.com/docs/enterprise#timing.

`clearCache(pass)` drops every cached answer for that pass, for all routes.

### API mode

Requests with `Accept: application/json` (and not `text/html`), or under `apiPaths`, get JSON instead of a redirect, for every denial: `401` when there is no pass or it is invalid or expired (sign in again), `403` when signed in but not allowed (route, method, environment, revoked, expired or pending key, organization, entitlement), `400` for a rejected path, `503` when the API can't answer. Body: `{ error, code, reason, correlation_id }`.

## Self-verify (0.3.0)

Run the whole sign-in on your server: you issue the challenge, keep the nonce, verify the wallet signature locally
(BIP-322 and legacy; XCP Wallet, Horizon, Unisat, Xverse, Leather) and read holdings from a source you choose.
Spec: [docs/self-verify-spec.md](docs/self-verify-spec.md) · https://proveitonchain.com/docs/self-verify

```js
import { createChallenge, verifySignIn, verifyLocalPass, fileNonceStore, tokenscanProvider, requireAgreement,
  proveitonchainProvider, signedPolicy } from '@proveitonchain/tokenlock/self-verify';

const store = fileNonceStore('/var/lib/tokenlock-nonces');            // or redisNonceStore(client) for many servers
const holdings = requireAgreement([tokenscanProvider(), proveitonchainProvider()]); // fail closed if they disagree
const cfg = { store, holdings, passSecret: process.env.MY_PASS_SECRET };  // 32+ chars, never sent to us

const c = await createChallenge({ site: 'https://shop.example', assets: ['CLUBTOKEN'], store });
// … the wallet signs c.message …
const r = await verifySignIn({ challenge_id: c.challenge_id, address, signature }, cfg);
if (r.valid) setCookie('tl_pass', r.pass);                              // HttpOnly, Secure
const v = await verifyLocalPass(cookie, { passSecret: process.env.MY_PASS_SECRET, identityOnly: true, site: 'https://shop.example' });
```

`site` (0.5.0, optional) refuses a pass issued for another site (`wrong_site`). Use one `passSecret` per site.
With `anyName: true`, the visitor must **own** a registered name (4–12 letters A–Z, not starting with A), as on hosted
sign-in: numeric assets and a balance of someone else's name are refused.

### Enterprise self-verify (registered keys, path, method, environment)

Pin the policy-signing key, pull a signed policy bundle, and enforce **both** `valid` and `allowed` for a resource. A runnable copy of this flow (including expired-bundle and holdings-outage cases) is in [`examples/self-verify-enterprise.mjs`](examples/self-verify-enterprise.mjs) and is exercised by `test/self-verify-enterprise.test.mjs`.

```js
import { createChallenge, verifySignIn, verifyLocalPass, fileNonceStore,
  tokenscanProvider, signedPolicy } from '@proveitonchain/tokenlock/self-verify';

// Pin the key from https://proveitonchain.com/.well-known/tokenlock-policy-keys.json (kid → hex).
const publicKeys = { [process.env.TOKENLOCK_POLICY_KID]: process.env.TOKENLOCK_POLICY_PUBLIC_KEY };
const policy = signedPolicy({
  siteId: process.env.TOKENLOCK_SITE_ID,
  secretKey: process.env.TOKENLOCK_SECRET_KEY, // fetches GET /api/v1/tokenlock/access/policy
  publicKeys,                                  // unknown kid or a bad signature → fail closed
  refreshSeconds: 60,                          // default: pull a fresh bundle every 60 s
  // retryMinSeconds: 5, retryMaxSeconds: 60,  // defaults: after a failed load, wait 5 s, 10 s, 20 s … (max 60 s)
                                               // before the next attempt; calls in between don't hit the network
  // ttlSeconds: 600,                          // optional; the API's default bundle lifetime is 600 s
});
const store = fileNonceStore('/var/lib/tokenlock-nonces');
const holdings = tokenscanProvider(); // or proveitonchainProvider(), or requireAgreement([...])
const cfg = { store, holdings, passSecret: process.env.MY_PASS_SECRET, policy };

const c = await createChallenge({ site: 'https://app.example', assets: ['TOKENLOCK'], store });
const r = await verifySignIn({ challenge_id: c.challenge_id, address, signature }, cfg);
// r.valid is false with code lookup_failed if the holdings provider is down,
// or policy_expired / policy_unavailable if the bundle cannot be used.
if (!(r.valid && r.pass)) deny(r.code, r.reason);

const v = await verifyLocalPass(r.pass, {
  passSecret: process.env.MY_PASS_SECRET,
  policy,
  resource: { path: '/api/reports/q3', method: 'GET', environment: 'production' },
});
// Enforce both: valid = authentic, unexpired pass still granted; allowed = this resource is in scope.
if (!(v.valid && v.allowed)) deny(v.code, v.reason); // route_not_allowed, policy_expired, policy_required, …
```

Registered keys offline: `signedPolicy({ siteId, secretKey, publicKeys: { kid: key } })` pulls a BIP-340-signed bundle
(Enterprise or pilot), checks it against the key you pinned from `/.well-known/tokenlock-policy-keys.json`, refreshes
every 60 s, uses the cached bundle while refreshes fail until it expires (default 600 s), then fails closed. After a
failed load it backs off (5 s, doubling, capped at `refreshSeconds`) and concurrent calls share one in-flight load, so an
outage doesn't add a slow request to every call. `policy.status()` reports `failures`, `last_error` and `next_retry_at`
for health checks. Or use `localPolicy(...)` if you keep the policy yourself.

**Policy validity window (0.4.4).** Every policy is checked against the current time wherever it is used (signed bundle,
`localPolicy`, a custom source, or a policy passed to `evaluate()`): past `expires_at` it answers `policy_expired`, and an
`issued_at` more than 5 minutes in the future is `policy_invalid`. A `localPolicy` that leaves out `expires_at` does not
expire. `evaluate(policy, { address, held, resource | identityOnly: true, now? })` checks the request first, then `held`
(a list of asset names), then the policy, then the mode. `verifyLocalPass` needs a `passSecret` of at least 32 characters.

**A `resource` needs a policy.** `verifyLocalPass(pass, { passSecret, resource })` without `policy` answers
`{ valid: false, allowed: false, code: 'policy_required' }`: route, method and environment rules live in the policy, so
they can't be checked without one (0.3.2 answered `allowed: true`). For an identity-only check pass `identityOnly: true` instead of `resource` (explicit since 0.4.3; no resource and no `identityOnly` answers `bad_resource`).
A token-mode policy (registered keys off) has no per-route rules either, so since 0.4.0 a `resource` with it also
answers `policy_required` (0.3.3 and earlier: `allowed: true`). The answer includes `identity_valid: true` when the pass
itself is good.

| Mode | You still trust |
|---|---|
| our holdings provider | our reading of the chain (and the bundle signer, if used) |
| tokenscan / your node via `httpJsonProvider` | that source (two sources with `requireAgreement`) |
| `localPolicy` + your node | No TOKENLOCK-hosted verification or external holdings provider required. You still depend on your own software and node infrastructure. |

All modes fail closed: lookup errors, an expired or unverifiable policy, replays and bad signatures all deny. The
`./self-verify` entry bundles the noble cryptography libraries, so there are no extra dependencies to install. PHP:
`tokenlock/self-verify.php` in the PHP drop-in (it needs the GMP extension), with the same formats. A pass issued by one
side verifies on the other.

## Decision log coverage (hosted API)

This is what the hosted TOKENLOCK service records when a check reaches our API (production as of 0.3.0, including authorized verifies). The SDK itself does not write this log.

| Event | What is recorded |
| --- | --- |
| Successful hosted resource check | Yes. Written as `kind: "pass_check"`, `outcome: "authorized"`, `reason: "ok"`, with the resource (`path`, `method`, `environment` when sent), key, owner, wallet, `correlation_id` (the sign-in nonce when the pass has one), and timestamps. These rows count toward the plan's monthly decision cap. |
| Denied hosted resource check | Yes. Same `pass_check` shape: `outcome: "denied"`, the reason code (`route_not_allowed`, `key_revoked`, …), `reason_text`, resource, key, and `correlation_id` when present. Sign-in denials are a separate `kind: "signin"` row with the same correlation id. |
| Locally cached SDK or PHP decision | No hosted event. A cache hit never reaches our API, so it cannot appear in the hosted log. In strict mode, registered-key checks reach the hosted API on every protected request. The service attempts to log each decision, and a logging failure does not block access. If you need a log of cache hits, record them on your server. |
| Self-verify decision | Not written to the hosted log. There is no `onDecision` hook in the SDK or PHP drop-in today. If you need an audit trail, record the `verifySignIn` / `verifyLocalPass` result on your server (that is your responsibility today; a hook is planned, not shipped). |
| Logging failure | Access still proceeds. `recordDecision` catches Redis errors and does not fail the verify or sign-in. The decision webhook (Business and Enterprise, opt-in) is one POST, 3 second timeout, no retries; delivery is best-effort, not at-least-once. A failed webhook leaves the row in the Redis export until retention or the cap drops it. |

Full fields, retention, caps and export: https://proveitonchain.com/docs/enterprise#logging

## Decision records: retention, modification and purge

This is how the hosted TOKENLOCK service stores decision and access records today (not something the SDK itself stores). Full version: https://proveitonchain.com/docs/enterprise#decision-records

**Where records live.** Access state (settings, organizations, keys, owner names and emails, open requests) lives in Upstash Redis. After each admin change, a durable backup is written to Vercel Blob at an HMAC-hashed path, encrypted with AES-256-GCM. A separate encrypted journal records key and policy changes and is replayed after a restore so a later revoke is not undone by an older snapshot. The backup holds state, keys and requests. It does not include the decision log or the admin-action history list. The decision log records sign-in outcomes, denied pass checks, and successful verifies that reach the API (these count toward the monthly cap). SDK or PHP cache hits and self-verify decisions are not hosted-logged. The log lives in Upstash Redis only, in a per-site list for each day. Site documents live in Vercel Blob.

**Retention and caps** (decision log): 14 days / 500 rows a month on Free, 30 / 2,000 on Starter, 90 / 10,000 on Pro, 180 / 25,000 on Business and 365 / 100,000 on Enterprise. The per-day list cap is ceil(monthly/10). The Redis keys expire one day after the retention window. If a site goes over the per-day list cap, the oldest rows for that day are dropped; the daily counts remain. The decisions API returns `monthly_used`, `today_count` and `warnings` at 80% and at the cap.

**Soft deletion.** Deleting a site marks the site document `deleted` with a `deleted_at` time and removes it from your account list, but the document stays in storage. The site's publishable key, secret key and outstanding passes stop working immediately. Soft deletion does not purge Redis access state, the encrypted Blob backup or journal, or decision-log keys. Decision-log keys expire with their retention TTL. Access state, the backup and the journal have no automatic expiry. To request permanent deletion of owner details, backups, journals and residual site records, email gotproof@oplanbtc.com.

**Who can modify or purge them.** You (the site dashboard or the site secret key) can export the decision log (`GET /access/decisions/export`, CSV or JSONL) and can change your settings, keys and organizations. You cannot edit or delete individual decision records; there is no customer API for that. You can soft-delete the site, which hides it from your account and immediately stops its credentials, but does not erase the stored records above. Prove It Onchain operators who have the live Redis credentials can read, change or delete any of these Redis keys. Operators who have the Vercel Blob credentials can read the ciphertext of a backup, overwrite it or delete it; operators who also have the backup encryption key can decrypt it. The platform admin token can turn enterprise-access pilot on or off for a site; it is not a decision-log editor.

**Retention alone is not tamper evidence.** Anyone with the credentials above can change or delete stored records. Entries are not hash-chained, and there is no signed or anchored digest, so a later change would not be evident from the log itself.

**Current mitigations.** Export the log to your own systems (`GET /access/decisions/export` is a read of whatever is still in Redis). On Business and Enterprise you can opt in to a signed decision webhook: each logged decision is POSTed once to your HTTPS URL, HMAC-SHA256 in `x-tokenlock-signature`, 3 second timeout, no retries. Delivery is best-effort, not at-least-once. Webhook retries and a SIEM sink are planned, not shipped. Decision logs are not included in the Blob backup; if Redis is lost, in-window rows may be gone.

**Roadmap (planned, not shipped):** hash-chained log entries with a periodic signed or anchored digest; webhook retries and a SIEM sink; separate verify-only, admin, and read-only audit-export credentials (today the same `sk_…` verifies passes and manages access).

