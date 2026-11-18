# @proveitonchain/tokenlock

**Zero-trust access for the token era.** An extra layer in front of your login, admin, or API. Only verified token holders get through.

Your content stays on your server. We do the Token check. Built for security teams, AI agents, and mining operations. Self-verify (public spec, no dependence on our API) is in preview for Enterprise: see [Self-verify (0.3.0)](#self-verify-030-preview).

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

## 2. Install

```bash
npm install @proveitonchain/tokenlock
```

## 3. Lock your pages (Next.js)

**`middleware.ts`**

```ts
import { tokenlock } from '@proveitonchain/tokenlock/next';

export default tokenlock({
  protect: ['/members/:path*'],
  signInPage: '/signin',
});

export const config = { matcher: ['/members/:path*'] };
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
  const pass = await getPass(); // null, or { address, assets_held, name, expires_at, … }
  return <p>Signed in as {pass?.address}</p>;
}
```

Sign out: link to `/api/tokenlock/signout`.

## Express

```js
import express from 'express';
import { tokenlock } from '@proveitonchain/tokenlock/express';

const app = express();
app.use(tokenlock({ protect: ['/members/:path*'], signInPage: '/signin' }));
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

const v = await verifyPass(pass, { secretKey: process.env.TOKENLOCK_SECRET_KEY });
if (v.valid) { /* v.address, v.assets_held, v.site_id, v.expires_at */ }

const visitor = await getPass(req);          // reads the tokenlock_pass cookie and checks it
const ch = await createChallenge({ siteKey: 'pk_…', origin: 'https://yoursite.com' }); // build your own wallet flow

const client = new TokenlockClient({ secretKey, siteKey }); // low-level REST client
await client.request('POST', '/api/v1/gate/verify', { pass });
```

| Function | What it does |
| --- | --- |
| `verifyPass(pass, { secretKey })` | `{ valid, address, assets_held, site_id, expires_at }` or `{ valid: false, code }`. Throws `TokenlockError` only if the API can't be reached. |
| `getPass(req, opts?)` | The verified pass from the request cookie, or `null`. **Identity only** unless you pass `{ path, method, environment }`. Works with Fetch `Request`, `NextRequest`, Express/Node `req`. |
| `authorize(req, { path, method, environment })` | Strict, uncached check for one action (agent APIs, sensitive operations). `{ valid: true, allowed: true, … }` or `{ valid: false, allowed: false, code, reason }`. |
| `canonicalPath(path)` | The path used for matching (see Path rules), or `null` to reject. |
| `clearCache(pass?)` | Drops every cached answer for that pass (all routes), or everything. |
| `createChallenge({ siteKey, origin })` | Starts a sign-in: `{ challenge_id, message, assets }`. |
| `TokenlockClient` | `verifyPass`, `createChallenge`, `signIn`, and `request()` for any `/api/v1` call (sends `Authorization: Bearer sk_…`). |
| `passCookie`, `clearPassCookie`, `readPass`, `createMatcher`, `safeNext` | Helpers used by the adapters. |

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
| `strict` | on | See Strict mode. `strict: true` with `failOpen` or `checkResource: false` throws at startup |
| `checkResource` | `true` | Send path + method with each check |
| `failOpen` | `false` | Let pass holders in unverified when the API is down. Turns strict off (with a warning) |
| `apiPaths` | none | Paths that always get JSON 401/403 (API mode) |
| `caseSensitive` | `false` | `/ADMIN` is the same as `/admin` unless set |
| `cache` | `true` | `false` asks the API on every request |

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

## Enterprise access controls (0.2.0)

Sites with **registered keys** turned on (Business and Enterprise) check every request against the key's routes, methods, environment and expiry, and see revocations immediately. Nothing changes for token-only sites.

```js
const info = await verifyPass(pass, { secretKey, path: '/api/partner/prices', method: 'GET', environment: 'production' });
if (!info.valid) return res.status(403).json({ code: info.code, correlation_id: info.correlation_id });
info.access; // { mode: 'registered_keys', allowed, reason, key: { id, label, owner_type, owner_name }, permissions, key_expires_at }
```

- The Express and Next.js middleware send the request path and method with each pass check (set `environment: 'production'` to check environments). An out-of-scope route answers `403` JSON instead of redirecting to sign-in.
- `correlation_id` matches the entry in your decision log.

## Security model (0.2.1)

### Sessions: a bearer pass, not a per-request signature

The wallet signature happens once, at sign-in. It gets the visitor (or agent) a **pass**: a signed, expiring bearer token kept in an HttpOnly cookie (or sent by an agent). Each request presents that pass; it is **not** a fresh signature per request. Anyone who steals the pass can use it until it expires or the key is revoked, so keep passes short for agents (`pass_ttl_s`), serve over HTTPS, and never log them. Per-request signing for agent APIs (each request signed by the agent's key over method, path, body hash and a timestamp) is on the roadmap.

### Path rules (the same in every adapter and on the API)

Paths are matched in canonical form, case-insensitively: query and fragment dropped; percent-decoded **once**; `;params` dropped from each segment; `//` collapsed; `.` and `..` resolved; trailing `/` dropped. Requests are **rejected with 400** if the path has a backslash, a control byte, an encoded `/` `\` NUL or `%` (`%2f`, `%5c`, `%00`, `%25`), invalid encoding, or `..` above the root. So `/ADMIN`, `/admin/`, `//admin`, `/%61dmin`, `/admin;x` and `/./admin` are all `/admin`, and `/admin%2f..` is refused. Test vectors: `test/fixtures/path-vectors.json`.

Next.js: keep `config.matcher` broad (or leave it out). Next's own matcher is case-sensitive, so `matcher: ['/admin/:path*']` would never run the middleware for `/ADMIN`.

### Strict mode (default)

An answer counts only if it is complete and says `allowed: true` for **exactly** the path, method and environment you asked about (the API echoes them back). Anything else (missing fields, an unknown access mode, a different resource, an expired pass) is a denial. Strict is on in the middleware and whenever you pass a resource to `verifyPass`. `strict: true` together with `failOpen: true` or `checkResource: false` throws when the middleware is created; setting either of those without `strict` turns strict off and logs a warning. When the API can't answer, strict mode denies protected requests with `503`.

### Revocation window

| Setup | How long a revoked key, expired key, revoked entitlement or changed permission can still get in |
| --- | --- |
| Strict (default), registered keys | **0**: never cached, every protected request asks the API |
| `strict: false`, registered keys | up to **5 s** per server process (the API's `cache_max_s`) |
| Token-only sites (no registered keys) | Holdings are checked at sign-in; a pass stays good until it expires (cached up to 60 s) |
| `cache: false` (any mode) | 0 |
| 0.1.x SDKs | up to 60 s |

`clearCache(pass)` drops every cached answer for that pass, for all routes.

### API mode

Requests with `Accept: application/json` (and not `text/html`), or under `apiPaths`, get JSON instead of a redirect, for every denial: `401` when there is no pass or it is invalid or expired (sign in again), `403` when signed in but not allowed (route, method, environment, revoked, expired or pending key, organization, entitlement), `400` for a rejected path, `503` when the API can't answer. Body: `{ error, code, reason, correlation_id }`.

## Self-verify (0.3.0, preview)

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
const v = await verifyLocalPass(cookie, { passSecret: process.env.MY_PASS_SECRET });
```

Registered keys offline: `signedPolicy({ siteId, secretKey, publicKeys: { kid: key } })` pulls a BIP-340-signed bundle
(Enterprise or pilot), checks it against the key you pinned from `/.well-known/tokenlock-policy-keys.json`, refreshes
every 60 s, uses the cached bundle while refreshes fail until it expires (default 600 s), then fails closed. Or use
`localPolicy(...)` if you keep the policy yourself.

| Mode | You still trust |
|---|---|
| our holdings provider | our reading of the chain (and the bundle signer, if used) |
| tokenscan / your node via `httpJsonProvider` | that source (two sources with `requireAgreement`) |
| `localPolicy` + your node | nothing outside your servers |

All modes fail closed: lookup errors, an expired or unverifiable policy, replays and bad signatures all deny. The
`./self-verify` entry bundles the noble cryptography libraries, so there are no extra dependencies to install. PHP:
`tokenlock/self-verify.php` in the PHP drop-in (it needs the GMP extension), with the same formats. A pass issued by one
side verifies on the other.

