# @proveitonchain/tokenlock

Lock pages on your site to people who hold a name or token on Bitcoin. **Your content stays on your server. We do the Token check.**

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
| `getPass(req, opts?)` | The verified pass from the request cookie, or `null`. Works with Fetch `Request`, `NextRequest`, Express/Node `req`. |
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

### `<SignInWithBitcoin />` props

`siteKey` (required), `redirectTo` (default: `?next=` or `/`), `sessionUrl` (`/api/tokenlock/session`), `label` (`Sign in with your Token`), `title`, `passTtlSeconds` (3600), `className`, `style`, `onSignedIn`, `onError`. Also exported: `SignOutLink`, `loadGate()`.

## Cloudflare

`examples/cloudflare-worker/worker.js` puts the same check in front of any site, with no dependencies.

## How it stays safe

- The secret key never leaves your server. Passes are checked with it, so a pass made for another site is refused.
- The pass cookie is HttpOnly, Secure and SameSite=Lax, and the session endpoint refuses requests from other sites.
- Good checks are cached in memory for at most 60 seconds and never past the pass's expiry.
- Your dashboard shows every sign-in attempt, and Business plans can get webhook alerts on failure spikes.
- A pass proves the visitor controlled a wallet holding your token when they signed in. It does not prove who they are.

## Plans

Free: 1 site, 100 sign-ins a month. Pro and Business add sites, sign-ins, branding and alerts. See https://proveitonchain.com/tokenlock. Going over never breaks your site.

MIT © Prove It Onchain
