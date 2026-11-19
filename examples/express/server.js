import express from 'express';
import { tokenlock } from '@proveitonchain/tokenlock/express';
import { safeNext } from '@proveitonchain/tokenlock';

// TOKENLOCK_SECRET_KEY and TOKENLOCK_SITE_KEY come from https://proveitonchain.com/tokenlock/dashboard
const app = express();
app.use(express.json());
// tokenOnly: true = a holder site (any wallet holding one of your tokens may open /members). Remove it if you turn on
// registered keys and want each key's routes, methods and environments enforced (without it a holder site answers 403
// policy_required, because there are no route rules to permit the path).
app.use(tokenlock({ protect: ['/members/:path*'], signInPage: '/signin', tokenOnly: true }));
// tokenlock() also handles POST /api/tokenlock/session and /api/tokenlock/signout.

app.get('/', (req, res) => res.send('<h1>Public home</h1><a href="/members">Members</a>'));
app.get('/signin', (req, res) => res.send(`<!doctype html><meta charset="utf-8"><title>Sign in</title>
<h1>Members only</h1>
<script src="https://proveitonchain.com/gate.js" data-site-key="${process.env.TOKENLOCK_SITE_KEY}"></script>
<button id="go">Sign in with your Token</button>
<script>
  go.onclick = async () => {
    const { pass } = await ProveItGate.signIn();
    const r = await fetch('/api/tokenlock/session', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ pass }) });
    // Only same-site paths: ?next=//evil.com, /\\evil.com, javascript:… fall back to '/'.
    if (r.ok) location.assign(tlSafeNext(new URLSearchParams(location.search).get('next') || '/members'));
  };
  const tlSafeNext = ${safeNext.toString()};
</script>`));
app.get('/members', (req, res) => res.send(`<h1>Welcome in</h1><p>Signed in as ${req.tokenlock.address}</p><a href="/api/tokenlock/signout">Sign out</a>`));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`http://localhost:${port}`));
