# TOKENLOCK + Express

1. Create a site at https://tokenlock.ai/dashboard with `http://localhost:3000` as a site address and pick its tokens.
2. `npm install`
3. `TOKENLOCK_SITE_KEY=pk_… TOKENLOCK_SECRET_KEY=sk_… npm start`, then open http://localhost:3000/members.

Needs `@tokenlock/sdk` 0.5.3 or later (the same code was published as `@proveitonchain/tokenlock` 0.5.0–0.5.2). `server.js` sets `tokenOnly: true` (a holder site: any wallet holding one of your tokens may open /members). If you turn on registered keys and want each key's routes enforced, remove it.
