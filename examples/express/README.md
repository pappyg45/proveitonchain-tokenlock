# TOKENLOCK + Express

1. Create a site at https://proveitonchain.com/tokenlock/dashboard with `http://localhost:3000` as a site address and pick its tokens.
2. `npm install`
3. `TOKENLOCK_SITE_KEY=pk_… TOKENLOCK_SECRET_KEY=sk_… npm start`, then open http://localhost:3000/members.

Needs `@proveitonchain/tokenlock` 0.4.4 or later. `server.js` sets `tokenOnly: true` (a holder site: any wallet holding one of your tokens may open /members). If you turn on registered keys and want each key's routes enforced, remove it.
