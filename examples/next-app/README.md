# TOKENLOCK + Next.js (App Router)

1. Create a site at https://tokenlock.ai/dashboard with `http://localhost:3000` as a site address and pick the tokens that unlock it.
2. `cp .env.example .env.local` and paste your keys.
3. `npm install && npm run dev`, then open http://localhost:3000/members.

Files: `middleware.ts` (locks /members), `app/api/tokenlock/[action]/route.ts` (pass → cookie, sign out), `app/signin/page.tsx` (button), `app/members/page.tsx` (`getPass(undefined, { identityOnly: true })`). Needs `@tokenlock/sdk` 0.5.3 or later (the same code was published as `@proveitonchain/tokenlock` 0.4.4–0.5.2).

`middleware.ts` sets `tokenOnly: true` (a holder site: any wallet holding one of your tokens may open /members). If you turn on registered keys in the dashboard and want each key's routes enforced, remove it.
