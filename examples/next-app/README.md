# TOKENLOCK + Next.js (App Router)

1. Create a site at https://proveitonchain.com/tokenlock/dashboard with `http://localhost:3000` as a site address and pick the tokens that unlock it.
2. `cp .env.example .env.local` and paste your keys.
3. `npm install && npm run dev`, then open http://localhost:3000/members.

Files: `middleware.ts` (locks /members), `app/api/tokenlock/[action]/route.ts` (pass → cookie, sign out), `app/signin/page.tsx` (button), `app/members/page.tsx` (`getPass()`).
