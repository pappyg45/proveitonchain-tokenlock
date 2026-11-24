import { tokenlock } from '@tokenlock/sdk/next';

// Everything under /members needs a pass. Which tokens unlock it is set in your TOKENLOCK dashboard.
// tokenOnly: true = a holder site (any wallet holding one of your tokens may open /members). Remove it if you turn on
// registered keys and want each key's routes, methods and environments enforced (without it a holder site answers
// 403 policy_required, because there are no route rules to permit the path).
// Paths are matched case-insensitively in canonical form, so /MEMBERS, //members and /%6Dembers are locked too.
export default tokenlock({
  protect: ['/members/:path*'],
  signInPage: '/signin',
  environment: 'production',
  tokenOnly: true,
});

// Keep the matcher broad: Next's own matcher is case-sensitive, so ['/members/:path*'] would skip /MEMBERS.
// This runs the middleware on everything except static assets; tokenlock() decides what is locked.
export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] };
