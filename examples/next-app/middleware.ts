import { tokenlock } from '@proveitonchain/tokenlock/next';

// Everything under /members needs a pass. Which tokens unlock it is set in your TOKENLOCK dashboard.
// Paths are matched case-insensitively in canonical form, so /MEMBERS, //members and /%6Dembers are locked too.
export default tokenlock({
  protect: ['/members/:path*'],
  signInPage: '/signin',
  environment: 'production',
});

// Keep the matcher broad: Next's own matcher is case-sensitive, so ['/members/:path*'] would skip /MEMBERS.
// This runs the middleware on everything except static assets; tokenlock() decides what is locked.
export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] };
