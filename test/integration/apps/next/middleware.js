import { tokenlock } from '@tokenlock/sdk/next';

// Same protection as the other integration apps: /admin and /members (and everything under them), any case.
export const middleware = tokenlock({ protect: ['/admin/:path*', '/members/:path*'], signInPage: '/signin', environment: 'production' });
export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] };
