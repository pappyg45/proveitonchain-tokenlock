import { defineConfig } from 'tsup';
const shared = { format: ['esm', 'cjs'] as const, dts: true, sourcemap: false, target: 'es2020', external: ['next', 'next/server', 'next/server.js', 'next/headers', 'next/headers.js', 'react', 'react/jsx-runtime'], splitting: false, treeshake: true };
export default defineConfig([
  { ...shared, entry: { index: 'src/index.ts', next: 'src/next.ts', express: 'src/express.ts' } },
  { ...shared, entry: { react: 'src/react.tsx' }, banner: { js: '"use client";' } },
  // Self-verify bundles its two audited crypto libraries (@noble/curves, @noble/hashes), so the package keeps zero runtime dependencies.
  { ...shared, entry: { 'self-verify': 'src/self-verify/index.ts' }, noExternal: [/^@noble\//], platform: 'node' },
]);
