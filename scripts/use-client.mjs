// Mark the React entry as a client component for the Next.js App Router.
import fs from 'node:fs';
for (const f of ['dist/react.js', 'dist/react.cjs']) {
  const s = fs.readFileSync(f, 'utf8');
  if (!/^["']use client["']/.test(s)) fs.writeFileSync(f, '"use client";\n' + s);
}
