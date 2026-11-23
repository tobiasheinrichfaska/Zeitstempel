// Runs the library and the relay's browser interface in a real (headless) Chromium.
// By hand, no network needed: the relay gets a recorded answer instead of a real service.
//   node scripts/browser-check.mjs
// Prerequisites:
//   - Node 24 and `npm install` (vite, which builds the bundle, comes along as a dependency of vitest).
//   - Playwright (1.5x or newer; tested with 1.63) with an installed Chromium (`npx playwright install
//     chromium`). Playwright is NOT a dependency of this project: install it where `require('playwright')`
//     finds it (node_modules next to this project, or NODE_PATH).
//   - No relay key: the relay inside this script runs with authentication off (`keys: 'off'`, the
//     equivalent of RELAY_AUTH=off, on 127.0.0.1 only), so this check does NOT cover `signRelayRequest`
//     or the signed header in a browser.
import { createRequire } from 'node:module';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { build } from 'vite';
import { createRelayServer } from '../relay/server.ts';
import { loadServices } from '../relay/load.ts';

const root = fileURLToPath(new URL('..', import.meta.url));
const out = `${root}.tmp/browser/`;
mkdirSync(out, { recursive: true });
writeFileSync(
  `${out}entry.ts`,
  `import * as lib from '${root}src/lib/index.ts';\n(globalThis as Record<string, unknown>).zs = lib;\n`,
);
await build({
  root: out,
  logLevel: 'warn',
  build: {
    lib: { entry: 'entry.ts', formats: ['iife'], name: 'zsb', fileName: () => 'bundle.js' },
    outDir: 'dist',
    emptyOutDir: true,
  },
});
const bundle = readFileSync(`${out}dist/bundle.js`, 'utf8');
const b64 = (name) => readFileSync(`${root}tests/fixtures/${name}`).toString('base64');
const pem = (name) => readFileSync(`${root}anchors/${name}.pem`, 'utf8');

const NOW = Date.parse('2026-11-23T13:10:00Z');
const { chromium } = createRequire(import.meta.url)('playwright');

// The page's own origin; the relay allows exactly this origin.
const page = http.createServer((_q, r) => {
  r.setHeader('content-type', 'text/html');
  r.end('<!doctype html><html><body></body></html>');
});
await new Promise((r) => page.listen(0, '127.0.0.1', r));
const pageOrigin = `http://localhost:${page.address().port}`;
const { server: relay } = createRelayServer({
  services: loadServices(),
  origins: [pageOrigin],
  allowPlainHttp: false,
  keys: 'off', // local, loopback only: the check calls the relay without a signature
  upstream: async () => ({
    status: 200,
    contentType: 'application/timestamp-reply',
    body: new Uint8Array(readFileSync(`${root}tests/fixtures/freetsa.tsr`)),
  }),
  random: () => Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
  now: () => NOW,
});
await new Promise((r) => relay.listen(0, '127.0.0.1', r));
const relayUrl = `http://127.0.0.1:${relay.address().port}`;

const browser = await chromium.launch();
let failed = false;
try {
  const p = await browser.newPage();
  await p.goto(`${pageOrigin}/`);
  await p.addScriptTag({ content: bundle });
  const results = await p.evaluate(
    async ({ cases, anchors, relayUrl }) => {
      const dec = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
      const hash = new Uint8Array(
        await crypto.subtle.digest('SHA-256', new TextEncoder().encode('probe')),
      );
      const nonce = Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8);
      const res = [];
      for (const c of cases) {
        const r = zs.readTimestampResponse(dec(c.tsr));
        const v = await zs.verifyTimestampToken(r.value.token, hash, [anchors[c.anchor]], {
          expectedNonce: nonce,
        });
        const wrong = await zs.verifyTimestampToken(r.value.token, new Uint8Array(32), [
          anchors[c.anchor],
        ]);
        const elsewhere = await zs.verifyTimestampToken(r.value.token, hash, [
          anchors[c.otherAnchor],
        ]);
        // The token carries a copy of the trust anchor's certificate (a cross-signed form for some
        // services). The caller's anchor is used instead, so changes inside that copy are
        // legitimately accepted, as in tests/verify.test.ts.
        let changed = 0;
        const bytes = r.value.token;
        const anchorCert = zs.parsePemCertificates(anchors[c.anchor])[0];
        const skip = [];
        for (const cert of zs.readToken(bytes).certificates) {
          if (cert.subject.length !== anchorCert.subject.length) continue;
          if (!cert.subject.every((x, j) => x === anchorCert.subject[j])) continue;
          for (let i = 0; i + cert.raw.length <= bytes.length; i += 1)
            if (cert.raw.every((x, j) => bytes[i + j] === x)) skip.push([i, i + cert.raw.length]);
        }
        for (let i = 0; i < bytes.length; i += 53) {
          if (skip.some(([from, to]) => i >= from && i < to)) continue;
          const copy = bytes.slice();
          copy[i] ^= 1;
          const t = await zs.verifyTimestampToken(copy, hash, [anchors[c.anchor]], {
            expectedNonce: nonce,
          });
          if (t.ok) changed += 1;
        }
        res.push({
          name: `verify ${c.name} (${c.alg})`,
          pass:
            v.ok &&
            wrong.reason === 'imprint-mismatch' &&
            elsewhere.reason === 'untrusted-chain' &&
            changed === 0,
          detail: `${v.ok ? v.value.signer : v.reason} | wrong=${wrong.reason} elsewhere=${elsewhere.reason} accepted-changes=${changed}`,
        });
      }
      // Cross-origin call to the relay, as an app would make it (preflight included).
      const body = JSON.stringify({ hash: zs.toBase64Url(hash) });
      const ask = () =>
        fetch(`${relayUrl}/v1/stamp/freetsa`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body,
        });
      const first = await ask();
      const answer = await first.json();
      const token = zs.fromBase64Url(answer.token);
      const again = await zs.verifyTimestampToken(token, hash, [anchors.freetsa]);
      res.push({
        name: 'relay call from the page, token verified again without the relay nonce',
        pass: first.status === 200 && again.ok && answer.genTime === again.value.genTime,
        detail: `${first.status} ${answer.genTime}`,
      });
      let last;
      for (let i = 0; i < 4; i += 1) last = await ask();
      const wait = last.headers.get('Retry-After');
      res.push({
        name: 'Retry-After readable by the page on 429',
        pass: last.status === 429 && Number(wait) > 0,
        detail: `${last.status} ${wait}`,
      });
      return res;
    },
    {
      relayUrl,
      anchors: {
        freetsa: pem('freetsa-root'),
        sectigo: pem('usertrust-rsa'),
        digicert: pem('digicert-trusted-root-g4'),
        certum: pem('certum-trusted-network-ca-2'),
      },
      cases: [
        ['freetsa', 'signer ECDSA P-384', 'freetsa', 'sectigo'],
        ['sectigo', 'signer RSA-4096', 'sectigo', 'freetsa'],
        ['digicert', 'signer RSA-4096', 'digicert', 'freetsa'],
        ['certum', 'signer RSA-4096', 'certum', 'freetsa'],
      ].map(([name, alg, anchor, otherAnchor]) => ({
        name,
        alg,
        anchor,
        otherAnchor,
        tsr: b64(`${name}.tsr`),
      })),
    },
  );
  console.log(await p.evaluate(() => navigator.userAgent));
  for (const r of results) {
    console.log(`${r.pass ? 'OK  ' : 'FAIL'} ${r.name}: ${r.detail}`);
    if (!r.pass) failed = true;
  }
} finally {
  await browser.close();
  relay.close();
  page.close();
}
process.exit(failed ? 1 : 0);
