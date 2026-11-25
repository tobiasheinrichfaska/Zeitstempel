// Runs the library and the relay's browser interface in real (headless) browsers.
// By hand or in CI, no network needed: the relays of this script get recorded or built answers instead of a
// real service.
//   npm run build && node scripts/browser-check.mjs        (also: npm run browser-check)
//   BROWSERS=chromium,firefox,webkit node scripts/browser-check.mjs   (default: chromium only)
// Prerequisites:
//   - Node 24, `npm install` and a built `dist/` (`npm run build`): the page loads the BUILT library, as an
//     app would.
//   - Playwright (tested with 1.63) with the installed browsers (`npx playwright install chromium`).
//     Playwright is NOT a dependency of this project: install it where `require('playwright')` finds it
//     (node_modules next to this project, or NODE_PATH).
// Exit codes: 0 all checks passed, 1 a check failed, 2 the check could not run (no Playwright, no browser,
// no `dist/`).
// Three parts per browser (87 checks in Chromium, 57 in A and B, 30 in C; about 80 s):
//   A) the relay with authentication off (`keys: 'off'`, loopback): the four recorded tokens, a call from the
//      page, `Retry-After` on a 429.
//   B) signed calls: `signRelayRequest` with key bytes and a non-extractable CryptoKey, wrong signatures,
//      clock correction with `Date`, replay, CORS with preflight, collecting operation with
//      `verifyBatchedTimestamp`, solo stamps of a type-2 key, the insecure context (Chromium only), and the
//      same verdicts as in Node. The token builder of the tests stands in for a service.
//   C) the client `zeitstempel/client` (dist/client) in the page, page and relays on different origins of
//      127.0.0.1 (same site, so a cookie WOULD be sent with credentials 'include': a control proves it): stamp in
//      single and collecting operation, solo (type 2, and type 1 refused), evidence round trip and
//      verifyEvidence (browser and Node), wrong hash, key as bytes and as non-extractable CryptoKey, clock
//      correction with a Date.now override (+-30 s without, +-62 s with one 401, +-70 s refused), Retry-After on
//      429, abort (waiting, slow answer, before sending), failover between services, no cookie or Authorization.
import { createRequire } from 'node:module';
import { existsSync, readFileSync, statSync } from 'node:fs';
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const R = fileURLToPath(new URL('..', import.meta.url));
const stop = (message) => {
  console.error(`browser-check: ${message}`);
  process.exit(2);
};

if (!existsSync(`${R}dist/index.js`)) stop('dist/ is missing: run `npm run build` first.');
let playwright;
try {
  playwright = createRequire(import.meta.url)('playwright');
} catch {
  stop(
    'Playwright was not found (it is not a dependency of this project). Install it where ' +
      "require('playwright') finds it, and a browser: `npm install --no-save playwright` and " +
      '`npx playwright install chromium`.',
  );
}

const { createRelayServer } = await import(`${R}relay/server.ts`);
const { loadServices } = await import(`${R}relay/load.ts`);
const { build, int, seq } = await import(`${R}tests/token-builder.ts`);
const { children, integerBytes, octets, parseDer } = await import(`${R}src/lib/der.ts`);
const nodeLib = await import(`${R}dist/index.js`);

const wanted = (process.env.BROWSERS ?? 'chromium')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
for (const name of wanted)
  if (!['chromium', 'firefox', 'webkit'].includes(name))
    stop(`BROWSERS names an unknown browser: ${name} (chromium, firefox, webkit).`);

let total = 0;
let failed = 0;
const record = (engine, name, pass, detail = '') => {
  total += 1;
  if (!pass) failed += 1;
  console.log(`${pass ? 'OK  ' : 'FAIL'} [${engine}] ${name}${detail ? `: ${detail}` : ''}`);
};

const SIGNER = build();
const SERVICES = loadServices();
const genTimeText = (ms) =>
  new Date(ms)
    .toISOString()
    .replace(/[-:T]/g, '')
    .replace(/\.\d+Z$/, 'Z');
// the stub service: answers a request with a token that is valid for it (hash and nonce of the request)
function replyFor(request, atMs) {
  const parts = children(parseDer(request));
  const hash = octets(children(parts[1])[1]);
  const nonceBytes = integerBytes(parts[2]);
  const made = build({ keys: SIGNER.keys, hash, nonceBytes, genTime: genTimeText(atMs) });
  return seq(seq(int(0)), made.token);
}
const upstream = async (_t, body) => ({
  status: 200,
  contentType: 'application/timestamp-reply',
  body: replyFor(body, Date.now()),
});

const mime = { '.js': 'text/javascript', '.html': 'text/html' };
// a page of its own origin; it serves the built library under /dist/
function pageServer() {
  return http.createServer((q, r) => {
    const u = new URL(q.url, 'http://x');
    if (u.pathname.startsWith('/dist/')) {
      const f = R + u.pathname.slice(1);
      if (!f.includes('..') && existsSync(f) && statSync(f).isFile()) {
        r.setHeader('content-type', mime[f.slice(f.lastIndexOf('.'))] ?? 'text/plain');
        return r.end(readFileSync(f));
      }
      r.statusCode = 404;
      return r.end();
    }
    r.setHeader('content-type', 'text/html');
    r.end('<!doctype html><html><body></body></html>');
  });
}
const listen = (s) => new Promise((r) => s.listen(0, '127.0.0.1', r));

const b64 = (n) => readFileSync(`${R}tests/fixtures/${n}`).toString('base64');
const pem = (n) => readFileSync(`${R}anchors/${n}.pem`, 'utf8');
const ANCHORS = {
  freetsa: pem('freetsa-root'),
  sectigo: pem('usertrust-rsa'),
  digicert: pem('digicert-trusted-root-g4'),
  certum: pem('certum-trusted-network-ca-2'),
};
const CASES = [
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
}));

const json = (_k, x) => (x instanceof Uint8Array ? Array.from(x) : x);

// Part A: authentication off, recorded answer
async function partA(engine, browser) {
  const rec = (name, pass, detail) => record(engine, `A ${name}`, pass, detail);
  // the relay clock: a few seconds after the recorded FreeTSA token (13:05:56), because the relay refuses a token
  // whose time is not around the moment of its request (genTimeSlackMs)
  const NOW = Date.parse('2026-11-23T13:06:00Z');
  const page = pageServer();
  await listen(page);
  const pageOrigin = `http://localhost:${page.address().port}`;
  // maxWaitMs 1 s against the 5 s minimum distance of FreeTSA: the second request in a row finds the distance
  // longer than it may wait and gets 429 with Retry-After at once (a longer maxWaitMs would let it wait: 200)
  const { server: relay } = createRelayServer({
    services: loadServices(),
    origins: [pageOrigin],
    allowPlainHttp: false,
    keys: 'off', // local, loopback only: this part calls the relay without a signature
    maxWaitMs: 1000,
    upstream: async () => ({
      status: 200,
      contentType: 'application/timestamp-reply',
      body: new Uint8Array(readFileSync(`${R}tests/fixtures/freetsa.tsr`)),
    }),
    random: () => Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
    now: () => NOW,
  });
  await listen(relay);
  const relayUrl = `http://127.0.0.1:${relay.address().port}`;
  try {
    const p = await browser.newPage();
    await p.goto(`${pageOrigin}/`);
    await p.evaluate(async () => {
      window.zs = await import('/dist/index.js');
    });
    const results = await p.evaluate(
      async ({ cases, anchors, relayUrl }) => {
        const zs = window.zs;
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
        const second = await ask();
        const wait = second.headers.get('Retry-After');
        res.push({
          name: 'Retry-After readable by the page on 429',
          pass: second.status === 429 && Number(wait) > 0,
          detail: `${second.status} ${wait}`,
        });
        return res;
      },
      { relayUrl, anchors: ANCHORS, cases: CASES },
    );
    for (const r of results) rec(r.name, r.pass, r.detail);
    await p.close();
  } finally {
    relay.closeAllConnections();
    relay.close();
    page.close();
  }
}

// Part B: signed calls
async function partB(engine, browser, launcher) {
  const rec = (name, pass, detail) => record(engine, name, pass, detail);
  const preflights = [];
  const relays = [];
  const page1 = pageServer();
  const page2 = pageServer(); // a foreign origin
  await listen(page1);
  await listen(page2);
  const origin1 = `http://localhost:${page1.address().port}`;
  const origin2 = `http://localhost:${page2.address().port}`;
  try {
    const ctx = await browser.newContext();
    const p = await ctx.newPage();
    const pageErrors = [];
    p.on('pageerror', (e) => pageErrors.push(String(e)));
    await p.goto(`${origin1}/`);
    console.log(
      `[${engine}]`,
      await p.evaluate(() => navigator.userAgent),
      'secure:',
      await p.evaluate(() => isSecureContext),
    );
    await p.evaluate(async () => {
      window.zs = await import('/dist/index.js');
    });
    // keys generated in the browser: a = type 1 (extractable pkcs8), b = type 2 solo, c = non-extractable
    // CryptoKey (type 1), d = unknown to the relay
    const keys = await p.evaluate(async () => {
      window.K = {};
      const res = {};
      for (const [n, ex] of [
        ['a', true],
        ['b', true],
        ['c', false],
        ['d', true],
      ]) {
        const k = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, ex, [
          'sign',
          'verify',
        ]);
        window.K[n] = k;
        res[n] = {
          pub: Array.from(new Uint8Array(await crypto.subtle.exportKey('raw', k.publicKey))),
          pk: ex
            ? Array.from(new Uint8Array(await crypto.subtle.exportKey('pkcs8', k.privateKey)))
            : null,
        };
      }
      return res;
    });
    const relayKeys = [
      { id: 'app-a', publicKey: Uint8Array.from(keys.a.pub) },
      { id: 'app-b', publicKey: Uint8Array.from(keys.b.pub), solo: true },
      { id: 'app-c', publicKey: Uint8Array.from(keys.c.pub) },
    ];
    const mkOptions = (extra) => ({
      services: SERVICES.map((s) => ({ ...s, anchorPems: [...s.anchorPems, SIGNER.caPem] })),
      origins: [origin1],
      allowPlainHttp: false,
      upstream,
      random: (n) => new Uint8Array(randomBytes(n)),
      now: () => Date.now(),
      keys: relayKeys,
      audience: 'https://relay.browser-check', // the browser signs this name (AUD below)
      ...extra,
    });
    const { server: rs1 } = createRelayServer(mkOptions({ batch: { windowMs: 300, max: 100 } }));
    const { server: rs2 } = createRelayServer(mkOptions({}));
    for (const s of [rs1, rs2])
      s.prependListener('request', (q) =>
        preflights.push({
          m: q.method,
          url: q.url,
          origin: q.headers.origin,
          acrm: q.headers['access-control-request-method'],
          acrh: q.headers['access-control-request-headers'],
        }),
      );
    await listen(rs1);
    await listen(rs2);
    relays.push(rs1, rs2);
    const B1 = `http://127.0.0.1:${rs1.address().port}`;
    const B2 = `http://127.0.0.1:${rs2.address().port}`;
    const trust = SIGNER.caPem;

    await p.evaluate((o) => {
      window.__other = o;
    }, ANCHORS.freetsa);
    const res = await p.evaluate(
      async ({ keys, B1, B2, trust }) => {
        const zs = window.zs;
        const out = [];
        const add = (name, pass, detail = '') => out.push({ name, pass, detail });
        const enc = new TextEncoder();
        const sha = async (s) =>
          new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s)));
        const pk = (n) => Uint8Array.from(keys[n].pk);
        const AUD = 'https://relay.browser-check'; // the relay's RELAY_AUDIENCE (mkOptions below)
        const signed = async (
          key,
          keyId,
          path,
          bodyText,
          nowMs = Date.now(),
          method = 'POST',
          overrideAud = null,
          jti = null,
        ) => {
          const r = await zs.signRelayRequest({
            privateKey: key,
            keyId,
            method,
            path,
            body: enc.encode(bodyText),
            nowMs,
            audience: overrideAud ?? AUD,
            ...(jti ? { jti } : {}),
          });
          if (!r.ok) throw new Error('sign ' + r.reason);
          return r.value;
        };
        const post = async (base, id, bodyText, head, extraHeaders = {}) =>
          fetch(`${base}/v1/stamp/${id}`, {
            method: 'POST',
            body: bodyText,
            headers: {
              'Content-Type': 'application/json',
              ...(head ? { 'X-Zeitstempel-Auth': head } : {}),
              ...extraHeaders,
            },
          });
        const stamp = async (base, key, keyId, hash, extra = {}, overrides = {}) => {
          const path = `/v1/stamp/${overrides.id ?? 'freetsa'}`;
          const bodyText = JSON.stringify({ hash: zs.toBase64Url(hash), ...extra });
          const head = await signed(
            key,
            keyId,
            path,
            overrides.signedBody ?? bodyText,
            overrides.nowMs ?? Date.now(),
          );
          return post(base, overrides.id ?? 'freetsa', bodyText, head);
        };
        const jsonOf = async (r) => {
          try {
            return await r.json();
          } catch {
            return null;
          }
        };

        // (a) signature accepted / wrong signature refused (single operation relay B2)
        const h0 = await sha('a-1');
        let r = await stamp(B2, pk('a'), 'app-a', h0);
        let j = await jsonOf(r);
        add(
          'a1 pkcs8 key signed in browser -> relay 200',
          r.status === 200 && !!j?.token,
          `${r.status} ${j?.error ?? ''} Date=${r.headers.get('Date')}`,
        );
        const v = j?.token
          ? await zs.verifyTimestampToken(zs.fromBase64Url(j.token), h0, [trust])
          : null;
        add(
          'a1b token of that answer verifies in browser against stub CA',
          !!v?.ok,
          v ? (v.ok ? (v.value.signer ?? '') : v.reason) : 'no token',
        );
        // CryptoKey non-extractable
        const ck = window.K.c.privateKey;
        r = await stamp(B2, ck, 'app-c', await sha('a-2'));
        j = await jsonOf(r);
        add(
          'a2 non-extractable CryptoKey signs -> 200',
          r.status === 200,
          `${r.status} ${j?.error ?? ''}`,
        );
        add(
          'a2b extractable:false really (exportKey fails)',
          await crypto.subtle.exportKey('pkcs8', ck).then(
            () => false,
            () => true,
          ),
        );
        // wrong signatures
        const path = '/v1/stamp/freetsa';
        const body = JSON.stringify({ hash: zs.toBase64Url(await sha('a-3')) });
        const good = await signed(pk('a'), 'app-a', path, body);
        const parts = good.split('.');
        const flip = (s) => s.slice(0, 5) + (s[5] === 'A' ? 'B' : 'A') + s.slice(6);
        const cases = {
          'flipped signature char': [parts[0], parts[1], parts[2], parts[3], flip(parts[4])].join(
            '.',
          ),
          'other audience': await signed(
            pk('a'),
            'app-a',
            path,
            body,
            Date.now(),
            'POST',
            'https://relay.elsewhere',
          ),
          'jti changed after signing': [
            parts[0],
            parts[1],
            parts[2],
            zs.toBase64Url(crypto.getRandomValues(new Uint8Array(16))),
            parts[4],
          ].join('.'),
          'version 2 head (seconds, no jti)': `v2.app-a.${Math.floor(Date.now() / 1000)}.${parts[4]}`,
          'other key (d, unknown to relay) under kid app-a': await signed(
            pk('d'),
            'app-a',
            path,
            body,
          ),
          'key of app-b under kid app-a': await signed(pk('b'), 'app-a', path, body),
          'signed other path': await signed(pk('a'), 'app-a', '/v1/stamp/sectigo', body),
          'signed other body': await signed(pk('a'), 'app-a', path, body + ' '),
          'unknown kid': await signed(pk('a'), 'app-zz', path, body),
          'ts 5 min in the past': await signed(pk('a'), 'app-a', path, body, Date.now() - 300000),
          'ts 5 min in the future': await signed(pk('a'), 'app-a', path, body, Date.now() + 300000),
        };
        for (const [n, head] of Object.entries(cases)) {
          const rr = await post(B2, 'freetsa', body, head);
          add(
            `a3 ${n} -> 401`,
            rr.status === 401,
            `${rr.status} ${JSON.stringify(await jsonOf(rr))}`,
          );
        }
        const none = await post(B2, 'freetsa', body, null);
        add('a3 no header -> 401', none.status === 401, String(none.status));
        // 401 from clock skew: read Date, correct once
        const skewHead = await signed(pk('a'), 'app-a', path, body, Date.now() - 300000);
        const rr = await post(B2, 'freetsa', body, skewHead);
        const dateHdr = rr.headers.get('Date');
        add('a4 Date readable on 401', rr.status === 401 && !!dateHdr, `${rr.status} ${dateHdr}`);
        if (dateHdr) {
          const off = Date.parse(dateHdr) - Date.now();
          const retry = await post(
            B2,
            'freetsa',
            body,
            await signed(pk('a'), 'app-a', path, body, Date.now() + off),
          );
          add(
            'a4b one correction with Date -> not 401',
            retry.status !== 401,
            `${retry.status} ${(await jsonOf(retry))?.error ?? ''}`,
          );
        }
        // replay of the same head (the jti makes every head its own request: no waiting for another second)
        const rbody = JSON.stringify({ hash: zs.toBase64Url(await sha('a-replay')) });
        const rh = await signed(pk('a'), 'app-a', path, rbody);
        const r1 = await post(B2, 'freetsa', rbody, rh);
        const r2 = await post(B2, 'freetsa', rbody, rh);
        add(
          'a5 same head twice: 2nd refused',
          r1.status === 200 && r2.status === 401,
          `${r1.status} ${r2.status}`,
        );
        // same key, same body, same millisecond, two jti: two requests, neither is refused as a replay (B3)
        const tNow = Date.now();
        const sameBody = JSON.stringify({ hash: zs.toBase64Url(await sha('a-two-jti')) });
        const t1 = await post(
          B2,
          'freetsa',
          sameBody,
          await signed(pk('a'), 'app-a', path, sameBody, tNow),
        );
        const t2 = await post(
          B2,
          'freetsa',
          sameBody,
          await signed(pk('a'), 'app-a', path, sameBody, tNow),
        );
        add(
          'a5b same key, body and millisecond with two jti: neither is 401',
          t1.status !== 401 && t2.status !== 401,
          `${t1.status} ${t2.status}`,
        );
        // the jti is 16 random bytes, 22 characters, new for every head
        const j1 = (await signed(pk('a'), 'app-a', path, sameBody, tNow)).split('.');
        const j2 = (await signed(pk('a'), 'app-a', path, sameBody, tNow)).split('.');
        add(
          'a5c head is v3.<kid>.<ts ms>.<jti 22>.<sig 86>, jti differs per call',
          j1[0] === 'v3' &&
            /^[0-9]{13}$/.test(j1[2]) &&
            j1[3].length === 22 &&
            j1[4].length === 86 &&
            j1[3] !== j2[3],
          j1.slice(0, 4).join('.'),
        );

        // (b) CORS
        const exp = await post(B2, 'freetsa', body, await signed(pk('a'), 'app-a', path, body));
        add(
          'b1 headers readable: Date',
          !!exp.headers.get('Date'),
          String(exp.headers.get('Date')),
        );
        // Retry-After on 429: burn budget
        let last = null;
        const seen = [];
        for (let i = 0; i < 8; i++) {
          const hh = await sha('burn' + i);
          const x = await stamp(B2, pk('a'), 'app-a', hh);
          seen.push(x.status);
          if (x.status !== 200) {
            last = x;
            break;
          }
        }
        add(
          'b2 Retry-After readable on 429',
          last?.status === 429 && Number(last.headers.get('Retry-After')) > 0,
          `statuses=${seen} RA=${last?.headers.get('Retry-After')}`,
        );
        // octet-stream raw body, header allowed
        const raw = await sha('raw-body');
        const rawPath = '/v1/stamp/sectigo';
        const rawHead = await zs.signRelayRequest({
          privateKey: pk('a'),
          keyId: 'app-a',
          method: 'POST',
          path: rawPath,
          body: raw,
          nowMs: Date.now(),
          audience: AUD,
        });
        const rr2 = await fetch(B2 + rawPath, {
          method: 'POST',
          body: raw,
          headers: {
            'Content-Type': 'application/octet-stream',
            'X-Zeitstempel-Auth': rawHead.value,
          },
        });
        add(
          'b3 octet-stream body signed in browser',
          rr2.status === 200 || rr2.status === 429,
          String(rr2.status),
        );
        // plain preflight for a disallowed header
        const bad = await fetch(B2 + path, {
          method: 'POST',
          body,
          headers: { 'Content-Type': 'application/json', 'X-Evil': '1' },
        }).then(
          (x) => 'resp ' + x.status,
          () => 'TypeError',
        );
        add(
          'b4 header not on the allow list: browser blocks at preflight',
          bad === 'TypeError',
          bad,
        );

        // (c) collecting operation: parallel requests
        const hs = await Promise.all(Array.from({ length: 6 }, (_, i) => sha('batch-' + i)));
        const keyOf = [pk('a'), pk('a'), ck, pk('a'), ck, pk('b')];
        const idOf = ['app-a', 'app-a', 'app-c', 'app-a', 'app-c', 'app-b'];
        const answers = await Promise.all(hs.map((h, i) => stamp(B1, keyOf[i], idOf[i], h)));
        const bodies = await Promise.all(answers.map(jsonOf));
        add(
          'c1 six parallel requests all 200',
          answers.every((a) => a.status === 200),
          answers.map((a) => a.status).join(','),
        );
        const cres = [];
        for (let i = 0; i < 6; i++) {
          const b = bodies[i];
          if (!b?.batch) {
            cres.push('nobatch');
            continue;
          }
          const vr = await zs.verifyBatchedTimestamp(
            { token: zs.fromBase64Url(b.token), hash: hs[i], batch: b.batch },
            [trust],
            { minGenTime: new Date(Date.now() - 60000) },
          );
          cres.push(
            vr.ok
              ? {
                  size: vr.value.batch.size,
                  index: vr.value.batch.index,
                  genTime: vr.value.genTime,
                }
              : vr.reason,
          );
        }
        add(
          'c2 verifyBatchedTimestamp in browser ok for all',
          cres.every((x) => typeof x === 'object'),
          JSON.stringify(cres),
        );
        add(
          'c3 one token for all, indices distinct',
          new Set(bodies.map((b) => b?.token)).size === 1 &&
            new Set(bodies.map((b) => b?.batch?.index)).size === bodies.length,
          `size=${bodies[0]?.batch?.size}`,
        );
        const wrongH = await zs.verifyBatchedTimestamp(
          { token: zs.fromBase64Url(bodies[0].token), hash: hs[1], batch: bodies[0].batch },
          [trust],
        );
        add('c4 receipt with other hash refused', !wrongH.ok, wrongH.ok ? '' : wrongH.reason);
        const wrongA = await zs.verifyBatchedTimestamp(
          { token: zs.fromBase64Url(bodies[0].token), hash: hs[0], batch: bodies[0].batch },
          [window.__other],
        );
        add(
          'c5 receipt with other anchor refused (no throw)',
          !wrongA.ok,
          wrongA.ok ? '' : wrongA.reason,
        );
        window.__batch = bodies.map((b, i) => ({ b, h: Array.from(hs[i]) }));

        // (d) solo
        await new Promise((x) => setTimeout(x, 1200));
        const sh = await sha('solo-1');
        const sr = await stamp(B1, pk('b'), 'app-b', sh, { mode: 'solo' });
        const sj = await jsonOf(sr);
        add(
          'd1 type-2 key mode solo -> 200, no batch field',
          sr.status === 200 && sj && !('batch' in sj),
          `${sr.status} ${sj?.error ?? ''} keys=${sj ? Object.keys(sj) : ''}`,
        );
        if (sj?.token) {
          const sv = await zs.verifyTimestampToken(zs.fromBase64Url(sj.token), sh, [trust], {
            minGenTime: new Date(Date.now() - 60000),
          });
          add(
            'd2 solo token verifies over the hash itself (plain verify)',
            sv.ok,
            sv.ok ? sv.value.genTime : sv.reason,
          );
          const sbat = await zs.verifyBatchedTimestamp(
            {
              token: zs.fromBase64Url(sj.token),
              hash: sh,
              batch: {
                v: 1,
                size: 1,
                index: 0,
                salt: zs.toBase64Url(new Uint8Array(32)),
                path: [],
              },
            },
            [trust],
          );
          add(
            'd2b solo token must not verify as batch',
            !sbat.ok,
            sbat.ok ? 'ACCEPTED' : sbat.reason,
          );
        }
        await new Promise((x) => setTimeout(x, 1200));
        // type 1 with solo while another waits -> 403: open a window with a normal request, then ask solo
        const wait1 = stamp(B1, pk('a'), 'app-a', await sha('w-1'));
        await new Promise((x) => setTimeout(x, 60));
        const denied = await stamp(B1, pk('a'), 'app-a', await sha('solo-denied'), {
          mode: 'solo',
        });
        add(
          'd3 type-1 solo while window waits -> 403 solo-not-allowed',
          denied.status === 403 && (await jsonOf(denied))?.error === 'solo-not-allowed',
          String(denied.status),
        );
        await wait1;
        // mode added after signing
        await new Promise((x) => setTimeout(x, 1200));
        const hb = await sha('solo-edit');
        const plainBody = JSON.stringify({ hash: zs.toBase64Url(hb) });
        const headPlain = await signed(pk('b'), 'app-b', path, plainBody);
        const edited = await post(
          B1,
          'freetsa',
          JSON.stringify({ hash: zs.toBase64Url(hb), mode: 'solo' }),
          headPlain,
        );
        add('d4 mode added after signing -> 401', edited.status === 401, String(edited.status));
        const bm = await stamp(B1, pk('b'), 'app-b', hb, { mode: 'nope' });
        add(
          'd5 unknown mode -> 400 bad-mode (signed)',
          bm.status === 400 && (await jsonOf(bm))?.error === 'bad-mode',
          String(bm.status),
        );
        return out;
      },
      { keys, B1, B2, trust },
    );
    for (const r of res) rec(r.name, r.pass, r.detail);

    // the same batch receipts in Node: browser and Node must agree
    const batch = await p.evaluate(() => window.__batch);
    const minGenTime = new Date(Date.now() - 120000);
    const nodeVals = [];
    for (const { b, h } of batch) {
      const v = await nodeLib.verifyBatchedTimestamp(
        { token: nodeLib.fromBase64Url(b.token), hash: Uint8Array.from(h), batch: b.batch },
        [trust],
        { minGenTime },
      );
      nodeVals.push(JSON.stringify(v, json));
    }
    rec(
      'c6 same batch receipts verify in Node too',
      nodeVals.every((s) => JSON.parse(s).ok === true),
      '',
    );
    const browserVals = await p.evaluate(
      async ({ trust, minGenTime }) => {
        const zs = window.zs;
        return Promise.all(
          window.__batch.map(async ({ b, h }) => {
            const v = await zs.verifyBatchedTimestamp(
              { token: zs.fromBase64Url(b.token), hash: Uint8Array.from(h), batch: b.batch },
              [trust],
              { minGenTime: new Date(minGenTime) },
            );
            return JSON.stringify(v, (k, x) => (x instanceof Uint8Array ? Array.from(x) : x));
          }),
        );
      },
      { trust, minGenTime: minGenTime.getTime() },
    );
    const same = browserVals.every((s, i) => s === nodeVals[i]);
    rec(
      'c7 browser and node result objects identical (JSON)',
      same,
      same ? '' : `${browserVals[0].slice(0, 300)} VS ${nodeVals[0].slice(0, 300)}`,
    );

    // preflight evidence
    const pf = preflights.filter((x) => x.m === 'OPTIONS' && !/x-evil/.test(x.acrh ?? ''));
    rec(
      'b5 preflights seen by relay, ask for x-zeitstempel-auth',
      pf.length > 0 &&
        pf.every(
          (x) => /x-zeitstempel-auth/.test(x.acrh ?? '') && /content-type/.test(x.acrh ?? ''),
        ),
      `${pf.length} OPTIONS, sample ${JSON.stringify(pf[0])}`,
    );
    rec(
      'b5b the b4 preflight (x-evil) reached the relay',
      preflights.some((x) => /x-evil/.test(x.acrh ?? '')),
      '',
    );

    // foreign origin
    const p2 = await ctx.newPage();
    await p2.goto(`${origin2}/`);
    await p2.evaluate(async () => {
      window.zs = await import('/dist/index.js');
    });
    const foreign = await p2.evaluate(
      async ({ B2, k }) => {
        const zs = window.zs;
        const enc = new TextEncoder();
        const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode('x')));
        const bodyText = JSON.stringify({ hash: zs.toBase64Url(hash) });
        const s = await zs.signRelayRequest({
          privateKey: Uint8Array.from(k),
          keyId: 'app-a',
          method: 'POST',
          path: '/v1/stamp/freetsa',
          body: enc.encode(bodyText),
          nowMs: Date.now(),
          audience: 'https://relay.browser-check',
        });
        return fetch(B2 + '/v1/stamp/freetsa', {
          method: 'POST',
          body: bodyText,
          headers: { 'Content-Type': 'application/json', 'X-Zeitstempel-Auth': s.value },
        }).then(
          (r) => 'resp ' + r.status,
          () => 'TypeError',
        );
      },
      { B2, k: keys.a.pk },
    );
    rec(
      'b7 foreign origin: browser blocks the call (no CORS grant)',
      foreign === 'TypeError',
      foreign,
    );

    // insecure context (plain http, not localhost): Chromium only (a host-resolver rule makes the name)
    if (engine === 'chromium') {
      const brow2 = await launcher.launch({
        args: ['--host-resolver-rules=MAP zs.test 127.0.0.1'],
      });
      try {
        const p3 = await brow2.newPage();
        await p3.goto(`http://zs.test:${page1.address().port}/`);
        await p3.evaluate(async () => {
          window.zs = await import('/dist/index.js');
        });
        const ins = await p3.evaluate(
          async ({ k }) => {
            const zs = window.zs;
            const r = await zs.signRelayRequest({
              privateKey: Uint8Array.from(k),
              keyId: 'app-a',
              method: 'POST',
              path: '/v1/stamp/freetsa',
              body: new Uint8Array(32),
              nowMs: Date.now(),
              audience: 'https://relay.browser-check',
            });
            return { secure: isSecureContext, subtle: typeof crypto.subtle, r };
          },
          { k: keys.a.pk },
        );
        rec(
          'b8 insecure context (http, non-localhost): signRelayRequest answers unsupported-signature, no throw',
          ins.secure === false &&
            ins.subtle === 'undefined' &&
            !ins.r.ok &&
            ins.r.reason === 'unsupported-signature',
          JSON.stringify(ins),
        );
      } finally {
        await brow2.close();
      }
    } else console.log(`[${engine}] b8 insecure context: skipped (Chromium only)`);

    // (e) the four recorded fixtures: browser against Node
    const fixBrowser = await p.evaluate(
      async ({ cases, anchors }) => {
        const zs = window.zs;
        const dec = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
        const hash = new Uint8Array(
          await crypto.subtle.digest('SHA-256', new TextEncoder().encode('probe')),
        );
        const o = [];
        for (const c of cases) {
          const r = zs.readTimestampResponse(dec(c.tsr));
          const v = await zs.verifyTimestampToken(r.value.token, hash, [anchors[c.anchor]]);
          const w = await zs.verifyTimestampToken(r.value.token, new Uint8Array(32), [
            anchors[c.anchor],
          ]);
          const e = await zs.verifyTimestampToken(r.value.token, hash, [anchors[c.otherAnchor]]);
          let accepted = 0;
          const bytes = r.value.token;
          for (let i = 0; i < bytes.length; i += 97) {
            const cp = bytes.slice();
            cp[i] ^= 1;
            const t = await zs.verifyTimestampToken(cp, hash, [anchors[c.anchor]]);
            if (t.ok) accepted++;
          }
          o.push({
            name: c.name,
            v: JSON.stringify(v, (k, x) => (x instanceof Uint8Array ? Array.from(x) : x)),
            w: w.reason,
            e: e.reason,
            accepted,
          });
        }
        return o;
      },
      { cases: CASES, anchors: ANCHORS },
    );
    const hashN = new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode('probe')),
    );
    for (const c of CASES) {
      const bres = fixBrowser.find((x) => x.name === c.name);
      const rn = nodeLib.readTimestampResponse(new Uint8Array(Buffer.from(c.tsr, 'base64')));
      const vn = await nodeLib.verifyTimestampToken(rn.value.token, hashN, [ANCHORS[c.anchor]]);
      const wn = await nodeLib.verifyTimestampToken(rn.value.token, new Uint8Array(32), [
        ANCHORS[c.anchor],
      ]);
      const en = await nodeLib.verifyTimestampToken(rn.value.token, hashN, [
        ANCHORS[c.otherAnchor],
      ]);
      let nacc = 0;
      for (let i = 0; i < rn.value.token.length; i += 97) {
        const cp = rn.value.token.slice();
        cp[i] ^= 1;
        if ((await nodeLib.verifyTimestampToken(cp, hashN, [ANCHORS[c.anchor]])).ok) nacc++;
      }
      const nodeV = JSON.stringify(vn, json);
      const okB = JSON.parse(bres.v).ok === true;
      rec(
        `e ${c.name}: browser verifies, wrong hash=${bres.w}, wrong anchor=${bres.e}, accepted bit flips=${bres.accepted}`,
        okB &&
          bres.w === 'imprint-mismatch' &&
          bres.e === 'untrusted-chain' &&
          bres.accepted === nacc,
        `accepted flips browser=${bres.accepted} node=${nacc} (the flips inside the anchor's own copy are accepted by design)`,
      );
      rec(
        `e ${c.name}: browser == node (result JSON, wrong hash, wrong anchor)`,
        nodeV === bres.v && wn.reason === bres.w && en.reason === bres.e,
        nodeV === bres.v ? '' : `node=${nodeV.slice(0, 200)} browser=${bres.v.slice(0, 200)}`,
      );
    }
    rec('page errors', pageErrors.length === 0, pageErrors.join(' | '));
  } finally {
    for (const s of relays) {
      s.closeAllConnections();
      s.close();
    }
    page1.close();
    page2.close();
  }
}

// Part C: the client `zeitstempel/client` in the browser (dist/client), against real relays with a stub service.
// The page is served from 127.0.0.1:<port> and the relays listen on other ports of 127.0.0.1: another ORIGIN
// (CORS with preflight applies) but the same SITE, so a cookie of the page WOULD be sent with
// `credentials: 'include'` (the control request below proves that, so "no cookie" means something).
async function partC(engine, browser) {
  const rec = (name, pass, detail) => record(engine, `C ${name}`, pass, detail);
  const clientLib = await import(`${R}dist/client/index.js`);
  const page = pageServer();
  await listen(page);
  const pageOrigin = `http://127.0.0.1:${page.address().port}`;
  const AUDC = 'https://relay.browser-check-client';
  const log = []; // every request any relay of this part saw
  const relays = [];
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  try {
    const ctx = await browser.newContext();
    const p = await ctx.newPage();
    const pageErrors = [];
    p.on('pageerror', (e) => pageErrors.push(String(e)));
    await p.goto(`${pageOrigin}/`);
    await p.evaluate(async () => {
      window.zs = await import('/dist/index.js');
      window.zc = await import('/dist/client/index.js');
      window.__real = Date.now.bind(Date);
      document.cookie = 'zs_probe=secret; path=/';
    });
    await p.evaluate((a) => {
      window.__anchor = a;
    }, ANCHORS.freetsa);
    // keys made in the browser: a (bytes), b (type 2, bytes), c (non-extractable CryptoKey)
    const keys = await p.evaluate(async () => {
      window.K = {};
      window.PK = {};
      const res = {};
      for (const [n, ex] of [
        ['a', true],
        ['b', true],
        ['c', false],
      ]) {
        const k = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, ex, [
          'sign',
          'verify',
        ]);
        window.K[n] = k;
        if (ex)
          window.PK[n] = Array.from(
            new Uint8Array(await crypto.subtle.exportKey('pkcs8', k.privateKey)),
          );
        res[n] = Array.from(new Uint8Array(await crypto.subtle.exportKey('raw', k.publicKey)));
      }
      return res;
    });
    await p.evaluate(
      ({ trust, aud }) => {
        window.TRUST = trust;
        window.mk = async (B, who, extra = {}) => {
          let privateKey;
          let keyId = 'app-' + who[0];
          if (who === 'a' || who === 'b') privateKey = Uint8Array.from(window.PK[who]);
          else if (who === 'c') privateKey = window.K.c.privateKey;
          else if (who === 'a-import') {
            privateKey = await crypto.subtle.importKey(
              'pkcs8',
              Uint8Array.from(window.PK.a),
              { name: 'ECDSA', namedCurve: 'P-256' },
              false,
              ['sign'],
            );
          }
          const c = window.zc.createRelayClient({
            relayUrl: B,
            audience: aud,
            keyId,
            privateKey,
            trust: [window.TRUST],
            services: ['freetsa'],
            ...extra,
          });
          if (!c.ok) throw new Error('client ' + c.reason);
          return c.value;
        };
        window.hashOf = async (s) =>
          new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)));
        window.setOffset = (ms) => {
          Date.now = () => window.__real() + ms;
        };
      },
      { trust: SIGNER.caPem, aud: AUDC },
    );
    const relayKeys = [
      { id: 'app-a', publicKey: Uint8Array.from(keys.a) },
      { id: 'app-b', publicKey: Uint8Array.from(keys.b), solo: true },
      { id: 'app-c', publicKey: Uint8Array.from(keys.c) },
    ];
    const make = (name, minIntervalMs, up, extra = {}) => {
      const { server } = createRelayServer({
        services: SERVICES.map((s) => ({
          ...s,
          anchorPems: [...s.anchorPems, SIGNER.caPem],
          minIntervalMs,
        })),
        origins: [pageOrigin],
        allowPlainHttp: false,
        upstream: up,
        random: (n) => new Uint8Array(randomBytes(n)),
        now: () => Date.now(),
        keys: relayKeys,
        audience: AUDC,
        ...extra,
      });
      server.prependListener('request', (q, r) => {
        const e = {
          relay: name,
          m: q.method,
          url: q.url,
          origin: q.headers.origin,
          cookie: q.headers.cookie,
          authz: q.headers.authorization,
          hasAuth: q.headers['x-zeitstempel-auth'] !== undefined,
          status: null,
        };
        log.push(e);
        r.on('finish', () => {
          e.status = r.statusCode;
        });
      });
      relays.push(server);
      return server;
    };
    const down = new Set(); // services the failover relay's stub refuses
    const slowUp = async (t, body) => {
      await sleep(4000);
      return upstream(t, body);
    };
    const failUp = async (t, body) =>
      down.has(t.id)
        ? { status: 500, contentType: 'text/plain', body: new Uint8Array(0) }
        : upstream(t, body);
    const rs = make('single', 300, upstream, { maxWaitMs: 5000 });
    const rb = make('batch', 250, upstream, {
      maxWaitMs: 5000,
      batch: { windowMs: 300, max: 100 },
    });
    const rl = make('limit', 4000, upstream, { maxWaitMs: 1000 });
    const ra = make('slow', 300, slowUp, { maxWaitMs: 5000 });
    const rf = make('failover', 300, failUp, { maxWaitMs: 5000 });
    for (const s of [rs, rb, rl, ra, rf]) await listen(s);
    const U = (s) => `http://127.0.0.1:${s.address().port}`;
    const BS = U(rs),
      BB = U(rb),
      BL = U(rl),
      BA = U(ra),
      BF = U(rf);
    const seen = async (relay, from) => {
      await sleep(80);
      return log.slice(from).filter((e) => e.relay === relay && e.m === 'POST');
    };
    const mark = () => log.length;
    const trust = SIGNER.caPem;
    const nodeVerify = async (text, hash) =>
      clientLib.verifyEvidence(text, Uint8Array.from(hash), { trust: [trust] });

    // --- single operation: stamp, evidence, round trip, wrong hash ---
    const one = await p
      .evaluate(async (B) => {
        const c = await window.mk(B, 'a');
        const h = await window.hashOf('client-1');
        const r = await c.stamp(h);
        const out = { r, h: Array.from(h) };
        if (r.ok) {
          const zc = window.zc;
          out.v = await zc.verifyEvidence(r.value, h, { trust: [window.TRUST] });
          const t1 = zc.serializeEvidence(r.value);
          const back = t1.ok ? zc.readEvidence(t1.value) : null;
          const t2 = back?.ok ? zc.serializeEvidence(back.value) : null;
          out.text = t1.ok ? t1.value : null;
          out.round = !!(
            back?.ok &&
            t2?.ok &&
            t2.value === t1.value &&
            JSON.stringify(back.value) === JSON.stringify(r.value)
          );
          out.fromText = t1.ok
            ? await zc.verifyEvidence(t1.value, h, { trust: [window.TRUST] })
            : null;
          out.wrong = await zc.verifyEvidence(r.value, await window.hashOf('other'), {
            trust: [window.TRUST],
          });
          out.badAnchor = await zc.verifyEvidence(r.value, h, { trust: [window.__anchor] });
          const flip = {
            ...r.value,
            token:
              r.value.token.slice(0, 40) +
              (r.value.token[40] === 'A' ? 'B' : 'A') +
              r.value.token.slice(41),
          };
          out.tampered = await zc.verifyEvidence(flip, h, { trust: [window.TRUST] });
        }
        return out;
      }, BS)
      .catch((e) => ({ err: String(e) }));
    rec(
      '1 stamp single operation (key as bytes): evidence, kind single',
      !!one.r?.ok &&
        one.r.value.kind === 'single' &&
        one.r.value.service === 'freetsa' &&
        !('batch' in one.r.value),
      JSON.stringify(one.r?.ok ? { kind: one.r.value.kind, genTime: one.r.value.genTime } : one),
    );
    rec(
      '2 verifyEvidence in the browser ok, genTime as in the evidence',
      !!one.v?.ok && one.v.value.genTime === one.r.value.genTime,
      one.v?.ok ? one.v.value.genTime : one.v?.reason,
    );
    rec(
      '3 serializeEvidence/readEvidence round trip, same text, verifies from text',
      one.round === true && !!one.fromText?.ok,
      '',
    );
    rec(
      '4 evidence from the browser verifies in Node too (same genTime)',
      await (async () => {
        const v = await nodeVerify(one.text, one.h);
        return v.ok && v.value.genTime === one.v.value.genTime;
      })(),
      '',
    );
    rec(
      '5 wrong hash -> evidence-hash-mismatch',
      one.wrong?.ok === false && one.wrong.reason === 'evidence-hash-mismatch',
      one.wrong?.reason,
    );
    rec(
      '6 changed token refused, other anchor refused (untrusted-chain)',
      one.tampered?.ok === false &&
        one.badAnchor?.ok === false &&
        one.badAnchor.reason === 'untrusted-chain',
      `tampered=${one.tampered?.reason} anchor=${one.badAnchor?.reason}`,
    );

    // --- keys: non-extractable CryptoKey, key imported non-extractable from bytes ---
    for (const [who, label] of [
      ['c', 'CryptoKey generated non-extractable'],
      ['a-import', 'CryptoKey imported from PKCS#8 bytes, non-extractable'],
    ]) {
      const k = await p.evaluate(
        async ({ B, who }) => {
          const c = await window.mk(B, who);
          const h = await window.hashOf('key-' + who);
          const r = await c.stamp(h);
          const v = r.ok
            ? await window.zc.verifyEvidence(r.value, h, { trust: [window.TRUST] })
            : null;
          const key = who === 'c' ? window.K.c.privateKey : null;
          const ex = key
            ? await crypto.subtle.exportKey('pkcs8', key).then(
                () => 'extractable',
                () => 'locked',
              )
            : 'locked';
          return { r: r.ok ? 'ok' : r.reason, v: v?.ok === true, ex };
        },
        { B: BS, who },
      );
      rec(`7 stamp with a ${label}`, k.r === 'ok' && k.v && k.ex === 'locked', JSON.stringify(k));
    }

    // --- collecting operation and solo ---
    const bt = await p.evaluate(async (B) => {
      const c = await window.mk(B, 'a');
      const hs = await Promise.all([0, 1, 2].map((i) => window.hashOf('batch-' + i)));
      const rs = await Promise.all(hs.map((h) => c.stamp(h)));
      const vs = [];
      for (let i = 0; i < 3; i++)
        vs.push(
          rs[i].ok
            ? await window.zc.verifyEvidence(rs[i].value, hs[i], { trust: [window.TRUST] })
            : null,
        );
      const text = rs[0].ok ? window.zc.serializeEvidence(rs[0].value) : null;
      return {
        res: rs.map((r) =>
          r.ok
            ? {
                kind: r.value.kind,
                size: r.value.batch?.size,
                index: r.value.batch?.index,
                token: r.value.token,
              }
            : r,
        ),
        v: vs.map((v) => v?.ok === true),
        text: text?.ok ? text.value : null,
        h0: Array.from(hs[0]),
      };
    }, BB);
    rec(
      '8 stamp collecting operation: three batch evidences, one token, indices distinct, verifyEvidence ok',
      bt.res.every((r) => r.kind === 'batch') &&
        bt.v.every(Boolean) &&
        new Set(bt.res.map((r) => r.token)).size === 1 &&
        new Set(bt.res.map((r) => r.index)).size === 3,
      JSON.stringify(bt.res.map((r) => [r.kind, r.size, r.index])),
    );
    rec(
      '9 batch evidence verifies in Node too',
      bt.text !== null && (await nodeVerify(bt.text, bt.h0)).ok === true,
      '',
    );
    await sleep(600);
    const solo = await p.evaluate(async (B) => {
      const c = await window.mk(B, 'b');
      const h = await window.hashOf('solo-1');
      const r = await c.stamp(h, { mode: 'solo' });
      const v = r.ok ? await window.zc.verifyEvidence(r.value, h, { trust: [window.TRUST] }) : null;
      return {
        r: r.ok ? { kind: r.value.kind, hasBatch: 'batch' in r.value } : r,
        v: v?.ok === true,
      };
    }, BB);
    rec(
      '10 solo with a type 2 key: kind single, no batch, verifies',
      solo.r.kind === 'single' && solo.r.hasBatch === false && solo.v,
      JSON.stringify(solo),
    );
    const solo1 = await p.evaluate(async (B) => {
      const c = await window.mk(B, 'a');
      const r = await c.stamp(await window.hashOf('solo-denied'), { mode: 'solo' });
      return r.ok ? { ok: true } : { reason: r.reason, status: r.status, code: r.code };
    }, BB);
    rec(
      '11 solo with a type 1 key -> relay-error 403 solo-not-allowed (no batch evidence handed out)',
      solo1.reason === 'relay-error' && solo1.status === 403 && solo1.code === 'solo-not-allowed',
      JSON.stringify(solo1),
    );

    // --- clock correction by overriding Date.now in the page (relay window +-60 s, client limit 65 s) ---
    for (const off of [30000, -30000]) {
      const r = await p.evaluate(
        async ({ B, off }) => {
          window.setOffset(off);
          try {
            const c = await window.mk(B, 'a');
            const h = await window.hashOf('clock' + off);
            const r = await c.stamp(h);
            const v = r.ok
              ? await window.zc.verifyEvidence(r.value, h, { trust: [window.TRUST] })
              : null;
            return { ok: r.ok, reason: r.reason, v: v?.ok === true };
          } finally {
            window.setOffset(0);
          }
        },
        { B: BS, off },
      );
      rec(
        `12 app clock ${off / 1000 > 0 ? '+' : ''}${off / 1000} s: stamp ok, evidence verifies`,
        r.ok && r.v,
        JSON.stringify(r),
      );
    }
    for (const off of [62000, -62000]) {
      const m = mark();
      const r = await p.evaluate(
        async ({ B, off }) => {
          window.setOffset(off);
          try {
            const c = await window.mk(B, 'a');
            const r1 = await c.stamp(await window.hashOf('corr1' + off));
            return { ok: r1.ok, reason: r1.reason };
          } finally {
            window.setOffset(0);
          }
        },
        { B: BS, off },
      );
      const posts = await seen('single', m);
      const n401 = posts.filter((e) => e.status === 401).length;
      rec(
        `13 app clock ${off / 1000 > 0 ? '+' : ''}${off / 1000} s (outside the relay window, inside 65 s): one 401, corrected from Date, stamp ok`,
        r.ok && n401 === 1 && posts.length === 2,
        `${JSON.stringify(r)} statuses=${posts.map((e) => e.status)}`,
      );
    }
    {
      // the offset is remembered: the second stamp of the same client needs no 401
      const m = mark();
      const r = await p.evaluate(async (B) => {
        window.setOffset(62000);
        try {
          const c = await window.mk(B, 'a');
          const a = await c.stamp(await window.hashOf('rem1'));
          const b = await c.stamp(await window.hashOf('rem2'));
          return { a: a.ok, b: b.ok };
        } finally {
          window.setOffset(0);
        }
      }, BS);
      const posts = await seen('single', m);
      rec(
        '13b the corrected offset is remembered: two stamps, one 401 only',
        r.a && r.b && posts.length === 3 && posts.filter((e) => e.status === 401).length === 1,
        `statuses=${posts.map((e) => e.status)}`,
      );
    }
    for (const off of [70000, -70000]) {
      const m = mark();
      const r = await p.evaluate(
        async ({ B, off }) => {
          window.setOffset(off);
          try {
            const c = await window.mk(B, 'a');
            const r = await c.stamp(await window.hashOf('far' + off));
            return r.ok ? { ok: true } : { reason: r.reason, status: r.status };
          } finally {
            window.setOffset(0);
          }
        },
        { B: BS, off },
      );
      const posts = await seen('single', m);
      rec(
        `14 app clock ${off / 1000 > 0 ? '+' : ''}${off / 1000} s (beyond 65 s): relay-error 401, no endless loop (${posts.length} requests)`,
        r.reason === 'relay-error' && r.status === 401 && posts.length === 1,
        JSON.stringify(r),
      );
    }

    // --- Retry-After on 429 (relay `limit`: 4 s distance, waits at most 1 s) ---
    const lim1 = await p.evaluate(async (B) => {
      const c = await window.mk(B, 'a', { maxAttempts: 1 });
      const r1 = await c.stamp(await window.hashOf('lim-1'));
      const t = performance.now();
      const r2 = await c.stamp(await window.hashOf('lim-2'));
      return {
        r1: r1.ok,
        r2: r2.ok ? 'ok' : { reason: r2.reason, status: r2.status, code: r2.code },
        ms: Math.round(performance.now() - t),
      };
    }, BL);
    rec(
      '15 429 with maxAttempts 1: relay-error 429, answered at once',
      lim1.r1 && lim1.r2.reason === 'relay-error' && lim1.r2.status === 429 && lim1.ms < 1500,
      JSON.stringify(lim1),
    );
    const lim2 = await p.evaluate(async (B) => {
      const ac = new AbortController();
      const c = await window.mk(B, 'a', { maxAttempts: 3 });
      setTimeout(() => ac.abort(), 500);
      const t = performance.now();
      const r = await c.stamp(await window.hashOf('lim-3'), { signal: ac.signal });
      return { reason: r.ok ? 'ok' : r.reason, ms: Math.round(performance.now() - t) };
    }, BL);
    rec(
      '16 abort while waiting for Retry-After: aborted at once',
      lim2.reason === 'aborted' && lim2.ms < 2000,
      JSON.stringify(lim2),
    );
    const lim3 = await p.evaluate(async (B) => {
      const c = await window.mk(B, 'a', { maxAttempts: 3 });
      const h = await window.hashOf('lim-4');
      const t = performance.now();
      const r = await c.stamp(h);
      const v = r.ok ? await window.zc.verifyEvidence(r.value, h, { trust: [window.TRUST] }) : null;
      return {
        reason: r.ok ? 'ok' : r.reason,
        v: v?.ok === true,
        ms: Math.round(performance.now() - t),
      };
    }, BL);
    {
      const postsL = log.filter((e) => e.relay === 'limit' && e.m === 'POST');
      const n429 = postsL.filter((e) => e.status === 429).length;
      rec(
        '17 429 waits Retry-After and sends again: ok after the wait, evidence verifies',
        lim3.reason === 'ok' && lim3.v && lim3.ms >= 300 && n429 >= 3,
        `${JSON.stringify(lim3)} 429s=${n429}`,
      );
    }

    // --- abort during a slow answer; abort before sending ---
    const slow = await p.evaluate(async (B) => {
      const ac = new AbortController();
      const c = await window.mk(B, 'a');
      setTimeout(() => ac.abort(), 400);
      const t = performance.now();
      const r = await c.stamp(await window.hashOf('slow-1'), { signal: ac.signal });
      return { reason: r.ok ? 'ok' : r.reason, ms: Math.round(performance.now() - t) };
    }, BA);
    rec(
      '18 AbortSignal during a slow answer: aborted at once',
      slow.reason === 'aborted' && slow.ms < 2000,
      JSON.stringify(slow),
    );
    {
      const m = mark();
      const pre = await p.evaluate(async (B) => {
        const ac = new AbortController();
        ac.abort();
        const c = await window.mk(B, 'a');
        const r = await c.stamp(await window.hashOf('pre'), { signal: ac.signal });
        return r.ok ? 'ok' : r.reason;
      }, BA);
      const posts = await seen('slow', m);
      rec(
        '19 signal already aborted: aborted, nothing sent',
        pre === 'aborted' && posts.length === 0,
        `${pre} requests=${posts.length}`,
      );
    }

    // --- failover between services of one relay: the first answers 502 ---
    down.add('freetsa');
    {
      const m = mark();
      const f = await p.evaluate(async (B) => {
        const c = await window.mk(B, 'a', { services: ['freetsa', 'sectigo'] });
        const h = await window.hashOf('failover');
        const r = await c.stamp(h);
        const v = r.ok
          ? await window.zc.verifyEvidence(r.value, h, { trust: [window.TRUST] })
          : null;
        return { r: r.ok ? { service: r.value.service } : { reason: r.reason }, v: v?.ok === true };
      }, BF);
      const posts = await seen('failover', m);
      rec(
        '20 failover: freetsa answers 502, sectigo stamps, evidence verifies',
        f.r.service === 'sectigo' &&
          f.v &&
          posts.map((e) => `${e.url.split('/').pop()}:${e.status}`).join(',') ===
            'freetsa:502,sectigo:200',
        `${JSON.stringify(f)} ${posts.map((e) => `${e.url.split('/').pop()}:${e.status}`)}`,
      );
      const only = await p.evaluate(async (B) => {
        const c = await window.mk(B, 'a', { services: ['freetsa', 'sectigo'] });
        const r = await c.stamp(await window.hashOf('failover-2'), { service: 'freetsa' });
        return r.ok ? { ok: true } : { reason: r.reason, status: r.status };
      }, BF);
      rec(
        '21 option service: no failover, relay-error 502',
        only.reason === 'relay-error' && only.status === 502,
        JSON.stringify(only),
      );
    }
    down.clear();

    // --- no cookies, no credentials; cross-origin with preflight ---
    const control = await p.evaluate(async (B) => {
      await fetch(B + '/v1/stamp/freetsa', { method: 'GET', credentials: 'include' }).catch(
        () => {},
      );
      return document.cookie;
    }, BS);
    await sleep(80);
    const ctl = log.filter((e) => e.m === 'GET' && e.url === '/v1/stamp/freetsa');
    rec(
      '22 control: a fetch with credentials include DOES carry the page cookie (same site, other origin)',
      control.includes('zs_probe') &&
        ctl.length === 1 &&
        /zs_probe=secret/.test(ctl[0].cookie ?? ''),
      `cookie sent=${ctl[0]?.cookie}`,
    );
    const posts = log.filter((e) => e.m === 'POST');
    rec(
      `23 none of the ${posts.length} stamp requests of the client carries a cookie or an Authorization header`,
      posts.length > 20 &&
        posts.every((e) => e.cookie === undefined && e.authz === undefined && e.hasAuth),
      `cookies=${posts.filter((e) => e.cookie !== undefined).length} authz=${posts.filter((e) => e.authz !== undefined).length}`,
    );
    const opts = log.filter((e) => e.m === 'OPTIONS');
    rec(
      '24 cross-origin: every call has the page origin, preflights were made',
      posts.every((e) => e.origin === pageOrigin) && opts.length > 0,
      `${opts.length} OPTIONS`,
    );
    rec('25 page errors', pageErrors.length === 0, pageErrors.join(' | '));
    await p.close();
  } finally {
    for (const s of relays) {
      s.closeAllConnections();
      s.close();
    }
    page.close();
  }
}

let ran = 0;
for (const engine of wanted) {
  const launcher = playwright[engine];
  let browser;
  try {
    browser = await launcher.launch();
  } catch (e) {
    const why = String(e?.message ?? e).split('\n')[0];
    if (engine === 'chromium' && wanted.length === 1)
      stop(`Chromium could not be started (${why}). Install it: npx playwright install chromium`);
    console.log(`[${engine}] skipped: not available (${why})`);
    continue;
  }
  ran += 1;
  try {
    await partA(engine, browser);
    await partB(engine, browser, launcher);
    await partC(engine, browser);
  } finally {
    await browser.close();
  }
}
if (ran === 0) stop('none of the requested browsers could be started.');
console.log(`\n${total} checks in ${ran} browser(s), ${failed} failed`);
process.exit(failed ? 1 : 0);
