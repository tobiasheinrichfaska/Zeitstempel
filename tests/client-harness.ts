import { createPublicKey, verify as nodeVerify, randomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { toBase64Url } from '../src/index.ts';
import type { RelayKey } from '../relay/keys.ts';
import { loadServices } from '../relay/load.ts';
import type { RelayOptions } from '../relay/relay.ts';
import { createRelayServer } from '../relay/server.ts';
import type { Upstream } from '../relay/upstream.ts';
import { children, integerBytes, octets, parseDer } from '../src/lib/der.ts';
import { TEST_AUDIENCE, authMessage, makeTestKey, type TestKey } from './auth-helpers.ts';
import { build, int, seq } from './token-builder.ts';

// Harness of the client tests: a real in-process relay with a stub service behind it, and a fake relay (a plain HTTP
// server) whose answers a test scripts. Tokens are made by the token builder under a CA of this run.

export const SIGNER = build();
export const TRUST = [SIGNER.caPem];
export { TEST_AUDIENCE };

const genTimeText = (ms: number) =>
  new Date(ms)
    .toISOString()
    .replace(/[-:T]/g, '')
    .replace(/\.\d+Z$/, 'Z');

/** A TimeStampToken (DER) for `imprint` with the given time. */
export function makeToken(imprint: Uint8Array, genTimeMs: number): Uint8Array {
  const made = build({
    keys: SIGNER.keys,
    hash: imprint,
    nonceBytes: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
    genTime: genTimeText(genTimeMs),
  });
  return made.token;
}

const imprintOf = (request: Uint8Array): Uint8Array =>
  octets(children(children(parseDer(request))[1]!)[1]!);

function replyFor(request: Uint8Array, nowMs: number): Uint8Array {
  const parts = children(parseDer(request));
  const made = build({
    keys: SIGNER.keys,
    hash: imprintOf(request),
    nonceBytes: integerBytes(parts[2]!),
    genTime: genTimeText(nowMs),
  });
  return seq(seq(int(0)), made.token);
}

export const KEY_1 = makeTestKey('app-one'); // type 1
export const KEY_2 = makeTestKey('app-two'); // type 2 (solo)
const relayKey = (k: TestKey, solo: boolean): RelayKey => ({
  id: k.id,
  publicKey: k.publicKey,
  ...(solo ? { solo: true } : {}),
});

export interface RealRelay {
  origin: string;
  /** Service calls the stub saw, by service url. */
  upstreamCalls: string[];
  close: () => Promise<void>;
}

/** A real relay (`createRelayServer`) on 127.0.0.1 with two services and a stub behind them. */
export async function startRelay(
  over: {
    batch?: { windowMs: number; max: number } | null;
    /** Answer of the stub per service url; default: a valid stamp. */
    failUrl?: (url: string) => boolean;
  } = {},
): Promise<RealRelay> {
  const upstreamCalls: string[] = [];
  const services = loadServices().filter((s) => s.id === 'freetsa' || s.id === 'sectigo');
  const stub: Upstream = async (target, body) => {
    upstreamCalls.push(target.url);
    if (over.failUrl?.(target.url)) {
      return { status: 500, contentType: 'text/plain', body: new Uint8Array() };
    }
    return {
      status: 200,
      contentType: 'application/timestamp-reply',
      body: replyFor(body, Date.now()),
    };
  };
  const batch = over.batch === undefined ? null : over.batch;
  const options: RelayOptions = {
    services: services.map((s) => ({
      ...s,
      minIntervalMs: 100,
      anchorPems: [...s.anchorPems, SIGNER.caPem],
    })),
    origins: ['https://app.example'],
    allowPlainHttp: false,
    upstream: stub,
    random: (n) => new Uint8Array(randomBytes(n)),
    now: () => Date.now(),
    keys: [relayKey(KEY_1, false), relayKey(KEY_2, true)],
    audience: TEST_AUDIENCE,
    ...(batch === null ? {} : { batch }),
  };
  const { server, relay } = createRelayServer(options);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return {
    origin: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    upstreamCalls,
    close: () =>
      new Promise((r) => {
        relay.close();
        server.closeAllConnections();
        server.close(() => r());
      }),
  };
}

export interface Seen {
  path: string;
  head: string;
  body: Uint8Array;
  contentType: string | undefined;
}
export interface Scripted {
  status: number;
  headers?: Record<string, string>;
  json?: unknown;
  text?: string;
  /** Wait before answering (ms). */
  delayMs?: number;
  /** Close the connection without an answer. */
  drop?: boolean;
}
export interface FakeRelay {
  origin: string;
  seen: Seen[];
  close: () => Promise<void>;
}

/** A fake relay: `answer(seen, n)` scripts the answer to the n-th request (0-based). */
export async function startFake(answer: (seen: Seen, n: number) => Scripted): Promise<FakeRelay> {
  const seen: Seen[] = [];
  const server: Server = createServer((req: IncomingMessage, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const entry: Seen = {
        path: req.url ?? '',
        head: String(req.headers['x-zeitstempel-auth'] ?? ''),
        body: new Uint8Array(Buffer.concat(chunks)),
        contentType: req.headers['content-type'],
      };
      const n = seen.length;
      seen.push(entry);
      const s = answer(entry, n);
      const send = () => {
        if (s.drop) {
          req.socket.destroy();
          return;
        }
        res.writeHead(s.status, {
          'Content-Type': 'application/json',
          ...(s.headers ?? {}),
        });
        res.end(s.text ?? JSON.stringify(s.json ?? { error: 'x' }));
      };
      if (s.delayMs) setTimeout(send, s.delayMs);
      else send();
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return {
    origin: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    seen,
    close: () =>
      new Promise((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
  };
}

/** The 200 body of a relay for `hash`, stamped at `genTimeMs`. */
export function okBody(service: string, hash: Uint8Array, genTimeMs: number) {
  return {
    service,
    genTime: new Date(genTimeMs).toISOString(),
    accuracyMs: null,
    serial: '01',
    token: toBase64Url(makeToken(hash, genTimeMs)),
  };
}

/** The hash a request body carries. */
export const hashOf = (seen: Seen): Uint8Array =>
  new Uint8Array(
    Buffer.from(
      (JSON.parse(new TextDecoder().decode(seen.body)) as { hash: string }).hash,
      'base64url',
    ),
  );

/** Parts of a head `v3.<kid>.<ts>.<jti>.<sig>`. */
export function headParts(head: string) {
  const [v, kid, ts, jti, sig] = head.split('.');
  return { v, kid: kid!, ts: Number(ts), jti: jti!, sig: sig! };
}

/** True when the head is a valid ECDSA signature of `key` over this request (checked with node:crypto). */
export function headVerifies(seen: Seen, key: TestKey, audience = TEST_AUDIENCE): boolean {
  const p = headParts(seen.head);
  const message = authMessage('POST', seen.path, p.ts, seen.body, p.jti, audience);
  return nodeVerify(
    'sha256',
    Buffer.from(message),
    { key: createPublicKey(key.object), dsaEncoding: 'ieee-p1363' },
    Buffer.from(p.sig, 'base64url'),
  );
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
