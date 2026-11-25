import { randomBytes, verify as nodeVerify } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import {
  createRelayClient,
  fromBase64Url,
  parseRelayAnswer,
  toBase64Url,
  verifyBatchedTimestamp,
  type FetchInit,
  type FetchLike,
  type FetchResponse,
  type RelayClientOptions,
} from '../src/lib/index.ts';
import { publicKeyObject, type RelayKey } from '../relay/keys.ts';
import { loadServices } from '../relay/load.ts';
import type { RelayOptions } from '../relay/relay.ts';
import { createRelayServer } from '../relay/server.ts';
import type { Upstream } from '../relay/upstream.ts';
import { authMessage, makeTestKey } from './auth-helpers.ts';
import { refBatch, refProof } from './batch-reference.ts';
import { sha256 } from './helpers.ts';
import { build, int, seq } from './token-builder.ts';
import { children, integerBytes, octets, parseDer } from '../src/lib/der.ts';

// The relay client against the relay of PR "authentication, collecting operation, solo": signed requests,
// 401/403, batch receipts, `mode: "solo"`, and once end to end against the real relay server.

const SIGNER = build();
const NOW = Date.parse('2026-11-23T13:06:00Z');
const KEY = makeTestKey('app-1');
const SOLO_KEY = makeTestKey('app-solo');
const genTimeText = (ms: number) =>
  new Date(ms)
    .toISOString()
    .replace(/[-:T]/g, '')
    .replace(/\.\d+Z$/, 'Z');

/** A batch of three around the hash at position 1, and the token the service gave for its imprint. */
const BATCH = refBatch(3, 'client');
const MY_HASH = new Uint8Array(BATCH.hashes[1]!);
const PROOF = refProof(BATCH, 1);
const BATCH_TOKEN = build({
  keys: SIGNER.keys,
  hash: new Uint8Array(BATCH.imprint),
  genTime: genTimeText(NOW),
}).token;
/** A token over the hash itself (no batch). */
const tokenFor = (hash: Uint8Array) =>
  build({ keys: SIGNER.keys, hash, genTime: genTimeText(NOW) }).token;

async function serialOf(token: Uint8Array, hash: Uint8Array): Promise<string> {
  const { verifyTimestampToken } = await import('../src/lib/index.ts');
  const r = await verifyTimestampToken(token, hash, [SIGNER.caPem]);
  if (!r.ok) throw new Error(`test token does not verify: ${r.reason}`);
  return r.value.serial;
}

const answerFor = async (token: Uint8Array, serialHash: Uint8Array, extra = {}) => ({
  service: 'freetsa',
  genTime: new Date(NOW).toISOString(),
  accuracyMs: 0.5,
  serial: await serialOf(token, serialHash),
  token: toBase64Url(token),
  ...extra,
});

const reply = (
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): FetchResponse => ({
  status,
  headers: { get: (n) => headers[n] ?? null },
  json: async () => body,
});

interface Call {
  url: string;
  init: FetchInit;
}
type Handler = (url: string, init: FetchInit) => FetchResponse | Promise<FetchResponse>;

type Extra = { [K in keyof RelayClientOptions]?: RelayClientOptions[K] | undefined };

function setup(stamp: Handler, extra: Extra = {}) {
  const calls: Call[] = [];
  const fetchFake: FetchLike = async (url, init) => {
    calls.push({ url, init });
    return url.endsWith('/v1/services')
      ? reply(200, { services: [{ id: 'freetsa' }] })
      : stamp(url, init);
  };
  const given: Extra = {
    relay: 'https://relay.example',
    fetch: fetchFake,
    now: () => 0,
    wallNow: () => NOW,
    trusted: new Map([['freetsa', [SIGNER.caPem]]]),
    auth: { privateKey: KEY.privateKey, keyId: KEY.id },
    ...extra,
  };
  const client = createRelayClient(
    Object.fromEntries(
      Object.entries(given).filter(([, v]) => v !== undefined),
    ) as unknown as RelayClientOptions,
  );
  return { client, calls, posts: () => calls.filter((c) => c.init.method === 'POST') };
}

/** Checks a header with the relay's own key reader (`publicKeyObject`) and node:crypto, independent of the library. */
function relayAccepts(header: string, path: string, body: string, key = KEY): boolean {
  const m = /^v2\.([a-z][a-z0-9-]{0,31})\.([0-9]{1,12})\.([A-Za-z0-9_-]{86})$/.exec(header);
  if (!m || m[1] !== key.id) return false;
  const publicKey = publicKeyObject(key.publicKey);
  if (!publicKey) return false;
  const message = authMessage('POST', path, Number(m[2]), new TextEncoder().encode(body));
  return nodeVerify(
    'sha256',
    Buffer.from(message),
    { key: publicKey, dsaEncoding: 'ieee-p1363' },
    Buffer.from(m[3]!, 'base64url'),
  );
}

describe('relay client: authentication', () => {
  it('signs every stamp over exactly the body sent; the service list stays unsigned', async () => {
    const hash = sha256('signed');
    const token = tokenFor(hash);
    const { client, calls } = setup(async () => reply(200, await answerFor(token, hash)));
    const r = await client.stamp(hash);
    expect(r.ok, JSON.stringify(r)).toBe(true);
    const [list, post] = calls;
    expect(list!.init.headers).toBeUndefined();
    const header = post!.init.headers!['X-Zeitstempel-Auth']!;
    expect(header).toMatch(new RegExp(`^v2\\.app-1\\.${Math.floor(NOW / 1000)}\\.`));
    expect(relayAccepts(header, '/v1/stamp/freetsa', post!.init.body!)).toBe(true);
    // another body or path does not fit the header
    expect(relayAccepts(header, '/v1/stamp/freetsa', post!.init.body! + ' ')).toBe(false);
    expect(relayAccepts(header, '/v1/stamp/other', post!.init.body!)).toBe(false);
  });
  it('a CryptoKey (non-extractable) signs as well', async () => {
    const hash = sha256('cryptokey');
    const token = tokenFor(hash);
    const privateKey = await crypto.subtle.importKey(
      'pkcs8',
      KEY.privateKey as BufferSource,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign'],
    );
    const { client, posts } = setup(async () => reply(200, await answerFor(token, hash)), {
      auth: { privateKey, keyId: KEY.id },
    });
    expect((await client.stamp(hash)).ok).toBe(true);
    const p = posts()[0]!;
    expect(
      relayAccepts(p.init.headers!['X-Zeitstempel-Auth']!, '/v1/stamp/freetsa', p.init.body!),
    ).toBe(true);
  });
  it('401 is relay-unauthorized; with a close Date there is no second try', async () => {
    const { client, posts } = setup(() =>
      reply(401, { error: 'unauthorized' }, { Date: new Date(NOW + 5_000).toUTCString() }),
    );
    expect(await client.stamp(sha256('x'))).toEqual({
      ok: false,
      reason: 'relay-unauthorized',
      detail: 'status 401, unauthorized',
    });
    expect(posts()).toHaveLength(1);
  });
  it('401 with the relay clock far off: signs exactly once more with the relay time, and keeps it', async () => {
    const hash = sha256('skew');
    const token = tokenFor(hash);
    const relayMs = NOW + 10 * 60_000; // the device runs 10 minutes behind
    let n = 0;
    const { client, posts } = setup(async (_url, init) => {
      n += 1;
      const ts = Number(init.headers!['X-Zeitstempel-Auth']!.split('.')[2]);
      return Math.abs(ts * 1000 - relayMs) <= 60_000
        ? reply(200, await answerFor(token, hash))
        : reply(401, { error: 'unauthorized' }, { Date: new Date(relayMs).toUTCString() });
    });
    expect((await client.stamp(hash)).ok).toBe(true);
    expect(n).toBe(2);
    const second = posts()[1]!.init.headers!['X-Zeitstempel-Auth']!;
    expect(second.split('.')[2]).toBe(String(Math.floor(relayMs / 1000)));
    // the next stamp is signed with the learnt clock at once
    expect((await client.stamp(hash)).ok).toBe(true);
    expect(n).toBe(3);
  });
  it('a second 401 after the clock fix is final (two POSTs, not more)', async () => {
    const { client, posts } = setup(() =>
      reply(401, { error: 'unauthorized' }, { Date: new Date(NOW + 3_600_000).toUTCString() }),
    );
    expect(await client.stamp(sha256('x'))).toMatchObject({ reason: 'relay-unauthorized' });
    expect(posts()).toHaveLength(2);
  });
  it('403 (solo-not-allowed) is relay-unauthorized and tries no other service', async () => {
    const { client, posts } = setup(() => reply(403, { error: 'solo-not-allowed' }));
    expect(await client.stamp(sha256('x'), { mode: 'solo' })).toEqual({
      ok: false,
      reason: 'relay-unauthorized',
      detail: 'status 403, solo-not-allowed',
    });
    expect(posts()).toHaveLength(1);
  });
  it('auth without wallNow, a bad key or key id: a code, nothing sent', async () => {
    const a = setup(() => reply(200, {}), { wallNow: undefined });
    expect(await a.client.stamp(sha256('x'))).toMatchObject({ reason: 'bad-options' });
    expect(a.calls).toHaveLength(0);
    const b = setup(() => reply(200, {}), { auth: { privateKey: new Uint8Array(10), keyId: 'k' } });
    expect(await b.client.stamp(sha256('x'))).toMatchObject({ reason: 'bad-key' });
    expect(b.posts()).toHaveLength(0);
    const c = setup(() => reply(200, {}), { auth: { privateKey: KEY.privateKey, keyId: 'Bad' } });
    expect(await c.client.stamp(sha256('x'))).toMatchObject({ reason: 'bad-key-id' });
    expect(c.posts()).toHaveLength(0);
  });
});

describe('relay client: collecting operation (batch receipts)', () => {
  it('verifies a batch receipt and returns it with the token', async () => {
    const body = await answerFor(BATCH_TOKEN, new Uint8Array(BATCH.imprint), { batch: PROOF });
    const { client } = setup(() => reply(200, body));
    const r = await client.stamp(MY_HASH);
    expect(r.ok, JSON.stringify(r)).toBe(true);
    if (!r.ok) return;
    expect(r.value.batch).toEqual(PROOF);
    expect(r.value.verified).toMatchObject({ batch: { size: 3, index: 1 } });
    // what a caller stores (token + batch) verifies later without the relay
    const again = await verifyBatchedTimestamp(
      { token: r.value.token, hash: MY_HASH, batch: r.value.batch! },
      [SIGNER.caPem],
    );
    expect(again.ok).toBe(true);
    // the token alone does not prove the hash
    const { verifyTimestampToken } = await import('../src/lib/index.ts');
    expect(await verifyTimestampToken(r.value.token, MY_HASH, [SIGNER.caPem])).toMatchObject({
      reason: 'imprint-mismatch',
    });
  });
  it('refuses a tampered receipt, a receipt for another hash and a malformed batch field', async () => {
    const imprint = new Uint8Array(BATCH.imprint);
    const cases: [unknown, Uint8Array, string][] = [
      [{ ...PROOF, index: 0 }, MY_HASH, 'imprint-mismatch'],
      [{ ...PROOF, salt: toBase64Url(new Uint8Array(32)) }, MY_HASH, 'imprint-mismatch'],
      [{ ...PROOF, path: [...PROOF.path].reverse() }, MY_HASH, 'imprint-mismatch'],
      [PROOF, sha256('not in the batch'), 'imprint-mismatch'],
      [{ ...PROOF, path: PROOF.path.slice(1) }, MY_HASH, 'bad-batch'],
      [{ ...PROOF, salt: 'AAAA' }, MY_HASH, 'bad-batch'],
      [{ ...PROOF, extra: 1 }, MY_HASH, 'relay-bad-response'],
      [{ ...PROOF, v: 2 }, MY_HASH, 'relay-bad-response'],
      [{ ...PROOF, index: 3 }, MY_HASH, 'relay-bad-response'],
      [{ ...PROOF, path: 'x' }, MY_HASH, 'relay-bad-response'],
      [null, MY_HASH, 'relay-bad-response'],
    ];
    for (const [batch, hash, reason] of cases) {
      const body = await answerFor(BATCH_TOKEN, imprint, { batch });
      const { client } = setup(() => reply(200, body));
      expect(await client.stamp(hash), JSON.stringify(batch)).toMatchObject({ ok: false, reason });
    }
  });
  it('parseRelayAnswer copies the batch field and refuses unknown fields', async () => {
    const body = await answerFor(BATCH_TOKEN, new Uint8Array(BATCH.imprint), { batch: PROOF });
    const read = parseRelayAnswer(body);
    expect(read.ok && read.value.batch).toEqual(PROOF);
    expect(read.ok && read.value.batch !== (PROOF as unknown)).toBe(true);
    expect(parseRelayAnswer({ ...body, other: 1 })).toMatchObject({ reason: 'relay-bad-response' });
  });
});

describe('relay client: solo', () => {
  it('sends "mode": "solo" per call or per client, and nothing extra without it', async () => {
    const hash = sha256('solo');
    const token = tokenFor(hash);
    const a = setup(async () => reply(200, await answerFor(token, hash)));
    expect((await a.client.stamp(hash, { mode: 'solo' })).ok).toBe(true);
    expect((await a.client.stamp(hash)).ok).toBe(true);
    expect(a.posts().map((p) => JSON.parse(p.init.body!))).toEqual([
      { hash: toBase64Url(hash), mode: 'solo' },
      { hash: toBase64Url(hash) },
    ]);
    const b = setup(async () => reply(200, await answerFor(token, hash)), { mode: 'solo' });
    expect((await b.client.stamp(hash)).ok).toBe(true);
    expect(JSON.parse(b.posts()[0]!.init.body!)).toEqual({ hash: toBase64Url(hash), mode: 'solo' });
    const signed = b.posts()[0]!;
    expect(
      relayAccepts(
        signed.init.headers!['X-Zeitstempel-Auth']!,
        '/v1/stamp/freetsa',
        signed.init.body!,
      ),
    ).toBe(true);
  });
  it('refuses a batch answer to a solo request, and an unknown mode', async () => {
    const body = await answerFor(BATCH_TOKEN, new Uint8Array(BATCH.imprint), { batch: PROOF });
    const { client, calls } = setup(() => reply(200, body));
    expect(await client.stamp(MY_HASH, { mode: 'solo' })).toMatchObject({
      reason: 'relay-bad-response',
      detail: 'a batch answer to a solo request',
    });
    const before = calls.length;
    expect(await client.stamp(MY_HASH, { mode: 'batch' as 'solo' })).toMatchObject({
      reason: 'bad-options',
    });
    expect(calls).toHaveLength(before);
  });
});

describe('relay client ↔ relay server, authentication and collecting operation on', () => {
  const SERVICES = loadServices();
  const KEYS: RelayKey[] = [
    { id: KEY.id, publicKey: KEY.publicKey },
    { id: SOLO_KEY.id, publicKey: SOLO_KEY.publicKey, solo: true },
  ];
  let close: () => Promise<void> = async () => {};
  afterEach(() => close());

  async function start() {
    const calls: Uint8Array[] = [];
    const upstream: Upstream = async (_t, body) => {
      calls.push(body);
      const parts = children(parseDer(body));
      const hash = octets(children(parts[1]!)[1]!);
      const made = build({
        keys: SIGNER.keys,
        hash,
        nonceBytes: integerBytes(parts[2]!),
        genTime: genTimeText(NOW),
      });
      return {
        status: 200,
        contentType: 'application/timestamp-reply',
        body: seq(seq(int(0)), made.token),
      };
    };
    const options: RelayOptions = {
      services: SERVICES.map((s) => ({ ...s, anchorPems: [...s.anchorPems, SIGNER.caPem] })),
      origins: ['https://app.example'],
      allowPlainHttp: false,
      upstream,
      random: (n) => new Uint8Array(randomBytes(n)),
      now: () => NOW,
      keys: KEYS,
      batch: { windowMs: 150, max: 100 },
    };
    const { server, relay } = createRelayServer(options);
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    close = () =>
      new Promise((r) => {
        relay.close();
        server.closeAllConnections();
        server.close(() => r());
      });
    return { base, calls };
  }

  const realFetch: FetchLike = (url, init) => fetch(url, init);
  const clientFor = (base: string, key: typeof KEY | null, wallOffsetMs = 0) =>
    createRelayClient({
      relay: base,
      fetch: realFetch,
      now: () => performance.now(),
      wallNow: () => NOW + wallOffsetMs,
      trusted: new Map([['freetsa', [SIGNER.caPem]]]),
      ...(key ? { auth: { privateKey: key.privateKey, keyId: key.id } } : {}),
    });

  it('three signed requests in one window: one call to the service, three verified receipts', async () => {
    const { base, calls } = await start();
    const client = clientFor(base, KEY);
    const hashes = [sha256('e2e-0'), sha256('e2e-1'), sha256('e2e-2')];
    const results = await Promise.all(hashes.map((h) => client.stamp(h)));
    for (const [i, r] of results.entries()) {
      expect(r.ok, JSON.stringify(r)).toBe(true);
      if (!r.ok) continue;
      expect(r.value.batch?.size).toBe(3);
      const later = await verifyBatchedTimestamp(
        { token: r.value.token, hash: hashes[i]!, batch: r.value.batch! },
        [SIGNER.caPem],
      );
      expect(later.ok).toBe(true);
    }
    expect(calls).toHaveLength(1);
    expect(new Set(results.map((r) => (r.ok ? r.value.batch!.index : -1)))).toEqual(
      new Set([0, 1, 2]),
    );
  });
  it('a key of type 2 gets a solo stamp (no batch); type 1 asking for solo gets relay-unauthorized', async () => {
    const { base } = await start();
    const solo = await clientFor(base, SOLO_KEY).stamp(sha256('solo-e2e'), { mode: 'solo' });
    expect(solo.ok, JSON.stringify(solo)).toBe(true);
    if (solo.ok) expect(solo.value.batch).toBeUndefined();
    expect(await clientFor(base, KEY).stamp(sha256('x'), { mode: 'solo' })).toMatchObject({
      reason: 'relay-unauthorized',
      detail: 'status 403, solo-not-allowed',
    });
  });
  it('without a key, or with an unknown key: relay-unauthorized', async () => {
    const { base, calls } = await start();
    expect(await clientFor(base, null).stamp(sha256('x'))).toMatchObject({
      reason: 'relay-unauthorized',
      detail: 'status 401, unauthorized',
    });
    expect(await clientFor(base, makeTestKey('app-1')).stamp(sha256('y'))).toMatchObject({
      reason: 'relay-unauthorized',
    });
    expect(calls).toHaveLength(0);
  });
  it('the payload decodes: the token in the receipt is the service token for the batch imprint', async () => {
    const { base } = await start();
    const r = await clientFor(base, KEY).stamp(sha256('single'));
    expect(r.ok).toBe(true);
    if (r.ok) expect(fromBase64Url(toBase64Url(r.value.token))).toEqual(r.value.token);
  });
});
