import { generateKeyPairSync, verify } from 'node:crypto';
import { signRelayRequest, toBase64Url } from '../src/index.ts';
import * as lib from '../src/index.ts';
import { RELAY_LIMITS } from '../relay/limits.ts';
import { authMessage, makeTestKey } from './auth-helpers.ts';

const KEY = makeTestKey('app-1');
const BODY = new TextEncoder().encode('{"hash":"x"}');
const NOW_MS = Date.parse('2026-11-23T13:10:00.900Z');
const TS = Math.floor(NOW_MS / 1000);

const input = (over: Record<string, unknown> = {}) => ({
  privateKey: KEY.privateKey,
  keyId: 'app-1',
  method: 'POST',
  path: '/v1/stamp/freetsa',
  body: BODY,
  nowMs: NOW_MS,
  ...over,
});

/** Does node:crypto accept the header's signature for this message under the test key? */
function accepts(header: string, method: string, path: string, ts: number, body: Uint8Array) {
  const sig = Buffer.from(header.split('.')[3]!, 'base64url');
  return verify(
    'sha256',
    Buffer.from(authMessage(method, path, ts, body)),
    { key: KEY.object, dsaEncoding: 'ieee-p1363' },
    sig,
  );
}

describe('signRelayRequest', () => {
  it('has no deriveVerifier any more (v1 is gone)', () => {
    expect('deriveVerifier' in lib).toBe(false);
    expect('generateAuthKeyPair' in lib).toBe(false); // making a key pair is a tool, not the library
  });
  it('makes a v2 header whose signature node:crypto verifies over the specified message', async () => {
    const r = await signRelayRequest(input());
    if (!r.ok) throw new Error(r.reason);
    const [version, kid, ts, sig] = r.value.split('.');
    expect([version, kid, ts]).toEqual(['v2', 'app-1', String(TS)]);
    expect(sig).toMatch(/^[A-Za-z0-9_-]{86}$/); // 64 bytes, r || s
    expect(accepts(r.value, 'POST', '/v1/stamp/freetsa', TS, BODY)).toBe(true);
  });
  it('takes the time from the parameter (seconds, rounded down)', async () => {
    const later = await signRelayRequest(input({ nowMs: NOW_MS + 1000 }));
    if (!later.ok) throw new Error(later.reason);
    expect(later.value.split('.')[2]).toBe(String(TS + 1));
    expect(accepts(later.value, 'POST', '/v1/stamp/freetsa', TS + 1, BODY)).toBe(true);
  });
  it('takes fractions of milliseconds and the lower bound 1e11, but not seconds', async () => {
    const frac = await signRelayRequest(input({ nowMs: NOW_MS + 0.25 }));
    expect(frac.ok).toBe(true);
    expect((await signRelayRequest(input({ nowMs: 1e11 }))).ok).toBe(true);
    expect(await signRelayRequest(input({ nowMs: NOW_MS / 1000 }))).toEqual({
      ok: false,
      reason: 'bad-options',
    });
  });
  it('binds method, path, time and body: the signature is not valid for any other message', async () => {
    const r = await signRelayRequest(input());
    if (!r.ok) throw new Error(r.reason);
    const other = new TextEncoder().encode('{"hash":"y"}');
    expect(accepts(r.value, 'PUT', '/v1/stamp/freetsa', TS, BODY)).toBe(false);
    expect(accepts(r.value, 'POST', '/v1/stamp/sectigo', TS, BODY)).toBe(false);
    expect(accepts(r.value, 'POST', '/v1/stamp/freetsa', TS + 1, BODY)).toBe(false);
    expect(accepts(r.value, 'POST', '/v1/stamp/freetsa', TS, other)).toBe(false);
  });
  it('is signed by the private key only: another key does not verify', async () => {
    const r = await signRelayRequest(input());
    if (!r.ok) throw new Error(r.reason);
    const stranger = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey;
    const sig = Buffer.from(r.value.split('.')[3]!, 'base64url');
    const message = Buffer.from(authMessage('POST', '/v1/stamp/freetsa', TS, BODY));
    expect(verify('sha256', message, { key: stranger, dsaEncoding: 'ieee-p1363' }, sig)).toBe(
      false,
    );
  });
  it('never contains the private key', async () => {
    const r = await signRelayRequest(input());
    if (!r.ok) throw new Error(r.reason);
    for (const secret of [
      toBase64Url(KEY.privateKey),
      Buffer.from(KEY.privateKey).toString('hex'),
      KEY.object.export({ format: 'jwk' }).d!, // the private scalar itself
    ]) {
      expect(r.value).not.toContain(secret);
    }
  });
  it('imports the key as not extractable and gives nothing back but the header', async () => {
    const spy = vi.spyOn(globalThis.crypto.subtle, 'importKey');
    try {
      const r = await signRelayRequest(input());
      expect(r.ok).toBe(true);
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.mock.calls[0]![3]).toBe(false); // extractable: false
      expect(Object.keys(r).sort()).toEqual(['ok', 'value']);
    } finally {
      spy.mockRestore();
    }
  });
  it('answers with codes and never throws', async () => {
    const other = generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).privateKey.export({
      format: 'der',
      type: 'pkcs8',
    });
    const codes: [Record<string, unknown>, string][] = [
      [{ privateKey: new Uint8Array(0) }, 'bad-key'],
      [{ privateKey: new Uint8Array(32) }, 'bad-key'], // a raw scalar is no PKCS#8
      [{ privateKey: KEY.privateKey.subarray(0, 40) }, 'bad-key'],
      [{ privateKey: new Uint8Array(other) }, 'bad-key'], // PKCS#8, but P-384
      [{ privateKey: 'text' }, 'bad-key'],
      [{ privateKey: null }, 'bad-key'],
      [{ keyId: 'App' }, 'bad-key-id'],
      [{ keyId: '1app' }, 'bad-key-id'],
      [{ keyId: 'a'.repeat(33) }, 'bad-key-id'],
      [{ keyId: '' }, 'bad-key-id'],
      [{ method: 'post' }, 'bad-options'],
      [{ path: 'v1/stamp/x' }, 'bad-options'],
      [{ path: '/v1/stamp/x?y=1' }, 'bad-options'],
      [{ path: '/v1/stamp/x\n' }, 'bad-options'],
      [{ body: 'text' }, 'bad-options'],
      [{ nowMs: Number.NaN }, 'bad-options'],
      [{ nowMs: -1 }, 'bad-options'],
      [{ nowMs: Number.POSITIVE_INFINITY }, 'bad-options'],
      [{ nowMs: Math.floor(NOW_MS / 1000) }, 'bad-options'], // seconds instead of milliseconds
      [{ nowMs: 0 }, 'bad-options'],
      [{ nowMs: 1e11 - 1 }, 'bad-options'],
    ];
    for (const [over, reason] of codes) {
      expect(await signRelayRequest(input(over)), JSON.stringify(over).slice(0, 40)).toMatchObject({
        ok: false,
        reason,
      });
    }
    expect(await signRelayRequest(null as never)).toMatchObject({
      ok: false,
      reason: 'bad-options',
    });
  });
  it('never throws or rejects for hostile Proxies: input, privateKey and body', async () => {
    const boom = () => {
      throw new Error('hostile');
    };
    const hostile = (target: object) =>
      new Proxy(target, { getPrototypeOf: boom, get: boom, has: boom, ownKeys: boom });
    const getTrap = (target: object) => new Proxy(target, { get: boom });
    const protoTrap = (target: object) => new Proxy(target, { getPrototypeOf: boom });
    const cases: [string, unknown, string | null][] = [
      ['input, get', getTrap(input()), 'bad-options'],
      ['input, getPrototypeOf', protoTrap(input()), null], // not needed to read the fields: a code or a header
      ['input, all traps', hostile(input()), 'bad-options'],
      ['privateKey, getPrototypeOf', input({ privateKey: protoTrap(KEY.privateKey) }), 'bad-key'],
      ['privateKey, get', input({ privateKey: getTrap(KEY.privateKey) }), 'bad-key'],
      ['privateKey, all traps', input({ privateKey: hostile(KEY.privateKey) }), 'bad-key'],
      ['body, getPrototypeOf', input({ body: protoTrap(BODY) }), 'bad-options'],
      ['body, get', input({ body: getTrap(BODY) }), 'bad-options'],
      ['body, all traps', input({ body: hostile(BODY) }), 'bad-options'],
    ];
    for (const [name, value, reason] of cases) {
      const r = await signRelayRequest(value as never); // a rejection fails the test here
      if (reason !== null) expect(r, name).toMatchObject({ ok: false, reason });
    }
  });
  it('reads each input once and never iterates the bytes', async () => {
    const reads: Record<string, number> = {};
    const counted = new Proxy(input(), {
      get(target, key, receiver) {
        reads[String(key)] = (reads[String(key)] ?? 0) + 1;
        return Reflect.get(target, key, receiver);
      },
    });
    expect(await signRelayRequest(counted as never)).toMatchObject({ ok: true });
    expect(Object.values(reads).every((n) => n === 1)).toBe(true);
    // an iterator that is hostile or answers differently is never called
    const evil = new Uint8Array(BODY);
    Object.defineProperty(evil, Symbol.iterator, {
      value: () => {
        throw new Error('iterated');
      },
    });
    const withEvilKey = new Uint8Array(KEY.privateKey);
    Object.defineProperty(withEvilKey, Symbol.iterator, {
      value: () => {
        throw new Error('iterated');
      },
    });
    expect(await signRelayRequest(input({ body: evil, privateKey: withEvilKey }))).toMatchObject({
      ok: true,
    });
  });
  it('uses the built-in length, not an own one, and copies before signing', async () => {
    const lying = new Uint8Array(BODY);
    Object.defineProperty(lying, 'length', { value: 1 });
    const r = await signRelayRequest(input({ body: lying }));
    if (!r.ok) throw new Error(r.reason);
    expect(accepts(r.value, 'POST', '/v1/stamp/freetsa', TS, BODY)).toBe(true); // the real bytes were signed
  });
  it('has an upper limit for privateKey (256 bytes) and body (512 bytes)', async () => {
    expect(await signRelayRequest(input({ privateKey: new Uint8Array(257) }))).toMatchObject({
      ok: false,
      reason: 'bad-key',
    });
    expect(await signRelayRequest(input({ body: new Uint8Array(513) }))).toMatchObject({
      ok: false,
      reason: 'bad-options',
    });
    expect(await signRelayRequest(input({ body: new Uint8Array(512) }))).toMatchObject({
      ok: true,
    });
    expect(await signRelayRequest(input({ body: new Uint8Array(0) }))).toMatchObject({ ok: true });
  });
  it("signs a body up to the relay's limit and refuses one byte more (MAX_BODY_BYTES = RELAY_LIMITS.bodyBytes)", async () => {
    // src/lib must not import relay/: the two numbers are tied here, by behaviour
    const limit = RELAY_LIMITS.bodyBytes;
    expect(await signRelayRequest(input({ body: new Uint8Array(limit) }))).toMatchObject({
      ok: true,
    });
    expect(await signRelayRequest(input({ body: new Uint8Array(limit + 1) }))).toMatchObject({
      ok: false,
      reason: 'bad-options',
    });
  });
  it('never rejects when WebCrypto itself is hostile (getter on globalThis.crypto throws): bad-options', async () => {
    const saved = Object.getOwnPropertyDescriptor(globalThis, 'crypto')!;
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      get() {
        throw new Error('hostile crypto');
      },
    });
    try {
      expect(await signRelayRequest(input())).toEqual({ ok: false, reason: 'bad-options' });
    } finally {
      Object.defineProperty(globalThis, 'crypto', saved);
    }
    expect(await signRelayRequest(input())).toMatchObject({ ok: true }); // restored
  });
  it('answers unsupported-signature without WebCrypto (insecure page)', async () => {
    vi.stubGlobal('crypto', {});
    try {
      expect(await signRelayRequest(input())).toMatchObject({
        ok: false,
        reason: 'unsupported-signature',
      });
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
