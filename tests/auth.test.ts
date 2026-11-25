import { generateKeyPairSync, verify } from 'node:crypto';
import { signRelayRequest, toBase64Url } from '../src/index.ts';
import * as lib from '../src/index.ts';
import { RELAY_LIMITS } from '../relay/limits.ts';
import { TEST_AUDIENCE, authMessage, makeTestKey } from './auth-helpers.ts';

const KEY = makeTestKey('app-1');
const BODY = new TextEncoder().encode('{"hash":"x"}');
const NOW_MS = Date.parse('2026-11-23T13:10:00.900Z');
const TS = Math.floor(NOW_MS); // `ts` of the head: whole milliseconds

const input = (over: Record<string, unknown> = {}) => ({
  privateKey: KEY.privateKey,
  keyId: 'app-1',
  method: 'POST',
  path: '/v1/stamp/freetsa',
  body: BODY,
  nowMs: NOW_MS,
  audience: TEST_AUDIENCE,
  ...over,
});

/** Does node:crypto accept the header's signature for this message under the test key? */
function accepts(
  header: string,
  method: string,
  path: string,
  ts: number,
  body: Uint8Array,
  audience: string = TEST_AUDIENCE,
) {
  const parts = header.split('.');
  const sig = Buffer.from(parts[4]!, 'base64url');
  return verify(
    'sha256',
    Buffer.from(authMessage(method, path, ts, body, parts[3]!, audience)),
    { key: KEY.object, dsaEncoding: 'ieee-p1363' },
    sig,
  );
}

describe('signRelayRequest', () => {
  it('has no deriveVerifier any more (v1 is gone)', () => {
    expect('deriveVerifier' in lib).toBe(false);
    expect('generateAuthKeyPair' in lib).toBe(false); // making a key pair is a tool, not the library
  });
  it('makes a v3 header whose signature node:crypto verifies over the specified message', async () => {
    const r = await signRelayRequest(input());
    if (!r.ok) throw new Error(r.reason);
    const [version, kid, ts, jti, sig] = r.value.split('.');
    expect([version, kid, ts]).toEqual(['v3', 'app-1', String(TS)]);
    expect(jti).toMatch(/^[A-Za-z0-9_-]{22}$/); // 16 bytes
    expect(Buffer.from(jti!, 'base64url')).toHaveLength(16);
    expect(Buffer.from(jti!, 'base64url').toString('base64url')).toBe(jti); // canonical
    expect(sig).toMatch(/^[A-Za-z0-9_-]{86}$/); // 64 bytes, r || s
    expect(accepts(r.value, 'POST', '/v1/stamp/freetsa', TS, BODY)).toBe(true);
  });
  it('takes the time from the parameter (milliseconds, rounded down)', async () => {
    const later = await signRelayRequest(input({ nowMs: NOW_MS + 1000 }));
    if (!later.ok) throw new Error(later.reason);
    expect(later.value.split('.')[2]).toBe(String(TS + 1000));
    expect(accepts(later.value, 'POST', '/v1/stamp/freetsa', TS + 1000, BODY)).toBe(true);
    const frac = await signRelayRequest(input({ nowMs: 1_800_000_000_123.9 }));
    if (!frac.ok) throw new Error(frac.reason);
    expect(frac.value.split('.')[2]).toBe('1800000000123');
  });
  it('signs the audience: the signature is no good for another audience, and a bad audience is bad-options', async () => {
    const r = await signRelayRequest(input({ audience: 'https://relay.one' }));
    if (!r.ok) throw new Error(r.reason);
    expect(accepts(r.value, 'POST', '/v1/stamp/freetsa', TS, BODY, 'https://relay.one')).toBe(true);
    expect(accepts(r.value, 'POST', '/v1/stamp/freetsa', TS, BODY, 'https://relay.two')).toBe(
      false,
    );
    expect(accepts(r.value, 'POST', '/v1/stamp/freetsa', TS, BODY, TEST_AUDIENCE)).toBe(false);
    for (const audience of [
      '',
      'a'.repeat(129),
      'has space',
      'tab\t',
      'new\nline',
      'ümlaut',
      5,
      null,
      undefined,
    ]) {
      expect(await signRelayRequest(input({ audience })), String(audience)).toEqual({
        ok: false,
        reason: 'bad-options',
      });
    }
    expect((await signRelayRequest(input({ audience: 'a'.repeat(128) }))).ok).toBe(true);
    expect((await signRelayRequest(input({ audience: '!' }))).ok).toBe(true);
  });
  it('makes a fresh random jti per call; a given jti (16 bytes) is used as it is; any other jti is bad-options', async () => {
    const a = await signRelayRequest(input());
    const b = await signRelayRequest(input());
    if (!a.ok || !b.ok) throw new Error('sign');
    expect(a.value.split('.')[3]).not.toBe(b.value.split('.')[3]); // same everything else
    const fixed = new Uint8Array(16).fill(7);
    const c = await signRelayRequest(input({ jti: fixed }));
    if (!c.ok) throw new Error(c.reason);
    expect(c.value.split('.')[3]).toBe(Buffer.from(fixed).toString('base64url'));
    expect(accepts(c.value, 'POST', '/v1/stamp/freetsa', TS, BODY)).toBe(true);
    for (const jti of [new Uint8Array(15), new Uint8Array(17), 'x'.repeat(22), [1, 2], null]) {
      expect(await signRelayRequest(input({ jti })), String(jti)).toEqual({
        ok: false,
        reason: 'bad-options',
      });
    }
    expect((await signRelayRequest(input({ jti: undefined }))).ok).toBe(true);
  });
  it('takes the jti from crypto.getRandomValues (WebCrypto), no node:', async () => {
    const spy = vi.spyOn(globalThis.crypto, 'getRandomValues');
    try {
      expect((await signRelayRequest(input())).ok).toBe(true);
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.mock.calls[0]![0]).toHaveLength(16);
    } finally {
      spy.mockRestore();
    }
  });
  it('takes fractions of milliseconds and the lower bound 1e11, but not seconds', async () => {
    const frac = await signRelayRequest(input({ nowMs: NOW_MS + 0.25 }));
    expect(frac.ok).toBe(true);
    expect((await signRelayRequest(input({ nowMs: 1e11 }))).ok).toBe(true);
    // the largest accepted time gives a 15 digit `ts`, the lowest a 12 digit one: the relay's header format reads both
    const top = await signRelayRequest(input({ nowMs: 1e15 - 1 }));
    expect(top.ok && /^v3\.[a-z0-9-]+\.999999999999999\./.test(top.value)).toBe(true);
    const low = await signRelayRequest(input({ nowMs: 1e11 }));
    expect(low.ok && /^v3\.[a-z0-9-]+\.100000000000\./.test(low.value)).toBe(true);
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
    // the jti is signed too: a head with another jti has no valid signature
    const parts = r.value.split('.');
    parts[3] = Buffer.alloc(16, 9).toString('base64url');
    expect(accepts(parts.join('.'), 'POST', '/v1/stamp/freetsa', TS, BODY)).toBe(false);
  });
  it('is signed by the private key only: another key does not verify', async () => {
    const r = await signRelayRequest(input());
    if (!r.ok) throw new Error(r.reason);
    const stranger = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey;
    const sig = Buffer.from(r.value.split('.')[4]!, 'base64url');
    const message = Buffer.from(
      authMessage('POST', '/v1/stamp/freetsa', TS, BODY, r.value.split('.')[3]!),
    );
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
  describe('a CryptoKey as privateKey (Befund 11)', () => {
    const importKey = (extractable: boolean) =>
      globalThis.crypto.subtle.importKey(
        'pkcs8',
        KEY.privateKey as BufferSource,
        { name: 'ECDSA', namedCurve: 'P-256' },
        extractable,
        ['sign'],
      );
    it('signs with a non-extractable CryptoKey: the header is the one node:crypto verifies', async () => {
      const key = await importKey(false);
      expect(key.extractable).toBe(false);
      const r = await signRelayRequest(input({ privateKey: key }));
      if (!r.ok) throw new Error(r.reason);
      expect(r.value.split('.').slice(0, 3)).toEqual(['v3', 'app-1', String(TS)]);
      expect(accepts(r.value, 'POST', '/v1/stamp/freetsa', TS, BODY)).toBe(true);
    });
    it('uses the key as it is: nothing is imported or exported, and the result holds only the header', async () => {
      const key = await importKey(false);
      const imp = vi.spyOn(globalThis.crypto.subtle, 'importKey');
      const exp = vi.spyOn(globalThis.crypto.subtle, 'exportKey');
      try {
        const r = await signRelayRequest(input({ privateKey: key }));
        expect(r.ok).toBe(true);
        expect(imp).not.toHaveBeenCalled();
        expect(exp).not.toHaveBeenCalled();
        expect(Object.keys(r).sort()).toEqual(['ok', 'value']);
      } finally {
        imp.mockRestore();
        exp.mockRestore();
      }
    });
    it('also takes an extractable key', async () => {
      const r = await signRelayRequest(input({ privateKey: await importKey(true) }));
      expect(r.ok).toBe(true);
    });
    it('refuses every other CryptoKey with bad-key: public, other curve, other algorithm, secret', async () => {
      const subtle = globalThis.crypto.subtle;
      const p256 = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
        'sign',
        'verify',
      ]);
      const p384 = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, false, [
        'sign',
        'verify',
      ]);
      const ecdh = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, [
        'deriveBits',
      ]);
      const rsa = await subtle.generateKey(
        {
          name: 'RSASSA-PKCS1-v1_5',
          modulusLength: 2048,
          publicExponent: Uint8Array.of(1, 0, 1),
          hash: 'SHA-256',
        },
        false,
        ['sign', 'verify'],
      );
      const hmac = await subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const cases: [string, unknown][] = [
        ['the public key of P-256', p256.publicKey],
        ['a private P-384 key', p384.privateKey],
        ['a private ECDH key', ecdh.privateKey],
        ['a private RSA key', rsa.privateKey],
        ['a secret HMAC key', hmac],
      ];
      for (const [name, privateKey] of cases) {
        expect(await signRelayRequest(input({ privateKey })), name).toEqual({
          ok: false,
          reason: 'bad-key',
        });
      }
    });
    it('a look-alike object and a Proxy with a throwing trap are no CryptoKey (bad-key, never a throw)', async () => {
      const key = await importKey(false);
      const lookAlike = {
        type: 'private',
        algorithm: { name: 'ECDSA', namedCurve: 'P-256' },
        usages: ['sign'],
        extractable: false,
      };
      const boom = () => {
        throw new Error('hostile');
      };
      const cases: [string, unknown][] = [
        ['look-alike', lookAlike],
        [
          'look-alike with the prototype of CryptoKey',
          Object.setPrototypeOf({ ...lookAlike }, CryptoKey.prototype),
        ],
        ['Proxy, get trap', new Proxy(key, { get: boom })],
        ['Proxy, getPrototypeOf trap', new Proxy(key, { getPrototypeOf: boom })],
      ];
      for (const [name, privateKey] of cases) {
        expect(await signRelayRequest(input({ privateKey })), name).toEqual({
          ok: false,
          reason: 'bad-key',
        });
      }
    });
    it('a Proxy that forwards everything is whatever the platform makes of it, and never a throw', async () => {
      const r = await signRelayRequest(
        input({ privateKey: new Proxy(await importKey(false), {}) }),
      );
      expect(typeof r.ok).toBe('boolean');
    });
    it('reads the key property of the input once', async () => {
      const key = await importKey(false);
      const reads: Record<string, number> = {};
      const counted = new Proxy(input({ privateKey: key }), {
        get(target, k, receiver) {
          reads[String(k)] = (reads[String(k)] ?? 0) + 1;
          return Reflect.get(target, k, receiver);
        },
      });
      expect(await signRelayRequest(counted as never)).toMatchObject({ ok: true });
      expect(Object.values(reads).every((n) => n === 1)).toBe(true);
    });
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
      [{ nowMs: Number.MAX_VALUE }, 'bad-options'], // audit 2, B4: an upper bound too
      [{ nowMs: 1e300 }, 'bad-options'],
      [{ nowMs: 1e17 }, 'bad-options'],
      [{ nowMs: 1e15 }, 'bad-options'], // ts of 16 digits: the relay's header takes 15 at most
      [{ nowMs: Number.NEGATIVE_INFINITY }, 'bad-options'],
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
