import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  buildTimestampRequest,
  readTimestampResponse,
  verifyTimestampToken,
} from '../src/index.ts';
import { byteLength, copyBytes } from '../src/lib/bytes.ts';
import { DER_LIMITS } from '../src/lib/der.ts';
import { FREETSA_NONCE, fixture, fixtureText, sha256 } from './helpers.ts';

const ROOT = fixtureText('cacert.pem');
const response = readTimestampResponse(fixture('freetsa.tsr'));
if (!response.ok) throw new Error('fixture unreadable');
const TOKEN = response.value.token;
const HASH = sha256('probe');
const OPTIONS = { expectedNonce: FREETSA_NONCE, now: new Date('2026-11-23T14:00:00Z') };
const show = (r: { ok: boolean; reason?: string }) => (r.ok ? 'ok' : r.reason);

const TypedArray = Object.getPrototypeOf(Uint8Array.prototype) as { set: unknown };

describe('J1: inputs are copied by length and set(), never through the iterator', () => {
  it('endless iterators on hash, nonce, token and trust do not matter (child process, 128 MB heap)', () => {
    const script = fileURLToPath(new URL('./copy-child.ts', import.meta.url));
    const r = spawnSync(process.execPath, ['--max-old-space-size=128', script], {
      encoding: 'utf8',
      timeout: 20_000,
    });
    expect(r.error, String(r.stderr)).toBeUndefined();
    expect(r.status, String(r.stderr)).toBe(0);
    expect(JSON.parse(r.stdout)).toEqual({
      request: 'ok',
      verifyInputs: 'ok',
      trustIterator: 'ok',
      trustHugeLength: 'bad-options',
      trustTooMany: 'bad-options',
    });
  });

  it('an input over the limit is refused by its length alone: nothing is iterated, nothing is copied', () => {
    let iterated = 0;
    const big = new Uint8Array(1 << 20); // far over the 16 bytes allowed
    const original = Uint8Array.prototype.values;
    Object.defineProperty(big, Symbol.iterator, {
      value: function* () {
        iterated += 1;
        yield* original.call(big);
      },
    });
    const set = vi.spyOn(TypedArray as { set: (source: Uint8Array) => void }, 'set');
    try {
      expect(copyBytes(big, 1, 16)).toBeNull();
      expect(buildTimestampRequest(HASH, big)).toEqual({ ok: false, reason: 'bad-nonce' });
      expect(iterated).toBe(0);
      expect(set.mock.calls.filter(([source]) => source.length === big.length)).toEqual([]);
    } finally {
      set.mockRestore();
    }
  });

  it('an own length property does not fool the length check', () => {
    const lie = new Uint8Array(40);
    Object.defineProperty(lie, 'length', { value: 4 });
    expect(byteLength(lie)).toBe(40);
    expect(copyBytes(lie, 1, 16)).toBeNull();
  });

  it('byteLength and copyBytes give null for everything that is no Uint8Array, a throwing proxy included', () => {
    const proxy = new Proxy(Uint8Array.of(1), {
      getPrototypeOf() {
        throw new Error('trap');
      },
    });
    for (const v of [proxy, [1, 2], 'ab', null, undefined, new ArrayBuffer(2), { length: 2 }]) {
      expect(byteLength(v)).toBeNull();
      expect(copyBytes(v, 0, 16)).toBeNull();
    }
  });
});

describe('J2: trust is read by length and index', () => {
  it('a list of exactly 64 entries is accepted as a list, 65 is bad-options', async () => {
    const sixtyFour = [ROOT, ...new Array<string>(63).fill(ROOT)];
    expect(show(await verifyTimestampToken(TOKEN, HASH, sixtyFour, OPTIONS))).toBe('ok');
    expect(await verifyTimestampToken(TOKEN, HASH, [...sixtyFour, ROOT], OPTIONS)).toEqual({
      ok: false,
      reason: 'bad-options',
    });
  });
  it('a non-numeric or negative length (proxy of an array) is bad-options', async () => {
    for (const length of ['3', -1, 1.5, NaN, undefined]) {
      const list = new Proxy([ROOT], {
        get: (t, k) => (k === 'length' ? length : Reflect.get(t, k)),
      });
      expect(await verifyTimestampToken(TOKEN, HASH, list as never, OPTIONS)).toEqual({
        ok: false,
        reason: 'bad-options',
      });
    }
  });
});

describe('J3/J4/J5a: the token is copied once, into a buffer of its own', () => {
  it('emptying the caller buffer right after the call does not change the result', async () => {
    const buf = new Uint8Array(TOKEN);
    const pending = verifyTimestampToken(buf, HASH, [ROOT], OPTIONS);
    buf.fill(0);
    expect(show(await pending)).toBe('ok');
  });
  it('changing the caller buffer during the awaits does not change the result', async () => {
    const buf = new Uint8Array(TOKEN);
    const pending = verifyTimestampToken(buf, HASH, [ROOT], OPTIONS);
    await Promise.resolve();
    await new Promise((resolve) => setTimeout(resolve, 0));
    buf.fill(0);
    expect(show(await pending)).toBe('ok');
  });
  it('a token that lives in a SharedArrayBuffer verifies', async () => {
    const view = new Uint8Array(new SharedArrayBuffer(TOKEN.length));
    view.set(TOKEN);
    expect(show(await verifyTimestampToken(view, HASH, [ROOT], OPTIONS))).toBe('ok');
  });
  it('a hash and a nonce in a SharedArrayBuffer are accepted too', async () => {
    const h = new Uint8Array(new SharedArrayBuffer(32));
    h.set(HASH);
    const n = new Uint8Array(new SharedArrayBuffer(FREETSA_NONCE.length));
    n.set(FREETSA_NONCE);
    expect(
      show(await verifyTimestampToken(TOKEN, h, [ROOT], { ...OPTIONS, expectedNonce: n })),
    ).toBe('ok');
  });
  it('a token over the DER limit is too-large, and the length is checked before the copy', async () => {
    const big = new Uint8Array(DER_LIMITS.maxBytes + 1);
    const set = vi.spyOn(TypedArray as { set: (source: Uint8Array) => void }, 'set');
    try {
      expect(await verifyTimestampToken(big, HASH, [ROOT], OPTIONS)).toEqual({
        ok: false,
        reason: 'too-large',
      });
      expect(set.mock.calls.filter(([source]) => source.length > 1000)).toEqual([]);
    } finally {
      set.mockRestore();
    }
  });
  it('copyBytes returns a copy, not the original', () => {
    const original = Uint8Array.of(1, 2, 3);
    const copy = copyBytes(original, 0, 8)!;
    expect(copy).not.toBe(original);
    expect(copy.buffer).not.toBe(original.buffer);
    original.fill(9);
    expect(Array.from(copy)).toEqual([1, 2, 3]);
  });
  it('buildTimestampRequest works on copies: the request does not change with the caller buffers', () => {
    const hash = new Uint8Array(HASH);
    const nonce = Uint8Array.of(1, 2, 3, 4);
    const first = buildTimestampRequest(hash, nonce);
    hash.fill(0);
    nonce.fill(0);
    expect(first).toEqual(buildTimestampRequest(HASH, Uint8Array.of(1, 2, 3, 4)));
  });
});
