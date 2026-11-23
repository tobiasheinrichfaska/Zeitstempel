import { createHash, createHmac, randomBytes } from 'node:crypto';
import { deriveVerifier, signRelayRequest, toBase64Url } from '../src/index.ts';

// Test keys are random per run: no key material is ever written down in the repo.
const KEY = new Uint8Array(randomBytes(32));
const BODY = new TextEncoder().encode('{"hash":"x"}');
const NOW_MS = Date.parse('2026-11-23T13:10:00.900Z');

/** Independent computation (node:crypto) of the header value the specification describes. */
function expected(
  key: Uint8Array,
  kid: string,
  method: string,
  path: string,
  ts: number,
  body: Uint8Array,
) {
  const v = createHash('sha256').update(key).digest();
  const bodyHex = createHash('sha256').update(body).digest('hex');
  const msg = `zeitstempel-auth-v1\n${method}\n${path}\n${ts}\n${bodyHex}`;
  return `v1.${kid}.${ts}.${createHmac('sha256', v).update(msg).digest('base64url')}`;
}

const input = (over: Record<string, unknown> = {}) => ({
  key: KEY,
  keyId: 'app-1',
  method: 'POST',
  path: '/v1/stamp/freetsa',
  body: BODY,
  nowMs: NOW_MS,
  ...over,
});

describe('deriveVerifier', () => {
  it('is SHA-256 of the key', async () => {
    const v = await deriveVerifier(KEY);
    expect(v.ok && Buffer.from(v.value).equals(createHash('sha256').update(KEY).digest())).toBe(
      true,
    );
  });
  it('refuses a key under 16 bytes', async () => {
    expect(await deriveVerifier(new Uint8Array(15))).toMatchObject({
      ok: false,
      reason: 'bad-key',
    });
    expect((await deriveVerifier(new Uint8Array(16))).ok).toBe(true);
    expect(await deriveVerifier('text' as unknown as Uint8Array)).toMatchObject({
      ok: false,
      reason: 'bad-key',
    });
  });
});

describe('signRelayRequest', () => {
  it('agrees with an independent HMAC computation', async () => {
    const r = await signRelayRequest(input());
    expect(r).toEqual({
      ok: true,
      value: expected(KEY, 'app-1', 'POST', '/v1/stamp/freetsa', Math.floor(NOW_MS / 1000), BODY),
    });
  });
  it('takes the time from the parameter (seconds, rounded down) and is deterministic', async () => {
    const a = await signRelayRequest(input());
    const b = await signRelayRequest(input());
    expect(a).toEqual(b);
    const later = await signRelayRequest(input({ nowMs: NOW_MS + 1000 }));
    expect(later.ok && a.ok && later.value !== a.value).toBe(true);
  });
  it('binds method, path and body', async () => {
    const base = await signRelayRequest(input());
    for (const over of [
      { method: 'PUT' },
      { path: '/v1/stamp/sectigo' },
      { body: new TextEncoder().encode('{"hash":"y"}') },
      { keyId: 'app-2' },
    ]) {
      const other = await signRelayRequest(input(over));
      expect(
        other.ok && base.ok && other.value !== base.value,
        JSON.stringify(Object.keys(over)),
      ).toBe(true);
    }
  });
  it('never contains the key or its verifier', async () => {
    const r = await signRelayRequest(input());
    const v = await deriveVerifier(KEY);
    if (!r.ok || !v.ok) throw new Error('unexpected');
    for (const secret of [
      toBase64Url(KEY),
      toBase64Url(v.value),
      Buffer.from(KEY).toString('hex'),
    ]) {
      expect(r.value).not.toContain(secret);
    }
  });
  it('answers with codes and never throws', async () => {
    const codes: [Record<string, unknown>, string][] = [
      [{ key: new Uint8Array(15) }, 'bad-key'],
      [{ key: null }, 'bad-key'],
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
    ];
    for (const [over, reason] of codes) {
      expect(await signRelayRequest(input(over)), JSON.stringify(Object.keys(over))).toMatchObject({
        ok: false,
        reason,
      });
    }
    expect(await signRelayRequest(null as never)).toMatchObject({
      ok: false,
      reason: 'bad-options',
    });
  });
  it('answers unsupported-signature without WebCrypto (insecure page)', async () => {
    vi.stubGlobal('crypto', {});
    try {
      expect(await signRelayRequest(input())).toMatchObject({
        ok: false,
        reason: 'unsupported-signature',
      });
      expect(await deriveVerifier(KEY)).toMatchObject({
        ok: false,
        reason: 'unsupported-signature',
      });
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
