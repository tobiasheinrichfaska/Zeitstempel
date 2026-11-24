// F3: `minRsaBits` (default 2048): an RSA key below it is `weak-key` for the signer and for every certificate of
// the chain; trust anchors are exempt (the caller chose them). `openssl ts -verify` accepts such keys (see
// tests/openssl.test.ts), so this is a deliberate difference.
import { verifyTimestampToken, parseCertificate } from '../src/lib/index.ts';
import type { Reason } from '../src/lib/index.ts';
import { rsaModulusBits } from '../src/lib/x509.ts';
import { build, type Opts } from './token-builder.ts';

async function reason(o: Opts = {}, options: object = {}, anchor?: 'tsa'): Promise<Reason | 'ok'> {
  const t = build(o);
  const r = await verifyTimestampToken(
    t.token,
    t.imprint,
    [anchor === 'tsa' ? t.tsaPem : t.caPem],
    options,
  );
  return r.ok ? 'ok' : r.reason;
}

describe('F3: minRsaBits for the signer', () => {
  it('RSA 2048 passes by default, RSA 1024 and 512 are weak-key', async () => {
    expect(await reason({ rsa: { tsa: 2048 } })).toBe('ok');
    expect(await reason({ rsa: { tsa: 1024 } })).toBe('weak-key');
    expect(await reason({ rsa: { tsa: 512 } })).toBe('weak-key'); // refused before the platform is asked to import it
  });
  it('the limit is the option: 0 switches the rule off, 1024 lets 1024 pass, 4096 refuses 2048', async () => {
    expect(await reason({ rsa: { tsa: 1024 } }, { minRsaBits: 0 })).toBe('ok');
    expect(await reason({ rsa: { tsa: 1024 } }, { minRsaBits: 1024 })).toBe('ok');
    expect(await reason({ rsa: { tsa: 1024 } }, { minRsaBits: 1025 })).toBe('weak-key');
    expect(await reason({ rsa: { tsa: 2048 } }, { minRsaBits: 4096 })).toBe('weak-key');
    expect(await reason({ rsa: { tsa: 2048 } }, { minRsaBits: 2048 })).toBe('ok');
  });
  it('an elliptic curve key is never judged by it', async () => {
    expect(await reason({}, { minRsaBits: 100000 })).toBe('ok');
  });
  it('a signer the caller trusts as an anchor is exempt', async () => {
    expect(await reason({ rsa: { tsa: 1024 } }, {}, 'tsa')).toBe('ok');
  });
});

describe('F3: minRsaBits for the chain', () => {
  it('a weak intermediate is weak-key, with the rule off the chain is fine', async () => {
    expect(await reason({ intermediate: {}, rsa: { int: 1024 } })).toBe('weak-key');
    expect(await reason({ intermediate: {}, rsa: { int: 1024 } }, { minRsaBits: 0 })).toBe('ok');
    expect(await reason({ intermediate: {}, rsa: { int: 2048 } })).toBe('ok');
  });
  it('a weak intermediate does not hide behind a strong signer, nor a strong one next to it', async () => {
    expect(await reason({ intermediate: {}, rsa: { int: 2048, tsa: 1024 } })).toBe('weak-key');
  });
  it('a weak root given as the trust anchor is exempt (the caller chose it)', async () => {
    expect(await reason({ rsa: { ca: 1024 } })).toBe('ok');
    expect(await reason({ rsa: { ca: 1024, tsa: 2048 }, intermediate: {} })).toBe('ok');
  });
  it('a weak intermediate given as the anchor is exempt', async () => {
    const t = build({ intermediate: {}, rsa: { int: 1024 } });
    const asAnchor = await verifyTimestampToken(t.token, t.imprint, [t.intPem], {});
    expect(asAnchor.ok).toBe(true);
  });
});

describe('F3: the option is checked', () => {
  it('a number >= 0 is accepted, anything else is bad-options (never a silently skipped rule)', async () => {
    for (const ok of [0, 1, 2048, 3072, 8192, 2047.5]) {
      expect(await reason({}, { minRsaBits: ok }), String(ok)).toBe('ok');
    }
    for (const bad of [-1, NaN, Infinity, -Infinity, '2048', null, true, {}, [], 2048n]) {
      expect(await reason({}, { minRsaBits: bad }), String(bad)).toBe('bad-options');
    }
    expect(await reason({}, { minRsaBits: undefined })).toBe('ok');
  });
  it('an inherited minRsaBits (prototype pollution) does not count', async () => {
    (Object.prototype as Record<string, unknown>).minRsaBits = 0;
    try {
      expect(await reason({ rsa: { tsa: 1024 } })).toBe('weak-key');
    } finally {
      delete (Object.prototype as Record<string, unknown>).minRsaBits;
    }
  });
});

describe('the modulus size is counted in bits', () => {
  it('RSA 1024, 2048; null for an elliptic curve key', () => {
    expect(rsaModulusBits(parseCertificate(build({ rsa: { tsa: 1024 } }).tsaCert))).toBe(1024);
    expect(rsaModulusBits(parseCertificate(build({ rsa: { tsa: 2048 } }).tsaCert))).toBe(2048);
    expect(rsaModulusBits(parseCertificate(build().tsaCert))).toBeNull();
  });
});
