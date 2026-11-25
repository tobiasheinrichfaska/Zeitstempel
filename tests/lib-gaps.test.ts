// Rules of the library that had no test of their own (audit of 2026-11-24, finding B2). Each test names the rule, the
// place in the code and the error code; each was shown to fail when the rule is taken out of the code.
import {
  parseCertificate,
  parsePemCertificates,
  readToken,
  verifyTimestampToken,
} from '../src/index.ts';
import type { Reason } from '../src/lib/index.ts';
import { fromBase64Url, toBase64Url } from '../src/lib/bytes.ts';
import { boolean, parseDer, tlv } from '../src/lib/der.ts';
import { build, octet, oidT, seq, set, type Opts } from './token-builder.ts';

async function reason(o: Opts = {}, options: object = {}): Promise<Reason | 'ok'> {
  const t = build(o);
  const r = await verifyTimestampToken(t.token, t.imprint, [t.caPem], options);
  return r.ok ? 'ok' : r.reason;
}
const readReason = (token: Uint8Array): string => {
  try {
    readToken(token);
    return 'ok';
  } catch (e) {
    return (e as { reason?: string }).reason ?? String(e);
  }
};
const ECDSA_SHA1 = '1.2.840.10045.4.1';
const SHA1 = '1.3.14.3.2.26';
const SHA256 = '2.16.840.1.101.3.4.2.1';
const SHA512 = '2.16.840.1.101.3.4.2.3';

describe('SHA-1 is no signature hash', () => {
  it('the signer signs the attributes with ecdsa-with-SHA1: unsupported-signature (verify.ts, verifyWithKey)', async () => {
    expect(await reason({})).toBe('ok');
    expect(await reason({ signatureAlg: { oid: ECDSA_SHA1, hash: 'sha1' } })).toBe(
      'unsupported-signature',
    );
  });
  it('an intermediate signed with ecdsa-with-SHA1 does not lead to the anchor: untrusted-chain', async () => {
    expect(await reason({ intermediate: {} })).toBe('ok');
    expect(await reason({ intermediate: { sha1Signed: true } })).toBe('untrusted-chain');
  });
});

describe('the imprint hash must be SHA-256 (verify.ts, unsupported-hash)', () => {
  const x = new Uint8Array(32).fill(7);
  const imprint = (oid: string, bytes: Uint8Array) => seq(seq(oidT(oid)), octet(bytes));
  it('a SHA-256 imprint of 32 bytes is fine; an unknown OID with the same 32 bytes is not', async () => {
    const t = build({ hash: x, tstImprintRaw: imprint(SHA256, x) });
    expect((await verifyTimestampToken(t.token, x, [t.caPem])).ok).toBe(true);
    const u = build({ hash: x, tstImprintRaw: imprint('1.2.3.4.5', x) });
    const r = await verifyTimestampToken(u.token, x, [u.caPem]);
    expect(r.ok ? 'ok' : r.reason).toBe('unsupported-hash');
  });
  it('a SHA-1 (20 bytes) or SHA-512 (64 bytes) imprint is unsupported-hash, not imprint-mismatch', async () => {
    for (const [oid, n] of [
      [SHA1, 20],
      [SHA512, 64],
    ] as const) {
      const h = new Uint8Array(n).fill(7);
      const t = build({ tstImprintRaw: imprint(oid, h) });
      const r = await verifyTimestampToken(t.token, x, [t.caPem]); // the caller's hash is 32 bytes
      expect(r.ok ? 'ok' : r.reason).toBe('unsupported-hash'); // not imprint-mismatch
    }
  });
});

describe('the signed attributes', () => {
  it('contentType must be id-ct-TSTInfo: bad-content-type (verify.ts)', async () => {
    expect(await reason({ contentTypeOid: '1.2.840.113549.1.7.1' })).toBe('bad-content-type'); // id-data
    expect(await reason({ contentTypeOid: '1.2.840.113549.1.9.16.1.4' })).toBe('ok');
  });
  it('an attribute twice is bad-structure, also for the reader (token.ts, readAttributes)', async () => {
    const dup = seq(oidT('1.2.840.113549.1.9.4'), set(octet(new Uint8Array(32))));
    expect(await reason({ extraSignedAttrs: [dup] })).toBe('bad-structure');
    expect(readReason(build({ extraSignedAttrs: [dup] }).token)).toBe('bad-structure');
    const ctDup = seq(oidT('1.2.840.113549.1.9.3'), set(oidT('1.2.840.113549.1.9.16.1.4')));
    expect(readReason(build({ extraSignedAttrs: [ctDup] }).token)).toBe('bad-structure');
  });
});

describe('SignedData and SignerInfo (token.ts)', () => {
  it('exactly one SignerInfo: none and two are one-signer-required', async () => {
    expect(readReason(build({}).token)).toBe('ok');
    expect(readReason(build({ signerInfoCount: 0 }).token)).toBe('one-signer-required');
    expect(readReason(build({ signerInfoCount: 2 }).token)).toBe('one-signer-required');
    expect(await reason({ signerInfoCount: 0 })).toBe('one-signer-required');
    expect(await reason({ signerInfoCount: 2 })).toBe('one-signer-required');
  });
  it('nothing after the SignerInfos in SignedData: bad-structure', async () => {
    expect(readReason(build({ sdExtra: [tlv(5, new Uint8Array())] }).token)).toBe('bad-structure');
    expect(readReason(build({ sdExtra: [set()] }).token)).toBe('bad-structure');
    expect(await reason({ sdExtra: [tlv(5, new Uint8Array())] })).toBe('bad-structure');
  });
});

describe('certificate: the algorithm inside and outside must be the same (x509.ts)', () => {
  const other = seq(oidT('1.2.840.10045.4.3.3')); // ecdsa-with-SHA384 inside, SHA256 outside
  it('parseCertificate refuses it as bad-certificate', () => {
    const ok = build({});
    expect(() => parseCertificate(ok.tsaCert)).not.toThrow();
    const bad = build({ tsaInnerSigAlg: other });
    expect(() => parseCertificate(bad.tsaCert)).toThrow(
      expect.objectContaining({ reason: 'bad-certificate' }),
    );
  });
  it('a trust anchor with differing algorithms is bad-certificate', async () => {
    const t = build({ caInnerSigAlg: other });
    expect(() => parsePemCertificates(t.caPem)).toThrow(
      expect.objectContaining({ reason: 'bad-certificate' }),
    );
    const r = await verifyTimestampToken(t.token, t.imprint, [t.caPem]);
    expect(r.ok ? 'ok' : r.reason).toBe('bad-certificate');
  });
  it('a signer certificate with differing algorithms is skipped: signer-certificate-missing', async () => {
    expect(await reason({ tsaInnerSigAlg: other })).toBe('signer-certificate-missing');
  });
});

describe('BOOLEAN is 00 or FF (der.ts)', () => {
  const node = (b: number[]) => parseDer(tlv(1, Uint8Array.from(b)));
  it('00 and FF are read, anything else (01, 80, FE) and a wrong length are malformed', () => {
    expect(boolean(node([0]))).toBe(false);
    expect(boolean(node([0xff]))).toBe(true);
    for (const b of [[1], [0x80], [0xfe]]) {
      expect(() => boolean(node(b))).toThrow(expect.objectContaining({ reason: 'malformed' }));
    }
    expect(() => boolean(node([]))).toThrow(expect.objectContaining({ reason: 'malformed' }));
    expect(() => boolean(node([0xff, 0xff]))).toThrow(
      expect.objectContaining({ reason: 'malformed' }),
    );
  });
  it('a critical flag 01 in a certificate makes it unreadable', () => {
    const flag = (v: number) =>
      build({
        extraTsaExts: [seq(oidT('2.5.29.19'), tlv(1, Uint8Array.of(v)), octet(seq()))],
      }).tsaCert;
    expect(() => parseCertificate(flag(0xff))).not.toThrow();
    expect(() => parseCertificate(flag(1))).toThrow(
      expect.objectContaining({ reason: 'malformed' }),
    );
  });
});

describe('base64url is canonical (bytes.ts)', () => {
  it('the spare bits of the last character must be zero', () => {
    expect(fromBase64Url('AA')).toEqual(Uint8Array.of(0));
    expect(fromBase64Url('AB')).toBeNull(); // would decode to the same byte
    expect(fromBase64Url('AAB')).toBeNull();
    expect(fromBase64Url('AAC')).toBeNull();
    expect(fromBase64Url('AAAB')).toEqual(Uint8Array.of(0, 0, 1));
  });
  it('what toBase64Url writes is read back, a length of 1 mod 4 and foreign characters are refused', () => {
    for (let n = 0; n < 12; n += 1) {
      const b = Uint8Array.from({ length: n }, (_, i) => (i * 37 + 250) & 255);
      expect(fromBase64Url(toBase64Url(b))).toEqual(b);
    }
    expect(fromBase64Url('A')).toBeNull();
    expect(fromBase64Url('AA==')).toBeNull();
    expect(fromBase64Url('A+')).toBeNull();
  });
});
