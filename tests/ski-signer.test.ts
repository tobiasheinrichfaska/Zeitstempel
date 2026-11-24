// F4: a signer named by `subjectKeyIdentifier` (SignerInfo version 3, RFC 5652 § 5.3) next to the one named by
// issuer and serial number (version 1). Every rule has a case here; the comparison with OpenSSL is in `openssl.test.ts`.
import {
  parseCertificate,
  readTimestampResponse,
  readToken,
  verifyTimestampToken,
} from '../src/lib/index.ts';
import type { Reason } from '../src/lib/index.ts';
import { ctx, tlv } from '../src/lib/der.ts';
import { build, ext, int, octet, seq, type Opts } from './token-builder.ts';
import { fixture } from './helpers.ts';

async function reason(o: Opts = {}, options: object = {}): Promise<Reason | 'ok'> {
  const t = build(o);
  const r = await verifyTimestampToken(t.token, t.imprint, [t.caPem], options);
  return r.ok ? 'ok' : r.reason;
}

const ski = (n: number, fill = 0x11) => new Uint8Array(n).fill(fill);
const SKI_OID = '2.5.29.14';

describe('F4: a signer named by subjectKeyIdentifier', () => {
  it('verifies, with the same result as the signer named by issuer and serial number', async () => {
    const first = build({ sid: 'ski' });
    const a = await verifyTimestampToken(first.token, first.imprint, [first.caPem]);
    expect(a.ok).toBe(true);
    const viaSerial = build({ keys: first.keys });
    const b = await verifyTimestampToken(viaSerial.token, viaSerial.imprint, [viaSerial.caPem]);
    expect(b).toEqual(a); // VerifiedTimestamp keeps its form
  });
  it('is read as version 3 with the key identifier; the form with issuer and serial as version 1', () => {
    const t = build({ sid: 'ski', tsaSki: ski(20, 0x42) });
    const sid = readToken(t.token).signer.sid;
    expect(sid.kind).toBe('subjectKeyIdentifier');
    if (sid.kind === 'subjectKeyIdentifier') expect([...sid.ski]).toEqual([...ski(20, 0x42)]);
    expect(readToken(build().token).signer.sid.kind).toBe('issuerAndSerialNumber');
    const cert = parseCertificate(t.tsaCert);
    expect([...cert.subjectKeyIdentifier!]).toEqual([...ski(20, 0x42)]);
    expect(parseCertificate(build().tsaCert).subjectKeyIdentifier).toBeNull();
  });
  it('the recorded answers of the four services are still read with issuer and serial number', () => {
    for (const f of ['freetsa.tsr', 'sectigo.tsr', 'digicert.tsr', 'certum.tsr']) {
      const r = readTimestampResponse(fixture(f));
      if (!r.ok) throw new Error(f);
      const token = readToken(r.value.token);
      expect(token.signer.sid.kind, f).toBe('issuerAndSerialNumber');
      expect(
        token.certificates.some((c) => c.subjectKeyIdentifier !== null),
        f,
      ).toBe(true);
    }
  });
  it('verifies below an intermediate, with an RSA signer, with the shortest and the longest identifier', async () => {
    expect(await reason({ sid: 'ski', intermediate: {} })).toBe('ok');
    expect(await reason({ sid: 'ski', rsa: { tsa: 2048 } })).toBe('ok');
    expect(await reason({ sid: 'ski', tsaSki: ski(1) })).toBe('ok');
    expect(await reason({ sid: 'ski', tsaSki: ski(64) })).toBe('ok');
  });
  it('keeps every other rule: a wrong key usage, a bad hash and an untrusted chain are still refused', async () => {
    expect(await reason({ sid: 'ski', ekuOids: ['1.3.6.1.5.5.7.3.1'] })).toBe('bad-eku');
    expect(await reason({ sid: 'ski', essCertId: { v2Hash: '1.3.14.3.2.26' } })).toBe(
      'unsupported-hash',
    );
    expect(
      await reason({ sid: 'ski', sigMangle: (s) => s.map((b, i) => (i === 10 ? b ^ 1 : b)) }),
    ).toBe('signature-invalid');
    expect(
      await reason({
        sid: 'ski',
        tsaValidity: ['20260102000000Z', '20400101000000Z'],
      }),
    ).toBe('certificate-not-valid-at-time');
    const t = build({ sid: 'ski' });
    const other = build({ sid: 'ski' }); // another root
    expect(await verifyTimestampToken(t.token, t.imprint, [other.caPem])).toEqual({
      ok: false,
      reason: 'untrusted-chain',
    });
  });

  describe('which certificate is the signer', () => {
    it('the identifier fits no certificate of the token: signer-certificate-missing', async () => {
      expect(await reason({ sid: 'ski', sidSki: ski(20, 0x99) })).toBe(
        'signer-certificate-missing',
      );
    });
    it('the whole identifier counts: one byte differing at the end, or a prefix, finds nothing', async () => {
      const id = ski(20, 0x21);
      const last = Uint8Array.from(id);
      last[19] = 0x22;
      expect(await reason({ sid: 'ski', tsaSki: id, sidSki: last })).toBe(
        'signer-certificate-missing',
      );
      expect(await reason({ sid: 'ski', tsaSki: id, sidSki: id.subarray(0, 19) })).toBe(
        'signer-certificate-missing',
      );
      expect(await reason({ sid: 'ski', tsaSki: id.subarray(0, 19), sidSki: id })).toBe(
        'signer-certificate-missing',
      );
    });
    it('the signer certificate has no subjectKeyIdentifier extension: never found, the identifier is not computed from the key', async () => {
      // the SignerInfo carries what a computed identifier would be (SHA-1 of the SPKI, as `build` makes it)
      const withExt = build({ sid: 'ski' });
      const wanted = readToken(withExt.token).signer.sid;
      if (wanted.kind !== 'subjectKeyIdentifier') throw new Error('test setup');
      expect(
        await reason({ sid: 'ski', tsaSki: null, sidSki: wanted.ski, keys: withExt.keys }),
      ).toBe('signer-certificate-missing');
      expect(await reason({ sid: 'ski', tsaSki: null })).toBe('signer-certificate-missing');
    });
    it('a certificate of the token with the same identifier but another key does not block the real one', async () => {
      const id = ski(20, 0x33);
      expect(await reason({ sid: 'ski', tsaSki: id, skiTwins: [{ wrongKey: true }] })).toBe('ok');
      expect(await reason({ sid: 'ski', tsaSki: id, skiTwins: [{}] })).toBe('ok'); // same key, other serial
      expect(
        await reason({
          sid: 'ski',
          tsaSki: id,
          skiTwins: [{ wrongKey: true }, {}, { wrongKey: true }],
        }),
      ).toBe('ok');
    });
    it('only look-alikes, no certificate the signingCertificate attribute names: signing-certificate-mismatch', async () => {
      const id = ski(20, 0x44);
      const stranger = build({ sid: 'ski', tsaSki: id }); // another key pair, same identifier
      expect(await reason({ sid: 'ski', tsaSki: id, tsaCertOverride: stranger.tsaCert })).toBe(
        'signing-certificate-mismatch',
      );
    });
    it('the right certificate is found at the limit of 16 certificates; the 17th is too-large', async () => {
      const id = ski(20, 0x55);
      expect(
        await reason({
          sid: 'ski',
          tsaSki: id,
          skiTwins: Array.from({ length: 14 }, () => ({ wrongKey: true })),
        }),
      ).toBe('ok');
      expect(
        await reason({
          sid: 'ski',
          tsaSki: id,
          skiTwins: Array.from({ length: 15 }, () => ({ wrongKey: true })),
        }),
      ).toBe('ok');
      expect(
        await reason({
          sid: 'ski',
          tsaSki: id,
          skiTwins: Array.from({ length: 16 }, () => ({ wrongKey: true })),
        }),
      ).toBe('too-large');
    });
    it('a look-alike that is a different certificate with the identifier of an intermediate does not become the signer', async () => {
      // the identifier names the intermediate's key identifier: no certificate of the token carries it as the signer's
      expect(await reason({ sid: 'ski', intermediate: {}, sidSki: ski(20, 0x01) })).toBe(
        'signer-certificate-missing',
      );
    });
  });

  describe('SignerInfo version and form belong together', () => {
    it('version 3 with issuer and serial number: unsupported-version', async () => {
      expect(await reason({ signerVersion: 3 })).toBe('unsupported-version');
    });
    it('version 1 with a key identifier: unsupported-version', async () => {
      expect(await reason({ sid: 'ski', signerVersion: 1 })).toBe('unsupported-version');
    });
    it('any other version, with either form: unsupported-version', async () => {
      for (const v of [0, 2, 4, 5, 127]) {
        expect(await reason({ signerVersion: v }), `issuer ${v}`).toBe('unsupported-version');
        expect(await reason({ sid: 'ski', signerVersion: v }), `ski ${v}`).toBe(
          'unsupported-version',
        );
      }
    });
    it('the SignedData version stays 3 for both forms (the content is a TSTInfo, not id-data): another number is refused', async () => {
      const patch = (t: Uint8Array) => {
        const a = Uint8Array.from(t);
        for (let i = 0; i < a.length - 2; i += 1) {
          if (a[i] === 2 && a[i + 1] === 1 && a[i + 2] === 3) {
            a[i + 2] = 1;
            break;
          }
        }
        return a;
      };
      const t = build({ sid: 'ski' });
      expect(await verifyTimestampToken(patch(t.token), t.imprint, [t.caPem])).toEqual({
        ok: false,
        reason: 'unsupported-version',
      });
    });
  });

  describe('the key identifier of the SignerInfo', () => {
    it('0 and 65 bytes: bad-structure; 1 and 64 bytes are fine', async () => {
      expect(await reason({ sid: 'ski', sidSki: ski(0) })).toBe('bad-structure');
      expect(await reason({ sid: 'ski', sidSki: ski(65) })).toBe('bad-structure');
      expect(await reason({ sid: 'ski', sidSki: ski(1), tsaSki: ski(1) })).toBe('ok');
      expect(await reason({ sid: 'ski', sidSki: ski(64), tsaSki: ski(64) })).toBe('ok');
      expect(() => readToken(build({ sid: 'ski', sidSki: ski(65) }).token)).toThrow();
    });
    it('only the primitive [0] is the identifier: constructed [0], OCTET STRING, [1], INTEGER, NULL are bad-structure; a SEQUENCE is the wrong form for version 3', async () => {
      const id = ski(20);
      for (const raw of [
        tlv(ctx(0), octet(id)), // constructed [0] (BER form of an OCTET STRING)
        octet(id), // universal OCTET STRING
        tlv(0x81, id), // [1]
        tlv(2, Uint8Array.of(1)),
        tlv(5, new Uint8Array()),
      ]) {
        expect(await reason({ sid: 'ski', sidRaw: raw })).toBe('bad-structure');
      }
      expect(await reason({ sid: 'ski', sidRaw: seq(seq(), int(1)) })).toBe('unsupported-version');
    });
  });

  describe('the subjectKeyIdentifier extension of a certificate', () => {
    const unreadable = async (o: Opts) => {
      const t = build({ sid: 'ski', sidSki: ski(20), ...o });
      expect(readToken(t.token).skippedCertificates).toBe(1);
      expect(() => parseCertificate(t.tsaCert)).toThrow();
      const r = await verifyTimestampToken(t.token, t.imprint, [t.caPem]);
      expect(r).toEqual({ ok: false, reason: 'signer-certificate-missing' });
    };
    it('twice in one certificate: the certificate is unreadable (skipped in a token, never a candidate)', async () => {
      await unreadable({ extraTsaExts: [ext(SKI_OID, false, octet(ski(20)))] });
    });
    it('empty, 65 bytes, not an OCTET STRING, trailing bytes: unreadable', async () => {
      await unreadable({ tsaSki: ski(0) });
      await unreadable({ tsaSki: ski(65) });
      await unreadable({ tsaSkiValueRaw: tlv(5, new Uint8Array()) });
      await unreadable({ tsaSkiValueRaw: seq(octet(ski(20))) });
      await unreadable({ tsaSkiValueRaw: Uint8Array.from([...octet(ski(20)), 0]) });
      await unreadable({ tsaSkiValueRaw: new Uint8Array() });
    });
    it('an unreadable one in a trust anchor is bad-certificate for the whole input', () => {
      const t = build({ caExts: [ext(SKI_OID, false, tlv(5, new Uint8Array()))] });
      expect(() =>
        parseCertificate(Uint8Array.from(atob(t.caPem.split('\n')[1]!), (c) => c.charCodeAt(0))),
      ).toThrow();
    });
    it('marked critical it still counts (RFC 5280 wants it non-critical; a verifier need not refuse it)', async () => {
      expect(await reason({ sid: 'ski', tsaSkiCritical: true })).toBe('ok');
    });
    it('a certificate of the token with the extension, but not the signer, is no candidate', async () => {
      const t = build({ sid: 'ski', tsaSki: ski(20, 0x77), intermediate: {} });
      const certs = readToken(t.token).certificates;
      expect(certs.filter((c) => c.subjectKeyIdentifier !== null)).toHaveLength(1);
    });
  });

  describe('hostile input', () => {
    it('flipping any byte of the SignerInfo never throws and never verifies', async () => {
      const t = build({ sid: 'ski' });
      const start = t.token.length - 160;
      for (let i = start; i < t.token.length; i += 1) {
        const bad = Uint8Array.from(t.token);
        bad[i] = bad[i]! ^ 0xff;
        const r = await verifyTimestampToken(bad, t.imprint, [t.caPem]);
        expect(r.ok, `byte ${i}`).toBe(false);
      }
    });
    it('every truncation is refused with a reason', async () => {
      const t = build({ sid: 'ski' });
      for (let n = 0; n < t.token.length; n += 7) {
        const r = await verifyTimestampToken(t.token.subarray(0, n), t.imprint, [t.caPem]);
        expect(r.ok).toBe(false);
      }
    });
    it('a token in a SharedArrayBuffer with a key identifier verifies', async () => {
      const t = build({ sid: 'ski' });
      const shared = new Uint8Array(new SharedArrayBuffer(t.token.length));
      shared.set(t.token);
      expect((await verifyTimestampToken(shared, t.imprint, [t.caPem])).ok).toBe(true);
    });
    it('readToken only throws ReaderError for hostile identifiers', () => {
      for (const sidRaw of [
        tlv(0x80, ski(0)),
        tlv(0x80, ski(65)),
        tlv(ctx(0), int(1)),
        tlv(0x80, ski(20)),
      ]) {
        try {
          readToken(build({ sid: 'ski', sidRaw }).token);
        } catch (e) {
          expect((e as { reason?: string }).reason).toMatch(/./);
        }
      }
    });
  });
});
