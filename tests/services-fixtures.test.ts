import { readFileSync } from 'node:fs';
import { readTimestampResponse, verifyTimestampToken } from '../src/lib/index.ts';
import { FREETSA_NONCE, fixture, sha256 } from './helpers.ts';

const anchor = (name: string): string =>
  readFileSync(new URL(`../anchors/${name}.pem`, import.meta.url), 'utf8');

// Real answers recorded on 2026-11-23 for the SHA-256 of "probe" and one fixed nonce, one per service.
const RECORDED = [
  { file: 'freetsa.tsr', anchor: 'freetsa-root', chain: 2, signer: 'CN=www.freetsa.org' },
  {
    file: 'sectigo.tsr',
    anchor: 'usertrust-rsa',
    chain: 4,
    signer: 'Sectigo Public Time Stamping Signer',
  },
  {
    file: 'digicert.tsr',
    anchor: 'digicert-trusted-root-g4',
    chain: 3,
    signer: 'DigiCert SHA256 RSA4096 Timestamp Responder',
  },
  {
    file: 'certum.tsr',
    anchor: 'certum-trusted-network-ca-2',
    chain: 3,
    signer: 'Certum Timestamp 2026',
  },
];

describe('recorded answers of four services', () => {
  for (const r of RECORDED) {
    it(`${r.file} verifies against its trust anchor`, async () => {
      const response = readTimestampResponse(fixture(r.file));
      expect(response.ok).toBe(true);
      if (!response.ok) return;
      const v = await verifyTimestampToken(
        response.value.token,
        sha256('probe'),
        [anchor(r.anchor)],
        {
          expectedNonce: FREETSA_NONCE,
        },
      );
      expect(v.ok).toBe(true);
      if (v.ok) {
        expect(v.value.signer).toContain(r.signer);
        expect(v.value.chainLength).toBe(r.chain);
        expect(v.value.genTime.startsWith('2026-11-23T')).toBe(true);
      }
    });
    it(`${r.file} is refused with another hash and with the anchor of another service`, async () => {
      const response = readTimestampResponse(fixture(r.file));
      if (!response.ok) throw new Error('unreadable');
      const other = RECORDED.find((x) => x.anchor !== r.anchor)!;
      const wrongHash = await verifyTimestampToken(response.value.token, sha256('other'), [
        anchor(r.anchor),
      ]);
      expect(wrongHash).toMatchObject({ ok: false, reason: 'imprint-mismatch' });
      const wrongAnchor = await verifyTimestampToken(response.value.token, sha256('probe'), [
        anchor(other.anchor),
      ]);
      expect(wrongAnchor).toMatchObject({ ok: false, reason: 'untrusted-chain' });
    });
  }
});
