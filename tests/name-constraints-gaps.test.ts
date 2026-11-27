// Name constraints, audit 14: the cases that a mutant of the matching rules survived before (a mailbox's local part
// and host length, a URI with one slash, a base with a leading dot, the 256 names after the commonName, the content of
// a subtree that is not evaluated) and the order of the refusals on one path (name constraint before revocation).
import { verifyTimestampToken } from '../src/index.ts';
import type { Reason } from '../src/lib/index.ts';
import { tlv } from '../src/lib/der.ts';
import { parseNameConstraints } from '../src/lib/nameconstraints.ts';
import { buildCrl } from './crl-builder.ts';
import { CN, dn, gnDns, gnEmail, gnUri, nc, san, sub } from './nc-builder.ts';
import { build, seq, type Opts } from './token-builder.ts';

const V = 'name-constraint-violation';
const P = (...b: Uint8Array[]) => nc({ permitted: b.map((x) => sub(x)) });
const X = (...b: Uint8Array[]) => nc({ excluded: b.map((x) => sub(x)) });
async function reason(o: Opts): Promise<Reason | 'ok'> {
  const t = build(o);
  const r = await verifyTimestampToken(t.token, t.imprint, [t.caPem]);
  return r.ok ? 'ok' : r.reason;
}
const withSan = (ca: Uint8Array, ...names: Uint8Array[]): Opts => ({
  caExts: [ca],
  extraTsaExts: [san(...names)],
});

describe('rfc822Name: local part and host are compared whole', () => {
  it('the local part of a base with @ must have the same length', async () => {
    expect(await reason(withSan(P(gnEmail('b@example.com')), gnEmail('b@example.com')))).toBe('ok');
    expect(await reason(withSan(P(gnEmail('b@example.com')), gnEmail('bx@example.com')))).toBe(V);
    expect(await reason(withSan(P(gnEmail('bx@example.com')), gnEmail('b@example.com')))).toBe(V);
    expect(await reason(withSan(X(gnEmail('b@example.com')), gnEmail('bx@example.com')))).toBe(
      'ok',
    );
    expect(await reason(withSan(X(gnEmail('b@example.com')), gnEmail('b@example.com')))).toBe(V);
  });
  it('the host must have the same length as the base host (no prefix match)', async () => {
    expect(await reason(withSan(P(gnEmail('example.com')), gnEmail('a@example.com')))).toBe('ok');
    expect(await reason(withSan(P(gnEmail('example.com')), gnEmail('a@example.com.evil')))).toBe(V);
    expect(await reason(withSan(X(gnEmail('example.com')), gnEmail('a@example.com.evil')))).toBe(
      'ok',
    );
    expect(await reason(withSan(P(gnEmail('b@example.com')), gnEmail('b@example.com.evil')))).toBe(
      V,
    );
  });
});

describe('uniformResourceIdentifier: the form and the base with a leading dot', () => {
  it('only `://` starts the authority: one slash or none is a form error, also under an exclusion', async () => {
    expect(await reason(withSan(P(gnUri('example.com')), gnUri('https://example.com/')))).toBe(
      'ok',
    );
    expect(await reason(withSan(P(gnUri('example.com')), gnUri('https:/xexample.com/')))).toBe(V);
    expect(await reason(withSan(P(gnUri('example.com')), gnUri('https:x/example.com/')))).toBe(V);
    expect(await reason(withSan(X(gnUri('evil.com')), gnUri('https:/xevil.com/')))).toBe(V);
    expect(await reason(withSan(X(gnUri('evil.com')), gnUri('https://example.com/')))).toBe('ok');
  });
  it('a base with a leading dot matches hosts below it, not an empty label', async () => {
    expect(await reason(withSan(P(gnUri('.example.com')), gnUri('https://a.example.com/')))).toBe(
      'ok',
    );
    expect(await reason(withSan(P(gnUri('.example.com')), gnUri('https://.example.com/')))).toBe(V);
    expect(await reason(withSan(X(gnUri('.example.com')), gnUri('https://.example.com/')))).toBe(
      'ok',
    );
    expect(await reason(withSan(P(gnUri('.example.com')), gnUri('https://example.com/')))).toBe(V);
  });
  it('the same for a mailbox: a base with a leading dot needs a host below it', async () => {
    expect(await reason(withSan(P(gnEmail('.example.com')), gnEmail('a@b.example.com')))).toBe(
      'ok',
    );
    expect(await reason(withSan(P(gnEmail('.example.com')), gnEmail('a@.example.com')))).toBe('ok');
    expect(await reason(withSan(P(gnEmail('.example.com')), gnEmail('a@example.com')))).toBe(V);
  });
});

describe('the limit of 256 names counts the commonName that is read as a host name', () => {
  const mails = (n: number) => Array.from({ length: n }, (_, i) => gnEmail(`a${i}@example.com`));
  const both = P(gnDns('example.com'), gnEmail('example.com'));
  it('255 entries and the commonName are 256 names, 256 entries and the commonName are 257', async () => {
    const o = (n: number): Opts => ({
      caExts: [both],
      extraTsaExts: [san(...mails(n))],
      tsaSubject: dn(CN('a.example.com')),
    });
    expect(await reason(o(255))).toBe('ok');
    expect(await reason(o(256))).toBe('bad-certificate');
  });
  it('without a host-like commonName 256 entries are still fine', async () => {
    expect(await reason({ caExts: [both], extraTsaExts: [san(...mails(256))] })).toBe('ok');
  });
  it('a commonName that is no host name does not count', async () => {
    expect(
      await reason({
        caExts: [both],
        extraTsaExts: [san(...mails(256))],
        tsaSubject: dn(CN('TSA')),
      }),
    ).toBe('ok');
  });
});

describe('a subtree of a form that is not evaluated is still read', () => {
  const broken = (tag: number) => seq(tlv(tag, Uint8Array.of(0x04, 0x09, 0x01)));
  const wrap = (...subtrees: Uint8Array[]) => seq(tlv(0xa0, ...subtrees));
  it('an otherName, x400Address or ediPartyName with a cut-off content: bad-certificate', () => {
    for (const tag of [0xa0, 0xa3, 0xa5]) {
      expect(() => parseNameConstraints(wrap(broken(tag))), `tag ${tag}`).toThrow();
    }
  });
  it('a well-formed one is read and marked, a registeredID needs no look inside', () => {
    const fine = parseNameConstraints(wrap(seq(tlv(0xa0, tlv(0x06, Uint8Array.of(0x2a, 3, 4))))));
    expect(fine.unsupported).toBe(true);
    expect(parseNameConstraints(wrap(seq(tlv(0x88, Uint8Array.of(0x2a, 3))))).unsupported).toBe(
      true,
    );
  });
  it('in a certificate of the chain it makes the chain unusable', async () => {
    const bad = nc({ permitted: [seq(tlv(0xa0, Uint8Array.of(0x04, 0x09, 0x01)))] });
    expect(await reason({ caExts: [bad] })).toBe('bad-certificate');
  });
});

describe('order of the refusals on one path', () => {
  it('a name constraint violation comes before a revocation of the same path', async () => {
    const t = build({
      intermediate: { extraExts: [X(gnDns('example.com'))] },
      crlSign: true,
      extraTsaExts: [san(gnDns('a.example.com'))],
    });
    const crl = buildCrl({
      key: t.midKeys,
      issuer: 'INT',
      entries: [{ serial: 7, date: '20251210000000Z' }],
    });
    const run = async (crls?: Uint8Array[]) => {
      const r = await verifyTimestampToken(t.token, t.imprint, [t.caPem], { crls } as never);
      return r.ok ? 'ok' : r.reason;
    };
    expect(await run([crl])).toBe(V);
    // the revocation alone is found when the name is fine
    const fine = build({ intermediate: {}, crlSign: true });
    const r = await verifyTimestampToken(fine.token, fine.imprint, [fine.caPem], {
      crls: [
        buildCrl({
          key: fine.midKeys,
          issuer: 'INT',
          entries: [{ serial: 7, date: '20251210000000Z' }],
        }),
      ],
    });
    expect(r.ok ? 'ok' : r.reason).toBe('revoked');
  });
});
