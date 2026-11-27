// Name constraints (RFC 5280 § 4.2.1.10): every row of `name-constraints-rows.ts` against `openssl ts -verify` (3.0.13,
// a visible skip without OpenSSL 3) and against this library; the strict reader with hostile input; the chain search.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ReaderError, parseCertificate, verifyTimestampToken } from '../src/index.ts';
import type { Reason } from '../src/lib/index.ts';
import { sameName } from '../src/lib/x509.ts';
import { parseNameConstraints } from '../src/lib/nameconstraints.ts';
import { encodeOid, tlv } from '../src/lib/der.ts';
import { build, ext, seq, type Opts } from './token-builder.ts';
import { ROWS as ROWS_A } from './name-constraints-rows.ts';
import { ROWS14 } from './name-constraints-rows14.ts';
import {
  C,
  CN,
  dn,
  gnDir,
  gnDns,
  gnEmail,
  gnIp,
  gnOther,
  gnUri,
  nc,
  san,
  sub,
} from './nc-builder.ts';

const ROWS = [...ROWS_A, ...ROWS14];

const probe = spawnSync('openssl', ['version'], { encoding: 'utf8' });
const major = Number(/^OpenSSL (\d+)/.exec(probe.stdout ?? '')?.[1] ?? 0);
const canCompare = probe.status === 0 && major >= 3;
const ATTIME = '1767225600'; // 2026-01-01T00:00:00Z, the genTime of the builder's tokens

let tmp = '';
beforeAll(() => {
  tmp = mkdtempSync(join(tmpdir(), 'zeitstempel-nc-'));
});
afterAll(() => {
  if (tmp) rmSync(tmp, { recursive: true, force: true });
});

function opensslAccepts(t: ReturnType<typeof build>): boolean {
  writeFileSync(join(tmp, 'row.tok'), t.token);
  writeFileSync(join(tmp, 'row.ca.pem'), t.caPem);
  const r = spawnSync(
    'openssl',
    [
      'ts',
      '-verify',
      '-in',
      join(tmp, 'row.tok'),
      '-token_in',
      '-digest',
      Buffer.from(t.imprint).toString('hex'),
      '-CAfile',
      join(tmp, 'row.ca.pem'),
      '-attime',
      ATTIME,
    ],
    { encoding: 'utf8' },
  );
  return r.status === 0;
}

async function ours(t: ReturnType<typeof build>, trust?: string[]): Promise<Reason | 'ok'> {
  const r = await verifyTimestampToken(t.token, t.imprint, trust ?? [t.caPem]);
  return r.ok ? 'ok' : r.reason;
}
const reason = (o: Opts) => ours(build(o));
const dns = (s: string) => [san(gnDns(s))];
const P = (...b: Uint8Array[]) => nc({ permitted: b.map((x) => sub(x)) });
const X = (...b: Uint8Array[]) => nc({ excluded: b.map((x) => sub(x)) });

describe('name constraints: the rows', () => {
  it('has at least 40 rows, every kind of name, a constraint at every level', () => {
    expect(ROWS.length).toBeGreaterThanOrEqual(40);
    const labels = ROWS.map((r) => r.label.split(':')[0]);
    for (const kind of [
      'dns',
      'cn',
      'email',
      'uri',
      'ip',
      'dir',
      'other',
      'ext',
      'level',
      'self-issued',
    ]) {
      expect(labels).toContain(kind);
    }
  });

  for (const row of ROWS) {
    if (row.openssl !== null) {
      it.skipIf(!canCompare)(`openssl: ${row.label}`, () => {
        expect(opensslAccepts(build(row.opts))).toBe(row.openssl);
      });
    }
    it(`ours: ${row.label}`, async () => {
      expect(await reason(row.opts)).toBe(row.ours);
    });
  }

  it('where ours differs from OpenSSL the row names its line in the table of docs/grenzen.md', () => {
    const doc = readFileSync(new URL('../docs/grenzen.md', import.meta.url), 'utf8');
    for (const row of ROWS) {
      const same = row.openssl === null ? true : row.openssl === (row.ours === 'ok');
      if (!same) expect(row.f, row.label).toBeDefined();
      if (row.f) expect(doc, row.label).toMatch(new RegExp(`\\|\\s*${row.f}\\s*\\|`));
    }
  });
});

describe('name constraints: the chain search', () => {
  it('another path can still be fine: a look-alike intermediate with an excluded subtree does not block the real one', async () => {
    const t = build({
      intermediate: {},
      twins: [{ extraExts: [X(gnDns('example.com'))] }],
      extraTsaExts: dns('a.example.com'),
    });
    expect(await ours(t)).toBe('ok');
  });
  it('the only usable intermediate carries the constraint: violation', async () => {
    const t = build({
      intermediate: { extraExts: [X(gnDns('example.com'))] },
      extraTsaExts: dns('a.example.com'),
    });
    expect(await ours(t)).toBe('name-constraint-violation');
  });
  it('an intermediate given as the trust anchor: its constraints apply to the signer', async () => {
    const t = build({
      intermediate: { extraExts: [P(gnDns('example.com'))] },
      extraTsaExts: dns('evil.com'),
    });
    expect(await ours(t, [t.intPem])).toBe('name-constraint-violation');
    const u = build({
      intermediate: { extraExts: [P(gnDns('example.com'))] },
      extraTsaExts: dns('a.example.com'),
    });
    expect(await ours(u, [u.intPem])).toBe('ok');
  });
  it('no constraint anywhere: nothing changes (names are not looked at)', async () => {
    expect(await reason({ extraTsaExts: [san(gnDns('anything.example'), gnEmail('x'))] })).toBe(
      'ok',
    );
  });
  it('a critical nameConstraints is no longer an unknown critical extension, a critical unknown one still is', async () => {
    expect(
      await reason({
        intermediate: { extraExts: [P(gnDns('example.com'))] },
        extraTsaExts: dns('a.example.com'),
      }),
    ).toBe('ok');
    expect(
      await reason({
        intermediate: { extraExts: [ext('2.5.29.99', true, seq())] },
        extraTsaExts: dns('a.example.com'),
      }),
    ).toBe('bad-certificate');
  });
  it('the constraint of an anchor without cA still works as the caller chose it (anchor is exempt from the checks)', async () => {
    // the anchor's own names are never checked against its own constraint
    expect(
      await reason({ caExts: [P(gnDir(dn(C('FR'))))], tsaSubject: dn(C('FR'), CN('TSA')) }),
    ).toBe('ok');
  });
  it('the signer is the trust anchor itself: its own constraints are not applied to it', async () => {
    const t = build({ extraTsaExts: [P(gnDns('example.com')), ...dns('evil.com')] });
    expect(await ours(t, [t.tsaPem])).toBe('ok');
  });
  it('the reason is a library reason: documented and known to the client', () => {
    const r: Reason = 'name-constraint-violation';
    expect(r).toBe('name-constraint-violation');
  });
});

describe('name constraints: the strict reader (parseNameConstraints)', () => {
  const body = (...parts: Uint8Array[]) => seq(...parts);
  const read = (der: Uint8Array) => parseNameConstraints(der);
  const bad = (der: Uint8Array) => {
    let caught: unknown;
    try {
      read(der);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ReaderError);
    expect((caught as ReaderError).reason).toBe('bad-certificate');
  };
  const permitted = (...subs: Uint8Array[]) => tlv(0xa0, ...subs);
  const excluded = (...subs: Uint8Array[]) => tlv(0xa1, ...subs);

  it('reads a normal extension', () => {
    const r = read(
      body(permitted(sub(gnDns('example.com'))), excluded(sub(gnEmail('a.example.com')))),
    );
    expect(r.permitted).toHaveLength(1);
    expect(r.excluded).toHaveLength(1);
    expect(r.unsupported).toBe(false);
  });
  it('marks a subtree of a form it does not evaluate', () => {
    const r = read(body(permitted(sub(gnOther()), sub(gnDns('example.com')))));
    expect(r.unsupported).toBe(true);
    expect(r.permitted).toHaveLength(1);
  });
  it('refuses the empty extension, an empty list, a wrong order, extra elements and other tags', () => {
    bad(body());
    bad(body(permitted()));
    bad(body(excluded()));
    bad(body(excluded(sub(gnDns('a.com'))), permitted(sub(gnDns('b.com')))));
    bad(body(permitted(sub(gnDns('a.com'))), permitted(sub(gnDns('b.com')))));
    bad(body(permitted(sub(gnDns('a.com'))), tlv(0xa2, sub(gnDns('b.com')))));
    bad(body(permitted(sub(gnDns('a.com'))), tlv(2, Uint8Array.of(1))));
    bad(tlv(0x31, permitted(sub(gnDns('a.com')))));
    bad(tlv(4, Uint8Array.of(1)));
  });
  it('refuses a subtree with minimum or maximum, a duplicate, a wrong order and extras', () => {
    bad(body(permitted(sub(gnDns('a.com'), 1))));
    bad(body(permitted(sub(gnDns('a.com'), 0))));
    bad(body(permitted(sub(gnDns('a.com'), undefined, 0))));
    bad(body(permitted(sub(gnDns('a.com'), undefined, 5))));
    bad(
      body(
        permitted(seq(gnDns('a.com'), tlv(0x81, Uint8Array.of(1)), tlv(0x80, Uint8Array.of(1)))),
      ),
    );
    bad(body(permitted(seq(gnDns('a.com'), tlv(2, Uint8Array.of(0))))));
    bad(body(permitted(seq())));
    bad(body(permitted(seq(tlv(2, Uint8Array.of(1))))));
    bad(body(permitted(tlv(4, Uint8Array.of(1)))));
  });
  it('refuses a base of a form that does not exist and bad bases of known forms', () => {
    bad(body(permitted(seq(tlv(0x89, Uint8Array.of(1))))));
    bad(body(permitted(seq(tlv(0x80 | 0x1f, Uint8Array.of(1))))));
    bad(body(permitted(sub(tlv(0x82, Uint8Array.of(0x61, 0xe9, 0x62)))))); // not ASCII
    bad(body(permitted(sub(tlv(0x81, Uint8Array.of(0x80))))));
    bad(body(permitted(sub(tlv(0x86, Uint8Array.of(0xff))))));
    bad(body(permitted(sub(tlv(0xa4, Uint8Array.of(1, 2))))));
    bad(body(permitted(sub(tlv(0xa4, seq(seq()))))));
    bad(body(permitted(sub(tlv(0xa4, tlv(0x31)))))); // not a name
    bad(body(permitted(sub(tlv(0xa4, dn(C('DE')), dn(C('DE')))))));
    bad(body(permitted(sub(tlv(0xa4)))));
  });
  it('refuses an address of the wrong length or with a mask that is no prefix, an address with host bits', () => {
    for (const n of [0, 1, 4, 5, 7, 9, 12, 16, 17, 31, 33]) {
      bad(body(permitted(sub(tlv(0x87, new Uint8Array(n))))));
    }
    bad(body(permitted(sub(gnIp(10, 0, 0, 0, 255, 0, 255, 0)))));
    bad(body(permitted(sub(gnIp(10, 0, 0, 0, 0, 255, 255, 255)))));
    expect(() => read(body(permitted(sub(gnIp(10, 0, 0, 0, 255, 0, 0, 0)))))).not.toThrow();
    expect(() => read(body(permitted(sub(gnIp(10, 0, 0, 0, 255, 255, 255, 254)))))).not.toThrow(); // /31
    bad(body(permitted(sub(gnIp(10, 0, 0, 0, 255, 255, 0, 255)))));
    expect(() => read(body(permitted(sub(gnIp(10, 0, 0, 2, 255, 255, 255, 254)))))).not.toThrow();
    expect(() => read(body(permitted(sub(gnIp(...Array<number>(32).fill(0))))))).not.toThrow();
  });
  it('bounds the number of subtrees (64 per list) and the length of a base', () => {
    const many = (n: number) =>
      Array.from({ length: n }, (_, i) => sub(gnDns(`h${i}.example.com`)));
    expect(() => read(body(permitted(...many(64)), excluded(...many(64))))).not.toThrow();
    bad(body(permitted(...many(65))));
    bad(body(excluded(...many(65))));
    expect(() => read(body(permitted(sub(gnDns('a'.repeat(253))))))).not.toThrow();
    bad(body(permitted(sub(gnDns('a'.repeat(254))))));
    bad(body(permitted(sub(gnEmail('a'.repeat(300))))));
    bad(body(permitted(sub(gnUri('a'.repeat(300))))));
  });
  it('refuses lengths that lie and bytes that trail', () => {
    const good = body(permitted(sub(gnDns('example.com'))));
    for (let cut = 1; cut < good.length; cut += 1) bad(good.subarray(0, cut));
    bad(Uint8Array.of(...good, 0));
    const lie = Uint8Array.from(good);
    lie[1] = lie[1]! + 5; // the outer length is larger than the bytes
    bad(lie);
    bad(Uint8Array.of(0x30, 0x84, 0xff, 0xff, 0xff, 0xff));
    bad(Uint8Array.of(0x30, 0x80, 0x00, 0x00)); // indefinite length
    bad(new Uint8Array(0));
  });
  it('refuses a deeply nested directory name base and many nested layers without crashing', () => {
    let deep: Uint8Array = Uint8Array.of(0x30, 0);
    for (let i = 0; i < 200; i += 1) deep = tlv(0x30, deep);
    bad(body(permitted(sub(tlv(0xa4, deep)))));
    let nest: Uint8Array = dn(C('DE'));
    for (let i = 0; i < 100; i += 1) nest = tlv(0xa0, nest);
    bad(body(permitted(sub(nest))));
  });
  it('never throws anything but a ReaderError, whatever the bytes are', () => {
    const seeds = [
      body(permitted(sub(gnDns('a.com')))),
      body(excluded(sub(gnIp(1, 2, 3, 4, 255, 255, 255, 255)))),
      body(permitted(sub(gnDir(dn(C('DE')))))),
    ];
    for (const seed of seeds) {
      for (let i = 0; i < seed.length; i += 1) {
        for (const v of [0x00, 0xff, 0x30, 0x80, 0x7f]) {
          const m = Uint8Array.from(seed);
          m[i] = v;
          try {
            read(m);
          } catch (e) {
            expect(e).toBeInstanceOf(ReaderError);
          }
        }
      }
    }
  });
});

describe('name constraints: hostile certificates and many names', () => {
  it('an unreadable extension in a chain certificate: bad-certificate (no violation, no ok)', async () => {
    const bogus = ext('2.5.29.30', true, tlv(4, Uint8Array.of(1, 2, 3)));
    expect(await reason({ caExts: [bogus], extraTsaExts: dns('a.example.com') })).toBe(
      'bad-certificate',
    );
    expect(
      await reason({ intermediate: { extraExts: [bogus] }, extraTsaExts: dns('a.example.com') }),
    ).toBe('bad-certificate');
  });
  it('an unreadable nameConstraints in the signer itself is ignored (only certificates above are read)', async () => {
    const bogus = ext('2.5.29.30', true, tlv(4, Uint8Array.of(1, 2, 3)));
    expect(
      await reason({
        caExts: [P(gnDns('example.com'))],
        extraTsaExts: [bogus, ...dns('a.example.com')],
      }),
    ).toBe('ok');
  });
  it('an empty SAN under a constraint is unreadable (bad-certificate); without a constraint it stays unread', async () => {
    const emptySan = ext('2.5.29.17', false, seq());
    expect(await reason({ caExts: [P(gnDns('example.com'))], extraTsaExts: [emptySan] })).toBe(
      'bad-certificate',
    );
    expect(await reason({ extraTsaExts: [emptySan] })).toBe('ok');
  });
  it('a SAN entry that is cut off under a constraint: bad-certificate', async () => {
    const cut = ext(
      '2.5.29.17',
      false,
      Uint8Array.of(0x30, 0x05, 0x82, 0x09, 0x61), // the length of the name lies
    );
    expect(await reason({ caExts: [P(gnDns('example.com'))], extraTsaExts: [cut] })).toBe(
      'bad-certificate',
    );
  });
  it('up to 256 names of the signer are checked, 257 are too many (bad-certificate), only under a constraint', async () => {
    const names = (n: number) => Array.from({ length: n }, (_, i) => gnDns(`h${i}.example.com`));
    expect(
      await reason({ caExts: [P(gnDns('example.com'))], extraTsaExts: [san(...names(256))] }),
    ).toBe('ok');
    expect(
      await reason({ caExts: [P(gnDns('example.com'))], extraTsaExts: [san(...names(257))] }),
    ).toBe('bad-certificate');
    expect(await reason({ extraTsaExts: [san(...names(257))] })).toBe('ok');
  });
  it('one bad name among many is found', async () => {
    const names = [
      ...Array.from({ length: 200 }, (_, i) => gnDns(`h${i}.example.com`)),
      gnDns('evil.com'),
    ];
    expect(await reason({ caExts: [P(gnDns('example.com'))], extraTsaExts: [san(...names)] })).toBe(
      'name-constraint-violation',
    );
  });
  it('64 permitted and 64 excluded subtrees with 256 names stay quick', async () => {
    const many = Array.from({ length: 64 }, (_, i) => sub(gnDns(`z${i}.net`)));
    const t = build({
      caExts: [
        nc({ permitted: [...many.slice(0, 63), sub(gnDns('example.com'))], excluded: many }),
      ],
      extraTsaExts: [san(...Array.from({ length: 256 }, (_, i) => gnDns(`h${i}.example.com`)))],
    });
    const start = Date.now();
    expect(await ours(t)).toBe('ok');
    expect(Date.now() - start).toBeLessThan(5000);
  });
  it('a signer name that is not text is no crash (high bytes in a dNSName under a constraint)', async () => {
    const odd = ext('2.5.29.17', false, seq(tlv(0x82, Uint8Array.of(0xff, 0xfe, 0x2e, 0x63))));
    const r = await reason({ caExts: [P(gnDns('example.com'))], extraTsaExts: [odd] });
    expect(['name-constraint-violation', 'bad-certificate']).toContain(r);
  });
  it('an embedded NUL in a name does not match a constraint (no truncation at the NUL)', async () => {
    const nul = ext(
      '2.5.29.17',
      false,
      seq(
        tlv(
          0x82,
          Uint8Array.of(
            ...new TextEncoder().encode('evil.com'),
            0,
            ...new TextEncoder().encode('.example.com'),
          ),
        ),
      ),
    );
    const r = await reason({ caExts: [X(gnDns('evil.com'))], extraTsaExts: [nul] });
    expect(r).toBe('name-constraint-violation'); // fail closed: a C string would stop at the NUL and see `evil.com`
    const r2 = await reason({ caExts: [P(gnDns('example.com'))], extraTsaExts: [nul] });
    expect(r2).toBe('name-constraint-violation');
    expect(await reason({ extraTsaExts: [nul] })).toBe('ok'); // no constraint of that form: not looked at
  });
  it('parseCertificate does not read the extension (a certificate with a broken one is still readable)', () => {
    const t = build({ caExts: [ext('2.5.29.30', true, tlv(4, Uint8Array.of(1)))] });
    const pem = t.caPem.replace(/-----[A-Z ]+-----|\s/g, '');
    const cert = parseCertificate(Uint8Array.from(Buffer.from(pem, 'base64')));
    expect(cert.nameConstraints).not.toBeNull();
    expect(cert.nameConstraints!.critical).toBe(true);
    expect(cert.unknownCritical).toBe(false);
  });
  it('encodeOid is used (keeps the helper import honest)', () => {
    expect(encodeOid('2.5.29.30').length).toBeGreaterThan(2);
  });
});

describe('name comparison after the refactor to a list of RDNs', () => {
  it('a name that is only the beginning of another is not the same name', () => {
    expect(sameName(dn(CN('A')), dn(CN('A'), CN('B')))).toBe(false);
    expect(sameName(dn(CN('A'), CN('B')), dn(CN('A')))).toBe(false);
    expect(sameName(dn(), dn(CN('A')))).toBe(false);
    expect(sameName(dn(CN('A'), CN('B')), dn(CN('a'), CN('b ')))).toBe(true);
    expect(sameName(dn(CN('A'), CN('B')), dn(CN('B'), CN('A')))).toBe(false);
  });
});
