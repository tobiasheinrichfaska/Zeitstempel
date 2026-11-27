// More measured cases of the name constraints (audit 14): the string types of a commonName and of a directory name,
// white space and byte order marks in a directory name, addresses of a wrong length, mailboxes with several @, URIs
// with a backslash or a second @. Same shape and same use as `name-constraints-rows.ts`.
import { encodeOid } from '../src/lib/der.ts';
import { gnDir, gnDns, gnEmail, gnIp, gnUri, nc, san, sub } from './nc-builder.ts';
import type { NcRow } from './name-constraints-rows.ts';
import { seq, set, tlv } from './token-builder.ts';

const V = 'name-constraint-violation';
const te = new TextEncoder();
const P = (...b: Uint8Array[]) => nc({ permitted: b.map((x) => sub(x)) });
const X = (...b: Uint8Array[]) => nc({ excluded: b.map((x) => sub(x)) });
const S = (...n: Uint8Array[]) => [san(...n)];

/** An attribute with the given string tag and raw content. */
const atv = (id: string, tag: number, v: Uint8Array) => seq(encodeOid(id), tlv(tag, v));
const bmp = (s: string) =>
  Uint8Array.from([...s].flatMap((c) => [c.codePointAt(0)! >> 8, c.codePointAt(0)! & 255]));
const uni = (s: string) =>
  Uint8Array.from(
    [...s].flatMap((c) => {
      const k = c.codePointAt(0)!;
      return [k >>> 24, (k >> 16) & 255, (k >> 8) & 255, k & 255];
    }),
  );
const cnName = (tag: number, v: Uint8Array) => seq(set(atv('2.5.4.3', tag, v)));
/** C=DE, O=<value as `tag`>, CN=TSA: a signer subject; and the same without the CN as a base of a subtree. */
const subjectO = (tag: number, v: Uint8Array) =>
  seq(
    set(atv('2.5.4.6', 0x13, te.encode('DE'))),
    set(atv('2.5.4.10', tag, v)),
    set(atv('2.5.4.3', 0x0c, te.encode('TSA'))),
  );
const baseO = (tag: number, v: Uint8Array) =>
  gnDir(seq(set(atv('2.5.4.6', 0x13, te.encode('DE'))), set(atv('2.5.4.10', tag, v))));
const u8 = (s: string) => te.encode(s);

const cn = (
  label: string,
  tag: number,
  v: Uint8Array,
  ca: Uint8Array,
  openssl: boolean,
  ours: NcRow['ours'],
  f?: string,
): NcRow => ({
  label: `cn: ${label}`,
  opts: { caExts: [ca], tsaSubject: cnName(tag, v) },
  openssl,
  ours,
  ...(f ? { f } : {}),
});
const dir = (
  label: string,
  subj: [number, Uint8Array],
  base: [number, Uint8Array],
  kind: 'P' | 'X',
  openssl: boolean,
  ours: NcRow['ours'],
  f?: string,
): NcRow => ({
  label: `dir: ${label} (${kind})`,
  opts: {
    caExts: [(kind === 'P' ? P : X)(baseO(...base))],
    tsaSubject: subjectO(...subj),
  },
  openssl,
  ours,
  ...(f ? { f } : {}),
});
const ipRow = (
  label: string,
  ca: Uint8Array,
  len: number,
  openssl: boolean,
  ours: NcRow['ours'],
): NcRow => ({
  label: `ip: ${label}`,
  opts: { caExts: [ca], extraTsaExts: S(gnIp(...Array<number>(len).fill(10))) },
  openssl,
  ours,
});
const mail = (
  label: string,
  ca: Uint8Array,
  name: string,
  openssl: boolean,
  ours: NcRow['ours'],
  f?: string,
): NcRow => ({
  label: `email: ${label}`,
  opts: { caExts: [ca], extraTsaExts: S(gnEmail(name)) },
  openssl,
  ours,
  ...(f ? { f } : {}),
});
const uri = (
  label: string,
  ca: Uint8Array,
  name: string,
  openssl: boolean,
  ours: NcRow['ours'],
  f?: string,
): NcRow => ({
  label: `uri: ${label}`,
  opts: { caExts: [ca], extraTsaExts: S(gnUri(name)) },
  openssl,
  ours,
  ...(f ? { f } : {}),
});

const V4 = gnIp(10, 0, 0, 0, 255, 0, 0, 0);
const V6 = gnIp(0x20, 1, ...Array<number>(14).fill(0), 0xff, 0xff, ...Array<number>(14).fill(0));
const XEVIL = X(gnDns('evil.com'));
const PEX = P(gnDns('example.com'));

export const ROWS14: NcRow[] = [
  // M1: the string type of the commonName of the signer
  cn('CN as BMPString evil.com, excluded evil.com', 0x1e, bmp('evil.com'), XEVIL, false, V, 'F32'),
  cn(
    'CN as UniversalString evil.com, excluded evil.com',
    0x1c,
    uni('evil.com'),
    XEVIL,
    false,
    V,
    'F32',
  ),
  cn(
    'CN as BMPString a.example.com, permitted example.com',
    0x1e,
    bmp('a.example.com'),
    PEX,
    true,
    'ok',
    'F32',
  ),
  cn(
    'CN as UniversalString a.example.com, permitted example.com',
    0x1c,
    uni('a.example.com'),
    PEX,
    true,
    'ok',
    'F32',
  ),
  cn('CN as NumericString, permitted example.com', 0x12, u8('1.2'), PEX, false, V, 'F32'),
  cn(
    'CN as VisibleString evil.com (OpenSSL cannot read the name at all)',
    0x1a,
    u8('evil.com'),
    XEVIL,
    false,
    V,
    'F32',
  ),
  cn(
    'CN as VisibleString a.example.com: no host name that can be judged',
    0x1a,
    u8('a.example.com'),
    PEX,
    false,
    V,
    'F32',
  ),
  cn('CN as BMPString with an odd length', 0x1e, Uint8Array.of(0, 0x65, 0), XEVIL, false, V, 'F32'),
  cn(
    'CN as UniversalString with a length of 3',
    0x1c,
    Uint8Array.of(0, 0, 0x65),
    XEVIL,
    false,
    V,
    'F32',
  ),
  cn(
    'CN as BMPString with a lone surrogate',
    0x1e,
    Uint8Array.of(0xd8, 0, 0, 0x41),
    XEVIL,
    false,
    V,
    'F32',
  ),
  cn(
    'CN as BMPString with a NUL character inside',
    0x1e,
    Uint8Array.of(0, 0x65, 0, 0x2e, 0, 0, 0, 0x63),
    XEVIL,
    false,
    V,
    'F32',
  ),
  cn(
    'CN as UTF8String that is no UTF-8',
    0x0c,
    Uint8Array.of(0xff, 0x2e, 0x63),
    XEVIL,
    false,
    V,
    'F32',
  ),
  cn(
    'CN of an unknown string type 0x1d under an email constraint',
    0x1d,
    u8('abc'),
    X(gnEmail('evil.com')),
    false,
    V,
    'F32',
  ),
  cn(
    'CN as BMPString, characters above 127 (no host name)',
    0x1e,
    bmp('а.co'),
    XEVIL,
    true,
    'ok',
    'F32',
  ),
  cn(
    'CN as BMPString, U+0165 is no e (no host name)',
    0x1e,
    bmp('\u0165vil.com'),
    XEVIL,
    true,
    'ok',
    'F32',
  ),
  cn(
    'CN as UniversalString, U+10065 is no e (no host name)',
    0x1c,
    uni('\u{10065}vil.com'),
    XEVIL,
    true,
    'ok',
    'F32',
  ),
  {
    label: 'cn: CN of an unknown type 0x1d is ignored when a dNSName exists',
    opts: {
      caExts: [X(gnEmail('evil.com'))],
      tsaSubject: cnName(0x1d, u8('abc')),
      extraTsaExts: S(gnDns('ok.example')),
    },
    openssl: true,
    ours: 'ok',
    f: 'F32',
  },
  // M2 and N1: the comparison of directory names
  dir(
    'O as UniversalString against UTF8String',
    [0x1c, uni('Foo')],
    [0x0c, u8('Foo')],
    'X',
    false,
    V,
  ),
  dir(
    'O as UniversalString against UTF8String',
    [0x1c, uni('Foo')],
    [0x0c, u8('Foo')],
    'P',
    true,
    'ok',
  ),
  dir(
    'O as UniversalString beyond the BMP',
    [0x1c, uni('F\u{1f600}')],
    [0x0c, u8('F\u{1f600}')],
    'X',
    false,
    V,
  ),
  dir(
    'O as VisibleString against UTF8String (OpenSSL cannot read it)',
    [0x1a, u8('Foo')],
    [0x0c, u8('Foo')],
    'X',
    false,
    V,
    'F32',
  ),
  dir('O as BMPString against UTF8String', [0x1e, bmp('Foo')], [0x0c, u8('Foo')], 'X', false, V),
  dir(
    'O as NumericString against PrintableString: another type',
    [0x12, u8('123')],
    [0x13, u8('123')],
    'X',
    true,
    'ok',
  ),
  dir(
    'O as NumericString against NumericString',
    [0x12, u8('123')],
    [0x12, u8('123')],
    'X',
    false,
    V,
  ),
  dir(
    'O as TeletexString 0x80 is U+0080, not the euro sign',
    [0x14, Uint8Array.of(0x80)],
    [0x0c, u8('€')],
    'X',
    true,
    'ok',
  ),
  dir(
    'O as TeletexString 0x80 is U+0080',
    [0x14, Uint8Array.of(0x80)],
    [0x0c, u8('\u0080')],
    'X',
    false,
    V,
  ),
  dir(
    'O with a no-break space at the end is another name',
    [0x0c, u8('Foo ')],
    [0x0c, u8('Foo')],
    'P',
    false,
    V,
  ),
  dir(
    'O with a no-break space at the end is another name',
    [0x0c, u8('Foo ')],
    [0x0c, u8('Foo')],
    'X',
    true,
    'ok',
  ),
  dir(
    'O with an em space at the end is another name',
    [0x0c, u8('Foo ')],
    [0x0c, u8('Foo')],
    'P',
    false,
    V,
  ),
  dir(
    'O with a byte order mark at the start is another name',
    [0x0c, u8('﻿Foo')],
    [0x0c, u8('Foo')],
    'P',
    false,
    V,
  ),
  dir(
    'O with a byte order mark at the start is another name',
    [0x0c, u8('﻿Foo')],
    [0x0c, u8('Foo')],
    'X',
    true,
    'ok',
  ),
  dir(
    'O as BMPString with a byte order mark is another name',
    [0x1e, bmp('﻿Foo')],
    [0x0c, u8('Foo')],
    'P',
    false,
    V,
  ),
  dir('O with a tab inside is a space', [0x0c, u8('F\too')], [0x0c, u8('F oo')], 'X', false, V),
  dir('O with a tab inside is a space', [0x0c, u8('F\too')], [0x0c, u8('F oo')], 'P', true, 'ok'),
  dir(
    'O with a run of white space inside is one space',
    [0x0c, u8('F \t oo')],
    [0x0c, u8('F oo')],
    'X',
    false,
    V,
  ),
  dir(
    'O with line feed and form feed at the ends is the same name',
    [0x0c, u8('\nFoo\f')],
    [0x0c, u8('Foo')],
    'X',
    false,
    V,
  ),
  // M3: addresses of a wrong length in the certificate
  ...[0, 1, 3, 5, 8, 12, 17, 20].flatMap((n) => [
    ipRow(`${n}-byte address against excluded 10.0.0.0/8`, X(V4), n, false, V),
    ipRow(`${n}-byte address against excluded IPv6`, X(V6), n, false, V),
    ipRow(`${n}-byte address against permitted 10.0.0.0/8`, P(V4), n, false, V),
  ]),
  {
    label: 'ip: a 5-byte address under a constraint of another kind is not looked at',
    opts: { caExts: [XEVIL], extraTsaExts: S(gnIp(1, 2, 3, 4, 5)) },
    openssl: true,
    ours: 'ok',
  },
  // M4: a mailbox is split at its LAST @
  mail(
    '"x@y"@evil.com is a mailbox at evil.com',
    X(gnEmail('evil.com')),
    '"x@y"@evil.com',
    false,
    V,
  ),
  mail(
    'a@evil.com@evil.com is a mailbox at evil.com',
    X(gnEmail('evil.com')),
    'a@evil.com@evil.com',
    false,
    V,
  ),
  mail(
    'a@b@example.com is a mailbox at example.com',
    P(gnEmail('example.com')),
    'a@b@example.com',
    true,
    'ok',
  ),
  mail(
    'evil.com@x@example.com is a mailbox at example.com',
    P(gnEmail('example.com')),
    'evil.com@x@example.com',
    true,
    'ok',
  ),
  mail(
    'a@evil.com@x is not a mailbox at evil.com',
    X(gnEmail('evil.com')),
    'a@evil.com@x',
    true,
    'ok',
  ),
  mail('base and name with two @', P(gnEmail('x@y@example.com')), 'x@y@example.com', true, 'ok'),
  mail(
    'base with two @, another local part',
    P(gnEmail('x@y@example.com')),
    'z@y@example.com',
    false,
    V,
  ),
  mail(
    'base b@evil.com against b@evil.com@evil.com',
    X(gnEmail('b@evil.com')),
    'b@evil.com@evil.com',
    true,
    'ok',
  ),
  // N2: a URI whose host is not clear
  uri(
    'backslash in the authority, permitted example.com',
    P(gnUri('example.com')),
    'https://evil.com\\@example.com/',
    false,
    V,
  ),
  uri(
    'backslash in the authority, excluded evil.com',
    X(gnUri('evil.com')),
    'https://evil.com\\@example.com/',
    true,
    V,
    'F41',
  ),
  uri(
    'second @ in the authority, permitted example.com',
    P(gnUri('example.com')),
    'https://evil.com@b@example.com/',
    false,
    V,
  ),
  uri(
    'second @ in the authority, excluded evil.com',
    X(gnUri('evil.com')),
    'https://evil.com@b@example.com/',
    true,
    V,
    'F41',
  ),
  uri(
    'backslash behind the authority does not matter',
    X(gnUri('evil.com')),
    'https://example.com/a\\b',
    true,
    'ok',
  ),
  uri(
    'one @ is user information',
    X(gnUri('evil.com')),
    'https://evil.com@example.com/',
    true,
    'ok',
  ),
  // shared with OpenSSL and not closed: the percent coding and a tab inside the host name
  uri(
    'percent-coded host %65vil.com passes an exclusion of evil.com',
    X(gnUri('evil.com')),
    'https://%65vil.com/',
    true,
    'ok',
  ),
  uri(
    'a tab inside the host passes an exclusion of evil.com',
    X(gnUri('evil.com')),
    'https://evil.\tcom/',
    true,
    'ok',
  ),
];
