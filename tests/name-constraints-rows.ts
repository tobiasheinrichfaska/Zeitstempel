// The measured cases of the name constraints (RFC 5280 § 4.2.1.10): shared by the OpenSSL comparison and the
// documentation test. `openssl` is what `openssl ts -verify` (3.0.13) answered, `ours` what this library answers.
import type { Reason } from '../src/lib/index.ts';
import type { Opts } from './token-builder.ts';
import {
  C,
  CN,
  EMAIL,
  O,
  dn,
  gnDir,
  gnDns,
  gnEmail,
  gnIp,
  gnOther,
  gnRid,
  gnUri,
  nc,
  san,
  sub,
} from './nc-builder.ts';
import { ext, seq, tlv } from './token-builder.ts';

export interface NcRow {
  label: string;
  opts: Opts;
  /** `null`: OpenSSL cannot build the chain at all (a self-issued intermediate), so there is nothing to compare. */
  openssl: boolean | null;
  ours: Reason | 'ok';
  /** The row of the table in docs/grenzen.md that explains a difference or a rule of its own (F32 and up). */
  f?: string;
}

const V = 'name-constraint-violation';
const root = (...e: Uint8Array[]): Pick<Opts, 'caExts'> => ({ caExts: e });
const viaInt = (...e: Uint8Array[]): Pick<Opts, 'intermediate'> => ({
  intermediate: { extraExts: e },
});
const dns = (s: string): Uint8Array[] => [san(gnDns(s))];
const P = (...b: Uint8Array[]) => nc({ permitted: b.map((x) => sub(x)) });
const X = (...b: Uint8Array[]) => nc({ excluded: b.map((x) => sub(x)) });
const SIGNER = dn(C('DE'), O('Foo'), CN('TSA'));
const zeros = (n: number) => Array<number>(n).fill(0);
const net6 = gnIp(0x20, 1, 0xd, 0xb8, ...zeros(12), 0xff, 0xff, 0xff, 0xff, ...zeros(12));

export const ROWS: NcRow[] = [
  // dNSName
  {
    label: 'dns: permitted example.com, SAN a.example.com',
    opts: { ...root(P(gnDns('example.com'))), extraTsaExts: dns('a.example.com') },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'dns: permitted example.com, SAN example.com itself',
    opts: { ...root(P(gnDns('example.com'))), extraTsaExts: dns('example.com') },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'dns: permitted example.com, SAN evil.com',
    opts: { ...root(P(gnDns('example.com'))), extraTsaExts: dns('evil.com') },
    openssl: false,
    ours: V,
  },
  {
    label: 'dns: permitted example.com, SAN notexample.com (no dot boundary)',
    opts: { ...root(P(gnDns('example.com'))), extraTsaExts: dns('notexample.com') },
    openssl: false,
    ours: V,
  },
  {
    label: 'dns: permitted example.com, SAN A.EXAMPLE.COM (case)',
    opts: { ...root(P(gnDns('example.com'))), extraTsaExts: dns('A.EXAMPLE.COM') },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'dns: permitted .example.com (leading dot), SAN a.example.com',
    opts: { ...root(P(gnDns('.example.com'))), extraTsaExts: dns('a.example.com') },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'dns: permitted .example.com (leading dot), SAN example.com',
    opts: { ...root(P(gnDns('.example.com'))), extraTsaExts: dns('example.com') },
    openssl: false,
    ours: V,
  },
  {
    label: 'dns: excluded example.com, SAN a.example.com',
    opts: { ...root(X(gnDns('example.com'))), extraTsaExts: dns('a.example.com') },
    openssl: false,
    ours: V,
  },
  {
    label: 'dns: excluded example.com, SAN evil.com',
    opts: { ...root(X(gnDns('example.com'))), extraTsaExts: dns('evil.com') },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'dns: permitted empty base matches every name',
    opts: { ...root(P(gnDns(''))), extraTsaExts: dns('evil.com') },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'dns: excluded empty base excludes every name',
    opts: { ...root(X(gnDns(''))), extraTsaExts: dns('evil.com') },
    openssl: false,
    ours: V,
  },
  {
    label: 'dns: SAN wildcard *.example.com, permitted example.com',
    opts: { ...root(P(gnDns('example.com'))), extraTsaExts: dns('*.example.com') },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'dns: SAN wildcard *.evil.com, permitted example.com',
    opts: { ...root(P(gnDns('example.com'))), extraTsaExts: dns('*.evil.com') },
    openssl: false,
    ours: V,
  },
  {
    label: 'dns: two permitted subtrees, SAN matches the second',
    opts: { ...root(P(gnDns('a.com'), gnDns('b.com'))), extraTsaExts: dns('x.b.com') },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'dns: permitted example.com, excluded bad.example.com, SAN bad.example.com',
    opts: {
      ...root(
        nc({ permitted: [sub(gnDns('example.com'))], excluded: [sub(gnDns('bad.example.com'))] }),
      ),
      extraTsaExts: dns('bad.example.com'),
    },
    openssl: false,
    ours: V,
  },
  {
    label: 'dns: permitted example.com, excluded bad.example.com, SAN good.example.com',
    opts: {
      ...root(
        nc({ permitted: [sub(gnDns('example.com'))], excluded: [sub(gnDns('bad.example.com'))] }),
      ),
      extraTsaExts: dns('good.example.com'),
    },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'dns: a dns constraint does not touch an email name',
    opts: { ...root(P(gnDns('example.com'))), extraTsaExts: [san(gnEmail('a@evil.com'))] },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'dns: no SAN, subject CN=TSA (no dot: not a host name)',
    opts: { ...root(P(gnDns('example.com'))) },
    openssl: true,
    ours: 'ok',
  },
  // commonName as a host name (OpenSSL checks it when the signer has no dNSName)
  {
    label: 'cn: no SAN, CN=evil.com, permitted example.com',
    opts: { ...root(P(gnDns('example.com'))), tsaSubject: dn(CN('evil.com')) },
    openssl: false,
    ours: V,
    f: 'F32',
  },
  {
    label: 'cn: no SAN, CN=a.example.com, permitted example.com',
    opts: { ...root(P(gnDns('example.com'))), tsaSubject: dn(CN('a.example.com')) },
    openssl: true,
    ours: 'ok',
    f: 'F32',
  },
  {
    label: 'cn: CN=EVIL.COM upper case',
    opts: { ...root(P(gnDns('example.com'))), tsaSubject: dn(CN('EVIL.COM')) },
    openssl: false,
    ours: V,
    f: 'F32',
  },
  {
    label: 'cn: CN as PrintableString',
    opts: { ...root(P(gnDns('example.com'))), tsaSubject: dn(['2.5.4.3', 'evil.com', 0x13]) },
    openssl: false,
    ours: V,
    f: 'F32',
  },
  {
    label: 'cn: CN=evil.com ignored when a dNSName SAN exists',
    opts: {
      ...root(P(gnDns('example.com'))),
      tsaSubject: dn(CN('evil.com')),
      extraTsaExts: dns('a.example.com'),
    },
    openssl: true,
    ours: 'ok',
    f: 'F32',
  },
  {
    label: 'cn: CN=evil.com checked when the SAN has only an email',
    opts: {
      ...root(P(gnDns('example.com'))),
      tsaSubject: dn(CN('evil.com')),
      extraTsaExts: [san(gnEmail('a@example.com'))],
    },
    openssl: false,
    ours: V,
    f: 'F32',
  },
  {
    label: 'cn: CN=evil (no dot) is no host name',
    opts: { ...root(P(gnDns('example.com'))), tsaSubject: dn(CN('evil')) },
    openssl: true,
    ours: 'ok',
    f: 'F32',
  },
  {
    label: 'cn: CN=*.evil.com (wildcard) is no host name',
    opts: { ...root(P(gnDns('example.com'))), tsaSubject: dn(CN('*.evil.com')) },
    openssl: true,
    ours: 'ok',
    f: 'F32',
  },
  {
    label: 'cn: CN=evil.com. (trailing dot) is no host name',
    opts: { ...root(P(gnDns('example.com'))), tsaSubject: dn(CN('evil.com.')) },
    openssl: true,
    ours: 'ok',
    f: 'F32',
  },
  {
    label: 'cn: CN=1.2.3.4 is read as a host name',
    opts: { ...root(P(gnDns('example.com'))), tsaSubject: dn(CN('1.2.3.4')) },
    openssl: false,
    ours: V,
    f: 'F32',
  },
  {
    label: 'cn: second CN is the bad one',
    opts: { ...root(P(gnDns('example.com'))), tsaSubject: dn(CN('a.example.com'), CN('evil.com')) },
    openssl: false,
    ours: V,
    f: 'F32',
  },
  {
    label: 'cn: excluded example.com, CN=a.example.com',
    opts: { ...root(X(gnDns('example.com'))), tsaSubject: dn(CN('a.example.com')) },
    openssl: false,
    ours: V,
    f: 'F32',
  },
  {
    label: 'cn: O=evil.com is not a commonName',
    opts: { ...root(P(gnDns('example.com'))), tsaSubject: dn(O('evil.com')) },
    openssl: true,
    ours: 'ok',
    f: 'F32',
  },
  {
    label: 'cn: CN=a-b.evil.com (hyphen inside a label)',
    opts: { ...root(P(gnDns('example.com'))), tsaSubject: dn(CN('a-b.evil.com')) },
    openssl: false,
    ours: V,
    f: 'F32',
  },
  {
    label: 'cn: CN=a-.evil.com (label ends with a hyphen) is no host name',
    opts: { ...root(P(gnDns('example.com'))), tsaSubject: dn(CN('a-.evil.com')) },
    openssl: true,
    ours: 'ok',
    f: 'F32',
  },
  {
    label: 'cn: CN=a..evil.com (empty label) is no host name',
    opts: { ...root(P(gnDns('example.com'))), tsaSubject: dn(CN('a..evil.com')) },
    openssl: true,
    ours: 'ok',
    f: 'F32',
  },
  {
    label: 'cn: CN=a_b.evil.com (underscore is a label character)',
    opts: { ...root(P(gnDns('example.com'))), tsaSubject: dn(CN('a_b.evil.com')) },
    openssl: false,
    ours: V,
    f: 'F32',
  },
  {
    label: 'cn: trailing NUL bytes are cut off',
    opts: { ...root(P(gnDns('example.com'))), tsaSubject: dn(CN('evil.com\0')) },
    openssl: false,
    ours: V,
    f: 'F32',
  },
  {
    label: 'cn: embedded NUL byte',
    opts: { ...root(P(gnDns('example.com'))), tsaSubject: dn(CN('evil.com\0.example.com')) },
    openssl: false,
    ours: V,
    f: 'F32',
  },
  {
    label: 'cn: CN as BMPString is not looked at',
    opts: { ...root(P(gnDns('example.com'))), tsaSubject: dn(['2.5.4.3', 'evil.com', 0x1e]) },
    openssl: true,
    ours: 'ok',
    f: 'F32',
  },
  {
    label: 'cn: CN as TeletexString',
    opts: { ...root(P(gnDns('example.com'))), tsaSubject: dn(['2.5.4.3', 'evil.com', 0x14]) },
    openssl: false,
    ours: V,
    f: 'F32',
  },
  {
    label: 'cn: CN as IA5String',
    opts: { ...root(P(gnDns('example.com'))), tsaSubject: dn(['2.5.4.3', 'evil.com', 0x16]) },
    openssl: false,
    ours: V,
    f: 'F32',
  },
  {
    label: 'cn: the CN of an intermediate is not looked at',
    opts: {
      ...root(P(gnDns('example.com'))),
      intermediate: {},
      intSubject: dn(CN('evil.com')),
      extraTsaExts: dns('a.example.com'),
    },
    openssl: true,
    ours: 'ok',
    f: 'F32',
  },
  {
    label: 'dns: a NUL inside a SAN name under an excluded subtree',
    opts: { ...root(X(gnDns('evil.com'))), extraTsaExts: dns('evil.com\0.example.com') },
    openssl: true,
    ours: V,
    f: 'F39',
  },
  {
    label: 'dns: a name with a byte above 127 under a permitted subtree',
    opts: { ...root(P(gnDns('example.com'))), extraTsaExts: dns('\u00e9xample.com') },
    openssl: false,
    ours: V,
  },
  {
    label: 'cn: CN=a.-evil.com (label starts with a hyphen) is no host name',
    opts: { ...root(P(gnDns('example.com'))), tsaSubject: dn(CN('a.-evil.com')) },
    openssl: true,
    ours: 'ok',
    f: 'F32',
  },
  {
    label: 'cn: CN=a.example.com with a trailing NUL is still a host name of the permitted domain',
    opts: { ...root(P(gnDns('example.com'))), tsaSubject: dn(CN('a.example.com\0')) },
    openssl: true,
    ours: 'ok',
    f: 'F32',
  },
  {
    label: 'dir: the permitted base is the whole subject',
    opts: { ...root(P(gnDir(dn(C('DE'), O('Foo'), CN('TSA'))))), tsaSubject: SIGNER },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'dir: a signer that is self-issued by name is still checked',
    opts: { ...root(P(gnDir(dn(C('DE'))))), tsaSubject: dn(CN('CA')) },
    openssl: false,
    ours: V,
  },
  // rfc822Name
  {
    label: 'email: permitted example.com, SAN a@example.com',
    opts: { ...root(P(gnEmail('example.com'))), extraTsaExts: [san(gnEmail('a@example.com'))] },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'email: permitted example.com (host), SAN a@sub.example.com',
    opts: { ...root(P(gnEmail('example.com'))), extraTsaExts: [san(gnEmail('a@sub.example.com'))] },
    openssl: false,
    ours: V,
  },
  {
    label: 'email: permitted .example.com, SAN a@sub.example.com',
    opts: {
      ...root(P(gnEmail('.example.com'))),
      extraTsaExts: [san(gnEmail('a@sub.example.com'))],
    },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'email: permitted .example.com, SAN a@example.com',
    opts: { ...root(P(gnEmail('.example.com'))), extraTsaExts: [san(gnEmail('a@example.com'))] },
    openssl: false,
    ours: V,
  },
  {
    label: 'email: permitted a@example.com, SAN a@example.com',
    opts: { ...root(P(gnEmail('a@example.com'))), extraTsaExts: [san(gnEmail('a@example.com'))] },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'email: permitted a@example.com, SAN A@example.com (local part is case sensitive)',
    opts: { ...root(P(gnEmail('a@example.com'))), extraTsaExts: [san(gnEmail('A@example.com'))] },
    openssl: false,
    ours: V,
  },
  {
    label: 'email: permitted a@example.com, SAN a@EXAMPLE.COM (host is not)',
    opts: { ...root(P(gnEmail('a@example.com'))), extraTsaExts: [san(gnEmail('a@EXAMPLE.COM'))] },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'email: excluded example.com, SAN a@example.com',
    opts: { ...root(X(gnEmail('example.com'))), extraTsaExts: [san(gnEmail('a@example.com'))] },
    openssl: false,
    ours: V,
  },
  {
    label: 'email: SAN without @ under an email constraint',
    opts: { ...root(P(gnEmail('example.com'))), extraTsaExts: [san(gnEmail('example.com'))] },
    openssl: false,
    ours: V,
    f: 'F33',
  },
  {
    label: 'email: emailAddress in the subject, no SAN, permitted example.com',
    opts: { ...root(P(gnEmail('example.com'))), tsaSubject: dn(CN('TSA'), EMAIL('a@evil.com')) },
    openssl: false,
    ours: V,
    f: 'F33',
  },
  {
    label: 'email: emailAddress in the subject within the permitted domain',
    opts: { ...root(P(gnEmail('example.com'))), tsaSubject: dn(CN('TSA'), EMAIL('a@example.com')) },
    openssl: true,
    ours: 'ok',
    f: 'F33',
  },
  // URI
  {
    label: 'uri: permitted example.com, SAN https://example.com/x',
    opts: { ...root(P(gnUri('example.com'))), extraTsaExts: [san(gnUri('https://example.com/x'))] },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'uri: permitted example.com (host), SAN https://a.example.com/',
    opts: {
      ...root(P(gnUri('example.com'))),
      extraTsaExts: [san(gnUri('https://a.example.com/'))],
    },
    openssl: false,
    ours: V,
  },
  {
    label: 'uri: permitted .example.com, SAN https://a.example.com:8080/',
    opts: {
      ...root(P(gnUri('.example.com'))),
      extraTsaExts: [san(gnUri('https://a.example.com:8080/'))],
    },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'uri: permitted .example.com, SAN https://example.com/',
    opts: { ...root(P(gnUri('.example.com'))), extraTsaExts: [san(gnUri('https://example.com/'))] },
    openssl: false,
    ours: V,
  },
  {
    label: 'uri: SAN without ://',
    opts: { ...root(P(gnUri('example.com'))), extraTsaExts: [san(gnUri('mailto:a@example.com'))] },
    openssl: false,
    ours: V,
    f: 'F33',
  },
  {
    label: 'uri: excluded example.com, SAN https://example.com',
    opts: { ...root(X(gnUri('example.com'))), extraTsaExts: [san(gnUri('https://example.com'))] },
    openssl: false,
    ours: V,
  },
  {
    label: 'uri: host case does not matter',
    opts: { ...root(P(gnUri('example.com'))), extraTsaExts: [san(gnUri('https://EXAMPLE.com/'))] },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'uri: excluded evil.com, SAN https://evil.com/x:y (a colon after the path)',
    opts: { ...root(X(gnUri('evil.com'))), extraTsaExts: [san(gnUri('https://evil.com/x:y'))] },
    openssl: true,
    ours: V,
    f: 'F40',
  },
  {
    label: 'uri: excluded evil.com, SAN https://user@evil.com/ (user information)',
    opts: { ...root(X(gnUri('evil.com'))), extraTsaExts: [san(gnUri('https://user@evil.com/'))] },
    openssl: true,
    ours: V,
    f: 'F40',
  },
  {
    label: 'uri: excluded evil.com, SAN https://evil.com?x=1 (query without a path)',
    opts: { ...root(X(gnUri('evil.com'))), extraTsaExts: [san(gnUri('https://evil.com?x=1'))] },
    openssl: true,
    ours: V,
    f: 'F40',
  },
  {
    label: 'uri: permitted example.com, SAN https://user@example.com:443/x',
    opts: {
      ...root(P(gnUri('example.com'))),
      extraTsaExts: [san(gnUri('https://user@example.com:443/x'))],
    },
    openssl: false,
    ours: 'ok',
    f: 'F40',
  },
  {
    label: 'uri: excluded example.com, SAN without :// (cannot be placed)',
    opts: { ...root(X(gnUri('example.com'))), extraTsaExts: [san(gnUri('mailto:a@other.org'))] },
    openssl: false,
    ours: V,
    f: 'F33',
  },
  {
    label: 'email: excluded example.com, SAN without @ (cannot be placed)',
    opts: { ...root(X(gnEmail('example.com'))), extraTsaExts: [san(gnEmail('other.org'))] },
    openssl: false,
    ours: V,
    f: 'F33',
  },
  // iPAddress
  {
    label: 'ip: permitted 10.0.0.0/8, SAN 10.1.2.3',
    opts: { ...root(P(gnIp(10, 0, 0, 0, 255, 0, 0, 0))), extraTsaExts: [san(gnIp(10, 1, 2, 3))] },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'ip: permitted 10.0.0.0/8, SAN 11.0.0.1',
    opts: { ...root(P(gnIp(10, 0, 0, 0, 255, 0, 0, 0))), extraTsaExts: [san(gnIp(11, 0, 0, 1))] },
    openssl: false,
    ours: V,
  },
  {
    label: 'ip: permitted 10.0.0.0/8, SAN an IPv6 address',
    opts: {
      ...root(P(gnIp(10, 0, 0, 0, 255, 0, 0, 0))),
      extraTsaExts: [san(gnIp(...zeros(15), 1))],
    },
    openssl: false,
    ours: V,
  },
  {
    label: 'ip: permitted 2001:db8::/32, SAN 2001:db8::1',
    opts: { ...root(P(net6)), extraTsaExts: [san(gnIp(0x20, 1, 0xd, 0xb8, ...zeros(11), 1))] },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'ip: permitted 2001:db8::/32, SAN 2001:db9::1',
    opts: { ...root(P(net6)), extraTsaExts: [san(gnIp(0x20, 1, 0xd, 0xb9, ...zeros(11), 1))] },
    openssl: false,
    ours: V,
  },
  {
    label: 'ip: excluded 10.0.0.0/8, SAN 10.0.0.1',
    opts: { ...root(X(gnIp(10, 0, 0, 0, 255, 0, 0, 0))), extraTsaExts: [san(gnIp(10, 0, 0, 1))] },
    openssl: false,
    ours: V,
  },
  {
    label: 'ip: excluded 10.0.0.0/8, SAN an IPv6 address',
    opts: {
      ...root(X(gnIp(10, 0, 0, 0, 255, 0, 0, 0))),
      extraTsaExts: [san(gnIp(...zeros(15), 1))],
    },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'ip: /32 mask only the exact address',
    opts: {
      ...root(P(gnIp(10, 0, 0, 1, 255, 255, 255, 255))),
      extraTsaExts: [san(gnIp(10, 0, 0, 2))],
    },
    openssl: false,
    ours: V,
  },
  {
    label: 'ip: /0 mask matches every IPv4 address',
    opts: { ...root(P(gnIp(0, 0, 0, 0, 0, 0, 0, 0))), extraTsaExts: [san(gnIp(8, 8, 8, 8))] },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'ip: SAN address of 3 bytes under an ip constraint',
    opts: { ...root(P(gnIp(10, 0, 0, 0, 255, 0, 0, 0))), extraTsaExts: [san(gnIp(10, 0, 0))] },
    openssl: false,
    ours: V,
  },
  {
    label: 'ip: constraint of 5 bytes (no address and mask)',
    opts: { ...root(P(gnIp(10, 0, 0, 0, 255))), extraTsaExts: dns('a.example.com') },
    openssl: true,
    ours: 'bad-certificate',
    f: 'F34',
  },
  {
    label: 'ip: mask 255.0.255.0 (not a prefix)',
    opts: { ...root(P(gnIp(10, 0, 0, 0, 255, 0, 255, 0))), extraTsaExts: [san(gnIp(10, 9, 0, 7))] },
    openssl: true,
    ours: 'bad-certificate',
    f: 'F34',
  },
  {
    label: 'ip: host bits set in the base address (10.1.2.3/8) are masked like OpenSSL does',
    opts: { ...root(P(gnIp(10, 1, 2, 3, 255, 0, 0, 0))), extraTsaExts: [san(gnIp(10, 9, 9, 9))] },
    openssl: true,
    ours: 'ok',
  },
  // directoryName
  {
    label: 'dir: permitted C=DE, subject C=DE O=Foo CN=TSA',
    opts: { ...root(P(gnDir(dn(C('DE'))))), tsaSubject: SIGNER },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'dir: permitted C=FR, subject C=DE O=Foo CN=TSA',
    opts: { ...root(P(gnDir(dn(C('FR'))))), tsaSubject: SIGNER },
    openssl: false,
    ours: V,
  },
  {
    label: 'dir: permitted C=DE O=Foo (longer prefix)',
    opts: { ...root(P(gnDir(dn(C('DE'), O('Foo'))))), tsaSubject: SIGNER },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'dir: permitted O=Foo (not at the start of the subject)',
    opts: { ...root(P(gnDir(dn(O('Foo'))))), tsaSubject: SIGNER },
    openssl: false,
    ours: V,
  },
  {
    label: 'dir: permitted base longer than the subject',
    opts: { ...root(P(gnDir(dn(C('DE'), O('Foo'), CN('TSA'), CN('more'))))), tsaSubject: SIGNER },
    openssl: false,
    ours: V,
  },
  {
    label: 'dir: excluded C=DE',
    opts: { ...root(X(gnDir(dn(C('DE'))))), tsaSubject: SIGNER },
    openssl: false,
    ours: V,
  },
  {
    label: 'dir: excluded C=FR',
    opts: { ...root(X(gnDir(dn(C('FR'))))), tsaSubject: SIGNER },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'dir: values compare case-insensitively (O=FOO)',
    opts: { ...root(P(gnDir(dn(C('DE'), O('FOO'))))), tsaSubject: SIGNER },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'dir: PrintableString base against a UTF8String subject',
    opts: {
      ...root(P(gnDir(dn(['2.5.4.6', 'DE', 0x13], ['2.5.4.10', 'Foo', 0x13])))),
      tsaSubject: SIGNER,
    },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'dir: empty base matches every subject',
    opts: { ...root(P(gnDir(dn()))), tsaSubject: SIGNER },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'dir: empty subject is not checked',
    opts: { ...root(P(gnDir(dn(C('FR'))))), tsaSubject: dn() },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'dir: a directoryName in the SAN is checked too',
    opts: {
      ...root(P(gnDir(dn(C('DE'))))),
      tsaSubject: SIGNER,
      extraTsaExts: [san(gnDir(dn(C('FR'), CN('x'))))],
    },
    openssl: false,
    ours: V,
  },
  {
    label: 'dir: multi-valued RDN, the same pair written in another order',
    opts: {
      ...root(
        P(
          gnDir(
            dn(C('DE'), [
              ['2.5.4.10', 'Foo'],
              ['2.5.4.11', 'Bar'],
            ]),
          ),
        ),
      ),
      tsaSubject: dn(
        C('DE'),
        [
          ['2.5.4.11', 'Bar'],
          ['2.5.4.10', 'Foo'],
        ],
        CN('TSA'),
      ),
    },
    openssl: true,
    ours: 'ok',
  },
  // name forms this library does not evaluate
  {
    label: 'other: permitted otherName, SAN otherName (critical)',
    opts: { ...root(nc({ permitted: [sub(gnOther())] })), extraTsaExts: [san(gnOther())] },
    openssl: false,
    ours: 'bad-certificate',
    f: 'F35',
  },
  {
    label: 'other: permitted otherName, SAN only a dNSName',
    opts: { ...root(nc({ permitted: [sub(gnOther())] })), extraTsaExts: dns('a.example.com') },
    openssl: true,
    ours: 'ok',
    f: 'F35',
  },
  {
    label: 'other: permitted registeredID, SAN registeredID',
    opts: {
      ...root(nc({ permitted: [sub(gnRid('1.2.3'))] })),
      extraTsaExts: [san(gnRid('1.2.3'))],
    },
    openssl: false,
    ours: 'bad-certificate',
    f: 'F35',
  },
  {
    label: 'other: NOT critical, permitted otherName, SAN otherName',
    opts: {
      ...root(nc({ critical: false, permitted: [sub(gnOther())] })),
      extraTsaExts: [san(gnOther())],
    },
    openssl: false,
    ours: 'ok',
    f: 'F36',
  },
  {
    label: 'other: SAN otherName, no constraint of that form',
    opts: { ...root(P(gnDns('example.com'))), extraTsaExts: [san(gnOther())] },
    openssl: true,
    ours: 'ok',
  },
  // the extension itself
  {
    label: 'ext: NOT critical, supported form, violated',
    opts: {
      ...root(nc({ critical: false, permitted: [sub(gnDns('example.com'))] })),
      extraTsaExts: dns('evil.com'),
    },
    openssl: false,
    ours: V,
  },
  {
    label: 'ext: minimum 1 in a subtree',
    opts: {
      ...root(nc({ permitted: [sub(gnDns('example.com'), 1)] })),
      extraTsaExts: dns('a.example.com'),
    },
    openssl: false,
    ours: 'bad-certificate',
  },
  {
    label: 'ext: maximum 3 in a subtree',
    opts: {
      ...root(nc({ permitted: [sub(gnDns('example.com'), undefined, 3)] })),
      extraTsaExts: dns('a.example.com'),
    },
    openssl: false,
    ours: 'bad-certificate',
  },
  {
    label: 'ext: minimum 0 written out (DER leaves a default out)',
    opts: {
      ...root(nc({ permitted: [sub(gnDns('example.com'), 0)] })),
      extraTsaExts: dns('a.example.com'),
    },
    openssl: true,
    ours: 'bad-certificate',
    f: 'F37',
  },
  {
    label: 'ext: neither permitted nor excluded',
    opts: { ...root(ext('2.5.29.30', true, seq())), extraTsaExts: dns('a.example.com') },
    openssl: true,
    ours: 'bad-certificate',
    f: 'F37',
  },
  {
    label: 'ext: permitted subtrees list is empty',
    opts: { ...root(ext('2.5.29.30', true, seq(tlv(0xa0)))), extraTsaExts: dns('a.example.com') },
    openssl: true,
    ours: 'bad-certificate',
    f: 'F37',
  },
  {
    label: 'ext: only excluded, other names stay free',
    opts: { ...root(X(gnDns('bad.com'))), extraTsaExts: dns('example.com') },
    openssl: true,
    ours: 'ok',
  },
  // levels
  {
    label: 'level: intermediate permits example.com, SAN a.example.com',
    opts: { ...viaInt(P(gnDns('example.com'))), extraTsaExts: dns('a.example.com') },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'level: intermediate permits example.com, SAN evil.com',
    opts: { ...viaInt(P(gnDns('example.com'))), extraTsaExts: dns('evil.com') },
    openssl: false,
    ours: V,
  },
  {
    label: 'level: root permits other.org, intermediate permits example.com, SAN a.example.com',
    opts: {
      ...root(P(gnDns('other.org'))),
      ...viaInt(P(gnDns('example.com'))),
      extraTsaExts: dns('a.example.com'),
    },
    openssl: false,
    ours: V,
  },
  {
    label:
      'level: root permits example.com, intermediate permits sub.example.com, SAN a.example.com',
    opts: {
      ...root(P(gnDns('example.com'))),
      ...viaInt(P(gnDns('sub.example.com'))),
      extraTsaExts: dns('a.example.com'),
    },
    openssl: false,
    ours: V,
  },
  {
    label: 'level: root excludes bad.com, intermediate silent, SAN bad.com',
    opts: { ...root(X(gnDns('bad.com'))), intermediate: {}, extraTsaExts: dns('bad.com') },
    openssl: false,
    ours: V,
  },
  {
    label:
      'level: constraint of the anchor reaches the intermediate subject (permitted C=DE, INT has no C)',
    opts: { ...root(P(gnDir(dn(C('DE'))))), intermediate: {}, tsaSubject: SIGNER },
    openssl: false,
    ours: V,
  },
  {
    label: 'level: permitted C=DE, INT has C=DE',
    opts: {
      ...root(P(gnDir(dn(C('DE'))))),
      intermediate: {},
      intSubject: dn(C('DE'), CN('INT')),
      tsaSubject: SIGNER,
    },
    openssl: true,
    ours: 'ok',
  },
  {
    label: "level: an intermediate's own constraint does not apply to itself",
    opts: {
      ...viaInt(P(gnDir(dn(C('FR'))))),
      intSubject: dn(C('DE'), CN('INT')),
      tsaSubject: dn(C('FR'), CN('TSA')),
    },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'level: two intermediates, the first excludes example.com, SAN a.example.com',
    opts: {
      deepChain: 2,
      deepExts: [[X(gnDns('example.com'))]],
      extraTsaExts: dns('a.example.com'),
    },
    openssl: false,
    ours: V,
  },
  {
    label: 'level: two intermediates, the first excludes bad.com, SAN example.com',
    opts: { deepChain: 2, deepExts: [[X(gnDns('bad.com'))]], extraTsaExts: dns('example.com') },
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'level: a constraint in the signer certificate itself is not applied',
    opts: { extraTsaExts: [P(gnDns('example.com')), ...dns('evil.com')!] },
    openssl: true,
    ours: 'ok',
  },
  // self-issued intermediate (key rollover)
  {
    label: 'self-issued: root permits C=DE, the rollover certificate (CN=CA) is exempt',
    opts: { ...root(P(gnDir(dn(C('DE'))))), rollover: {}, tsaSubject: SIGNER },
    openssl: null,
    ours: 'ok',
    f: 'F38',
  },
  {
    label: 'self-issued: its own excluded subtree applies to the signer',
    opts: {
      rollover: {},
      rolloverExts: [X(gnDns('example.com'))],
      extraTsaExts: dns('a.example.com'),
    },
    openssl: null,
    ours: V,
  },
  {
    label: 'self-issued: its own permitted subtree is not applied to itself',
    opts: {
      rollover: {},
      rolloverExts: [P(gnDns('example.com'))],
      extraTsaExts: dns('a.example.com'),
    },
    openssl: null,
    ours: 'ok',
  },
];
