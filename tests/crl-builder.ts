import { createSign } from 'node:crypto';
import { tlv, encodeOid } from '../src/lib/der.ts';
import { ext, int, octet, seq, set } from './token-builder.ts';

/** Builds small CRLs (RFC 5280 § 5) with single flaws on demand; signed with a key pair of `token-builder`. */
const oidT = encodeOid;
const gt = (s: string) => tlv(0x18, new TextEncoder().encode(s));
const utc = (s: string) => tlv(0x17, new TextEncoder().encode(s));
const enumerated = (n: number) => tlv(0x0a, Uint8Array.of(n));
const nameOf = (cn: string) =>
  seq(set(seq(oidT('2.5.4.3'), tlv(0x0c, new TextEncoder().encode(cn)))));

export interface CrlEntry {
  /** Serial number as one byte (the builder's certificates have 1, 2, 7 ...) or as raw INTEGER content. */
  serial: number | Uint8Array;
  /** GeneralizedTime text of the revocation date. */
  date: string;
  reason?: number;
  invalidity?: string;
  /** Extra entry extensions (DER, from `ext`). */
  exts?: Uint8Array[];
  /** Replaces the whole entry (DER). */
  raw?: Uint8Array;
}

export interface CrlOpts {
  /** Common name of the issuer ("CA" = the builder's root, "INT" = its intermediate). */
  issuer?: string;
  /** The key that signs (a `generateKeyPairSync` result, as in `build().keys.ca`). */
  key: { privateKey: import('node:crypto').KeyObject };
  thisUpdate?: string;
  /** `null` leaves the field out. */
  nextUpdate?: string | null;
  entries?: CrlEntry[];
  /** `'none'`: no version field, `1`: v2 (default when there are extensions), any other number as given. */
  version?: 'none' | number;
  exts?: Uint8Array[];
  /** Replaces the `revokedCertificates` element as it is (DER). */
  revokedRaw?: Uint8Array;
  /** Algorithm written outside; the inside one stays ecdsa-with-SHA256. */
  outerAlg?: Uint8Array;
  /** Extra DER elements at the end of the tbsCertList. */
  tbsExtra?: Uint8Array[];
  issuerRaw?: Uint8Array;
  mangleSig?: (sig: Uint8Array) => Uint8Array;
  utcTimes?: boolean;
}

export const OID_CRL = {
  reason: '2.5.29.21',
  invalidity: '2.5.29.24',
  certIssuer: '2.5.29.29',
  delta: '2.5.29.27',
  idp: '2.5.29.28',
  number: '2.5.29.20',
};

export function crlEntry(e: CrlEntry): Uint8Array {
  if (e.raw) return e.raw;
  const exts = [
    ...(e.reason === undefined ? [] : [ext(OID_CRL.reason, false, enumerated(e.reason))]),
    ...(e.invalidity === undefined ? [] : [ext(OID_CRL.invalidity, false, gt(e.invalidity))]),
    ...(e.exts ?? []),
  ];
  const serial = typeof e.serial === 'number' ? tlv(2, Uint8Array.of(e.serial)) : tlv(2, e.serial);
  return seq(serial, gt(e.date), ...(exts.length ? [seq(...exts)] : []));
}

export function buildCrl(o: CrlOpts): Uint8Array {
  const alg = seq(oidT('1.2.840.10045.4.3.2'));
  const time = (t: string) => (o.utcTimes ? utc(t.slice(2)) : gt(t));
  const entries = o.entries ?? [];
  const revoked =
    o.revokedRaw ?? (entries.length ? seq(...entries.map((e) => crlEntry(e))) : undefined);
  const hasExts =
    (o.exts?.length ?? 0) > 0 ||
    entries.some(
      (e) => e.reason !== undefined || e.invalidity !== undefined || e.exts !== undefined,
    );
  const version = o.version ?? (hasExts ? 1 : 'none');
  const tbs = seq(
    ...(version === 'none' ? [] : [int(version)]),
    alg,
    o.issuerRaw ?? nameOf(o.issuer ?? 'CA'),
    time(o.thisUpdate ?? '20251201000000Z'),
    ...(o.nextUpdate === null ? [] : [time(o.nextUpdate ?? '20260201000000Z')]),
    ...(revoked ? [revoked] : []),
    ...(o.exts?.length ? [tlv(0xa0, seq(...o.exts))] : []),
    ...(o.tbsExtra ?? []),
  );
  const signer = createSign('sha256');
  signer.update(tbs);
  let sig: Uint8Array = new Uint8Array(signer.sign(o.key.privateKey));
  if (o.mangleSig) sig = o.mangleSig(sig);
  return seq(tbs, o.outerAlg ?? alg, tlv(3, Uint8Array.of(0), sig));
}

export const toPem = (der: Uint8Array): string =>
  `-----BEGIN X509 CRL-----\n${Buffer.from(der).toString('base64')}\n-----END X509 CRL-----\n`;

export { octet };
