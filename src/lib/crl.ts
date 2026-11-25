import { equalBytes, trimZeros } from './bytes.ts';
import {
  DER_LIMITS,
  TAG,
  bitStringBytes,
  boolean,
  children,
  ctx,
  expect,
  inner,
  integerNumber,
  octets,
  oid,
  ownBytes,
  parseDer,
  time,
  unsignedBytes,
  type Node,
} from './der.ts';
import { ReaderError } from './result.ts';

/**
 * A strict, bounded reader of a certificate revocation list (CRL, RFC 5280 § 5), as DER. The caller hands the
 * lists over (`crls` of `verifyTimestampToken`); nothing is fetched. Every flaw is `ReaderError('bad-crl')`.
 * Not supported, and therefore refused (never silently ignored): delta CRLs (`deltaCRLIndicator`), indirect CRLs
 * (`indirectCRL` in the issuing distribution point, `certificateIssuer` in an entry), CRLs of attribute
 * certificates, a critical extension this reader does not know, an entry extension marked critical that it does
 * not know, and the reason `removeFromCRL` (only a delta CRL uses it).
 */

/** The limits of the CRL handling (docs/grenzen.md and docs/data-model.html name each value). */
export const CRL_LIMITS = {
  /** Entries of the option `crls`; a longer list is `bad-options`. */
  MAX_CRLS: 16,
  /** Bytes of one CRL; a larger one is `bad-options` (checked before it is copied). */
  MAX_CRL_BYTES: DER_LIMITS.maxBytes,
  /** Entries in `revokedCertificates` of one CRL (the child limit of the DER reader); more is `bad-crl`. */
  MAX_REVOKED_ENTRIES: DER_LIMITS.maxChildren,
  /** Signature verifications for the CRLs of one verification (all chains tried together); more is `bad-crl`. */
  MAX_CRL_SIGNATURE_CHECKS: 64,
} as const;

/** One entry of `revokedCertificates`. */
export interface RevokedEntry {
  /** The serial number (INTEGER content bytes, never negative). */
  serial: Uint8Array;
  /** Milliseconds since 1970. */
  revocationDate: number;
  /** The reason code (0 to 6, 9, 10), or null when the entry has none. */
  reason: number | null;
  /** The `invalidityDate` extension in milliseconds, or null. */
  invalidityDate: number | null;
}

/** What the verifier needs from a CRL; read strictly, nothing else is interpreted. */
export interface Crl {
  /** The whole list (DER, a private copy). */
  raw: Uint8Array;
  /** The signed part (`tbsCertList`, DER). */
  tbs: Uint8Array;
  signatureOid: string;
  signature: Uint8Array;
  /** DER of the issuer name; compared with the subject of the issuer certificate (`sameName`). */
  issuer: Uint8Array;
  thisUpdate: number;
  nextUpdate: number;
  revoked: RevokedEntry[];
}

const OIDS = {
  reasonCode: '2.5.29.21',
  holdInstruction: '2.5.29.23',
  invalidityDate: '2.5.29.24',
  certificateIssuer: '2.5.29.29',
  authorityKeyIdentifier: '2.5.29.35',
  issuerAltName: '2.5.29.18',
  cRLNumber: '2.5.29.20',
  issuingDistributionPoint: '2.5.29.28',
  deltaCrlIndicator: '2.5.29.27',
  freshestCrl: '2.5.29.46',
} as const;

const bad = () => new ReaderError('bad-crl');

interface Ext {
  critical: boolean;
  value: Uint8Array;
}

/** `Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension`, each OID once. */
function readExts(list: Node): Map<string, Ext> {
  const map = new Map<string, Ext>();
  const entries = children(expect(list, TAG.sequence));
  if (entries.length === 0) throw bad();
  for (const e of entries) {
    const parts = children(expect(e, TAG.sequence));
    if (parts.length < 2 || parts.length > 3) throw bad();
    const id = oid(parts[0]!);
    const critical = parts.length === 3 ? boolean(parts[1]!) : false;
    const value = octets(parts[parts.length - 1]!);
    if (map.has(id)) throw bad();
    map.set(id, { critical, value });
  }
  return map;
}

const REASONS = new Set([0, 1, 2, 3, 4, 5, 6, 9, 10]); // 7 is unused, 8 (removeFromCRL) belongs to delta CRLs

function readEntry(node: Node, versionTwo: { used: boolean }): RevokedEntry {
  const parts = children(expect(node, TAG.sequence));
  if (parts.length < 2 || parts.length > 3) throw bad();
  const serial = unsignedBytes(parts[0]!);
  const revocationDate = time(parts[1]!, false);
  let reason: number | null = null;
  let invalidityDate: number | null = null;
  if (parts[2]) {
    versionTwo.used = true;
    for (const [id, ext] of readExts(parts[2])) {
      if (id === OIDS.reasonCode) {
        const e = parseDer(ext.value);
        if (e.tag !== 0x0a || e.value.length !== 1 || !REASONS.has(e.value[0]!)) throw bad();
        reason = e.value[0]!;
      } else if (id === OIDS.invalidityDate) {
        const t = parseDer(ext.value);
        if (t.tag !== TAG.generalizedTime) throw bad();
        invalidityDate = time(t, false);
      } else if (id === OIDS.holdInstruction) {
        continue; // advice for people, no effect on the decision
      } else if (id === OIDS.certificateIssuer) {
        throw bad(); // an indirect CRL: the entry may belong to a certificate of another issuer
      } else if (ext.critical) {
        throw bad(); // RFC 5280 § 5.3: a CRL with a critical entry extension that is not understood is not used
      }
    }
  }
  return { serial, revocationDate, reason, invalidityDate };
}

/** The issuing distribution point: only what changes the meaning of the entries is looked at. */
function checkIssuingDistributionPoint(value: Uint8Array): void {
  const parts = children(expect(parseDer(value), TAG.sequence));
  const tags = [0xa0, 0x81, 0x82, 0x83, 0x84, 0x85]; // [0] .. [5], in this order, each at most once
  let previous = -1;
  for (const p of parts) {
    const n = tags.indexOf(p.tag);
    if (n <= previous) throw bad(); // unknown, doubled or out of order
    previous = n;
    if (n === 0) {
      children(p); // distributionPoint: must be readable, not evaluated
    } else if (n === 3) {
      if (p.value.length < 1) throw bad(); // onlySomeReasons: a BIT STRING
    } else {
      if (p.value.length !== 1 || (p.value[0] !== 0 && p.value[0] !== 0xff)) throw bad();
      // [4] indirectCRL and [5] onlyContainsAttributeCerts change whose certificates the entries name
      if ((n === 4 || n === 5) && p.value[0] === 0xff) throw bad();
    }
  }
}

function readCrlExtensions(list: Node): void {
  for (const [id, ext] of readExts(list)) {
    if (id === OIDS.cRLNumber) {
      const n = parseDer(ext.value);
      if (unsignedBytes(n).length > 20) throw bad();
    } else if (id === OIDS.authorityKeyIdentifier || id === OIDS.issuerAltName) {
      continue; // not used: the signature decides who issued the list
    } else if (id === OIDS.issuingDistributionPoint) {
      checkIssuingDistributionPoint(ext.value);
    } else if (id === OIDS.deltaCrlIndicator) {
      throw bad(); // delta CRLs are not supported (critical by the RFC; refused whatever the flag says)
    } else if (id === OIDS.freshestCrl) {
      if (ext.critical) throw bad();
    } else if (ext.critical) {
      throw bad(); // a critical extension that is not understood makes the list unusable (RFC 5280 § 5.2)
    }
  }
}

const sameNode = (a: Node, b: Node): boolean => equalBytes(a.raw, b.raw);

/** Reads one CRL. The bytes are copied first (by length): nothing in the result points into the caller's buffer. Throws `ReaderError('bad-crl')` for anything it cannot use. */
export function parseCrl(der: Uint8Array): Crl {
  try {
    return parseCrlStrict(ownBytes(der));
  } catch {
    throw bad();
  }
}

function parseCrlStrict(der: Uint8Array): Crl {
  const root = expect(parseDer(der), TAG.sequence);
  const top = children(root);
  if (top.length !== 3) throw bad();
  const [tbs, sigAlg, sigBits] = top;
  expect(tbs, TAG.sequence);
  expect(sigAlg, TAG.sequence);
  const signature = bitStringBytes(sigBits!);
  const fields = children(tbs!);
  let i = 0;
  let versionTwo = false;
  if (fields[0]?.tag === TAG.integer) {
    if (integerNumber(fields[0]) !== 1) throw bad(); // only v2 is written out (v1 has no version field)
    versionTwo = true;
    i = 1;
  }
  if (fields.length < i + 4) throw bad(); // signature, issuer, thisUpdate, nextUpdate
  if (!sameNode(expect(fields[i], TAG.sequence), sigAlg!)) throw bad(); // inner = outer algorithm
  const issuerNode = expect(fields[i + 1], TAG.sequence);
  if (children(issuerNode).length === 0) throw bad(); // an empty issuer name names nobody
  const thisUpdate = time(fields[i + 2]!, false);
  const nextUpdate = time(fields[i + 3]!, false); // required here: without it the list cannot be judged fresh
  i += 4;
  const used = { used: false };
  const revoked: RevokedEntry[] = [];
  if (fields[i]?.tag === TAG.sequence) {
    for (const e of children(fields[i]!)) revoked.push(readEntry(e, used));
    i += 1;
  }
  if (fields[i]?.tag === ctx(0)) {
    used.used = true;
    readCrlExtensions(inner(fields[i]!));
    i += 1;
  }
  if (i !== fields.length) throw bad();
  if (used.used && !versionTwo) throw bad(); // extensions need version 2
  return {
    raw: root.raw,
    tbs: tbs!.raw,
    signatureOid: oid(children(sigAlg!)[0]!),
    signature,
    issuer: issuerNode.raw,
    thisUpdate,
    nextUpdate,
    revoked,
  };
}

/**
 * Whether the list says that the certificate with this serial number was revoked by `atMs` (the stamped time).
 * An entry counts when its time (the revocation date, or the earlier `invalidityDate` when the entry has one) is
 * not after `atMs`. The reasons `keyCompromise` and `cACompromise` count whatever the date is: the date of a
 * compromise is the date the CA learned of it, and the key could have been used before (a token back-dated with
 * a stolen key is exactly what a revocation check is for).
 */
export function revokedAt(crl: Crl, serial: Uint8Array, atMs: number): boolean {
  const want = trimZeros(serial);
  for (const e of crl.revoked) {
    if (!equalBytes(trimZeros(e.serial), want)) continue;
    if (e.reason === 1 || e.reason === 2) return true;
    const effective =
      e.invalidityDate === null ? e.revocationDate : Math.min(e.revocationDate, e.invalidityDate);
    if (effective <= atMs) return true;
  }
  return false;
}
