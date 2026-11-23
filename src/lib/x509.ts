import { fromBase64 } from './bytes.ts';
import {
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
  parseDer,
  time,
  unsignedBytes,
  type Node,
} from './der.ts';
import { KNOWN_EXTENSIONS, OID } from './oids.ts';
import { ReaderError } from './result.ts';

/** What the verifier needs from a certificate; read strictly, nothing else is interpreted. */
export interface Certificate {
  /** The whole certificate (DER). */
  raw: Uint8Array;
  /** The signed part (to-be-signed certificate, DER). */
  tbs: Uint8Array;
  serial: Uint8Array;
  /** Signature algorithm OID (outer) and the signature bytes. */
  signatureOid: string;
  signature: Uint8Array;
  /** DER of the issuer and subject names, compared byte for byte. */
  issuer: Uint8Array;
  subject: Uint8Array;
  notBefore: number;
  notAfter: number;
  /** DER of SubjectPublicKeyInfo, with the algorithm OID and the curve OID (for EC keys). */
  spki: Uint8Array;
  keyOid: string;
  curveOid: string | null;
  /** From the extensions; null when the extension is absent. */
  isCa: boolean | null;
  /** First byte of the keyUsage bit string (0x80 digitalSignature, 0x40 nonRepudiation, 0x04 keyCertSign). */
  keyUsage: number | null;
  eku: { oids: string[]; critical: boolean } | null;
  /** True when a critical extension is present that this reader does not know (RFC 5280 § 4.2). */
  unknownCritical: boolean;
}

const LIMITS = { maxCertificates: 16, maxPemChars: 200_000 } as const;

function readExtensions(list: Node): Map<string, { critical: boolean; value: Uint8Array }> {
  const map = new Map<string, { critical: boolean; value: Uint8Array }>();
  for (const ext of children(expect(inner(list), TAG.sequence))) {
    const parts = children(expect(ext, TAG.sequence));
    const id = oid(parts[0]!);
    const critical = parts.length === 3 ? boolean(parts[1]!) : false;
    const value = octets(parts[parts.length - 1]!);
    if (parts.length < 2 || parts.length > 3 || map.has(id))
      throw new ReaderError('bad-certificate');
    map.set(id, { critical, value });
  }
  return map;
}

/** Runs a reader and makes sure that only `ReaderError` can come out of it. */
function strict<T>(run: () => T): T {
  try {
    return run();
  } catch (e) {
    throw e instanceof ReaderError ? e : new ReaderError('malformed');
  }
}

export function parseCertificate(der: Uint8Array): Certificate {
  return strict(() => parseCertificateStrict(der));
}

function parseCertificateStrict(der: Uint8Array): Certificate {
  const root = expect(parseDer(der), TAG.sequence);
  const top = children(root);
  if (top.length !== 3) throw new ReaderError('bad-certificate');
  const [tbs, sigAlg, sigBits] = top;
  expect(tbs, TAG.sequence);
  expect(sigAlg, TAG.sequence);
  const signature = bitStringBytes(sigBits!);
  const fields = children(tbs!);
  let i = 0;
  if (fields[0]?.tag === ctx(0)) {
    if (integerNumber(inner(fields[0]!)) !== 2) throw new ReaderError('bad-certificate'); // v3
    i = 1;
  }
  // version, serial, algorithm, issuer, validity, subject, key: at least these must be there
  if (fields.length < i + 6) throw new ReaderError('bad-certificate');
  const serial = unsignedBytes(expect(fields[i], TAG.integer));
  expect(fields[i + 1], TAG.sequence); // inner signature algorithm (must equal the outer one)
  if (!equalNode(fields[i + 1]!, sigAlg!)) throw new ReaderError('bad-certificate');
  const issuer = expect(fields[i + 2], TAG.sequence).raw;
  const validity = children(expect(fields[i + 3], TAG.sequence));
  if (validity.length !== 2) throw new ReaderError('bad-certificate');
  const subject = expect(fields[i + 4], TAG.sequence).raw;
  const spkiNode = expect(fields[i + 5], TAG.sequence);
  const spkiParts = children(spkiNode);
  const keyAlg = children(expect(spkiParts[0], TAG.sequence));
  const keyOid = oid(keyAlg[0]!);
  const curveOid = keyOid === OID.ecPublicKey && keyAlg[1] ? oid(keyAlg[1]) : null;
  bitStringBytes(spkiParts[1]!);

  let isCa: boolean | null = null;
  let keyUsage: number | null = null;
  let eku: Certificate['eku'] = null;
  let unknownCritical = false;
  const extNode = fields.find((f) => f.tag === ctx(3));
  if (extNode) {
    const exts = readExtensions(extNode);
    for (const [id, e] of exts) if (e.critical && !KNOWN_EXTENSIONS.has(id)) unknownCritical = true;
    const bc = exts.get(OID.extBasicConstraints);
    if (bc) {
      const seq = children(expect(parseDer(bc.value), TAG.sequence));
      isCa = seq.length > 0 && seq[0]!.tag === TAG.boolean ? boolean(seq[0]!) : false;
    }
    const ku = exts.get(OID.extKeyUsage);
    if (ku) {
      const bits = parseDer(ku.value);
      expect(bits, TAG.bitString);
      keyUsage = bits.value[1] ?? 0;
    }
    const ex = exts.get(OID.extEku);
    if (ex) {
      eku = {
        oids: children(expect(parseDer(ex.value), TAG.sequence)).map((n) => oid(n)),
        critical: ex.critical,
      };
    }
  }
  return {
    raw: root.raw,
    tbs: tbs!.raw,
    serial,
    signatureOid: oid(children(sigAlg!)[0]!),
    signature,
    issuer,
    subject,
    notBefore: time(validity[0]!),
    notAfter: time(validity[1]!),
    spki: spkiNode.raw,
    keyOid,
    curveOid,
    isCa,
    keyUsage,
    eku,
    unknownCritical,
  };
}

function equalNode(a: Node, b: Node): boolean {
  return a.raw.length === b.raw.length && a.raw.every((v, k) => v === b.raw[k]);
}

/** Reads every certificate of a PEM text (a bundle may hold several). */
export function parsePemCertificates(pem: string): Certificate[] {
  return strict(() => parsePemStrict(pem));
}

function parsePemStrict(pem: string): Certificate[] {
  if (pem.length > LIMITS.maxPemChars) throw new ReaderError('too-large');
  const out: Certificate[] = [];
  const re = /-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]*)-----END CERTIFICATE-----/g;
  for (const m of pem.matchAll(re)) {
    const bytes = fromBase64(m[1]!.replace(/\s+/g, ''));
    if (!bytes) throw new ReaderError('bad-pem');
    out.push(parseCertificate(bytes));
    if (out.length > LIMITS.maxCertificates) throw new ReaderError('too-large');
  }
  if (out.length === 0) throw new ReaderError('bad-pem');
  return out;
}
