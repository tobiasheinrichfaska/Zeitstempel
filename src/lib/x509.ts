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
  type Node,
} from './der.ts';
import { OID } from './oids.ts';
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

export function parseCertificate(der: Uint8Array): Certificate {
  const root = expect(parseDer(der), TAG.sequence);
  const [tbs, sigAlg, sigBits] = children(root);
  expect(tbs, TAG.sequence);
  expect(sigAlg, TAG.sequence);
  const signature = bitStringBytes(sigBits!);
  const fields = children(tbs!);
  let i = 0;
  if (fields[0]!.tag === ctx(0)) {
    if (integerNumber(inner(fields[0]!)) !== 2) throw new ReaderError('bad-certificate'); // v3
    i = 1;
  }
  const serial = expect(fields[i]!, TAG.integer).value;
  expect(fields[i + 1], TAG.sequence); // inner signature algorithm (must equal the outer one)
  if (!equalNode(fields[i + 1]!, sigAlg!)) throw new ReaderError('bad-certificate');
  const issuer = expect(fields[i + 2], TAG.sequence).raw;
  const validity = children(expect(fields[i + 3], TAG.sequence));
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
  const extNode = fields.find((f) => f.tag === ctx(3));
  if (extNode) {
    const exts = readExtensions(extNode);
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
  };
}

function equalNode(a: Node, b: Node): boolean {
  return a.raw.length === b.raw.length && a.raw.every((v, k) => v === b.raw[k]);
}

/** Reads every certificate of a PEM text (a bundle may hold several). */
export function parsePemCertificates(pem: string): Certificate[] {
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
