import { equalBytes, fromBase64, trimZeros } from './bytes.ts';
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
  ownBytes,
  parseDer,
  time,
  unsignedBytes,
  type Node,
} from './der.ts';
import { KNOWN_EXTENSIONS, OID, SKI_BYTES } from './oids.ts';
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
  /** DER of the issuer and subject names (`sameName` compares them; the signature decides in the end). */
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
  /**
   * `pathLenConstraint` of the basicConstraints: how many non-self-issued intermediate CAs may follow this
   * certificate on a path (RFC 5280 § 4.2.1.9). null: absent, or the certificate is no CA (a value next to
   * cA FALSE is ignored).
   */
  pathLen: number | null;
  /** First byte of the keyUsage bit string (0x80 digitalSignature, 0x40 nonRepudiation, 0x04 keyCertSign). */
  keyUsage: number | null;
  eku: { oids: string[]; critical: boolean } | null;
  /** The value (DER) of the subjectAltName extension, or null; read only when a `tsa` name needs it (`subjectAltNames`). */
  subjectAltName: Uint8Array | null;
  /**
   * The key identifier of the subjectKeyIdentifier extension (1 to 64 bytes), or null when the extension is absent.
   * Never computed from the key: a certificate without the extension has none (and is never found by a
   * SignerInfo that names a key identifier).
   */
  subjectKeyIdentifier: Uint8Array | null;
  /**
   * The nameConstraints extension as it stands (the DER inside the extension's OCTET STRING and its critical
   * flag), or null when absent. It is read only when a certificate below it is checked (`nameconstraints.ts`),
   * so a broken one makes only the paths through this certificate unusable.
   */
  nameConstraints: { value: Uint8Array; critical: boolean } | null;
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

/** Reads one certificate. The bytes are copied first (by length): nothing in the result points into the caller's buffer. */
export function parseCertificate(der: Uint8Array): Certificate {
  return strict(() => parseCertificateStrict(ownBytes(der)));
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
  let pathLen: number | null = null;
  let keyUsage: number | null = null;
  let eku: Certificate['eku'] = null;
  let subjectAltName: Uint8Array | null = null;
  let subjectKeyIdentifier: Uint8Array | null = null;
  let nameConstraints: Certificate['nameConstraints'] = null;
  let unknownCritical = false;
  const extNode = fields.find((f) => f.tag === ctx(3));
  if (extNode) {
    const exts = readExtensions(extNode);
    for (const [id, e] of exts) if (e.critical && !KNOWN_EXTENSIONS.has(id)) unknownCritical = true;
    const bc = exts.get(OID.extBasicConstraints);
    if (bc) {
      const seq = children(expect(parseDer(bc.value), TAG.sequence));
      // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX) OPTIONAL }
      let at = 0;
      isCa = false;
      if (seq[0]?.tag === TAG.boolean) {
        isCa = boolean(seq[0]);
        at = 1;
      }
      if (seq[at]?.tag === TAG.integer) {
        const len = unsignedBytes(seq[at]!); // a negative value is unreadable
        if (isCa) pathLen = len.length > 6 ? Number.MAX_SAFE_INTEGER : integerNumber(seq[at]!);
        at += 1;
      }
      if (at !== seq.length) throw new ReaderError('bad-certificate'); // nothing else is in the schema
    }
    const ku = exts.get(OID.extKeyUsage);
    if (ku) {
      const bits = parseDer(ku.value);
      expect(bits, TAG.bitString);
      keyUsage = bits.value[1] ?? 0;
    }
    subjectAltName = exts.get(OID.extSubjectAltName)?.value ?? null;
    nameConstraints = exts.get(OID.extNameConstraints) ?? null;
    const skiExt = exts.get(OID.extSubjectKeyIdentifier);
    if (skiExt) {
      // an OCTET STRING (the key identifier) inside the extension's OCTET STRING, 1 to 64 bytes
      const id = octets(parseDer(skiExt.value));
      if (id.length < SKI_BYTES.min || id.length > SKI_BYTES.max) {
        throw new ReaderError('bad-certificate');
      }
      subjectKeyIdentifier = id;
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
    notBefore: time(validity[0]!, false),
    notAfter: time(validity[1]!, false),
    spki: spkiNode.raw,
    keyOid,
    curveOid,
    isCa,
    pathLen,
    keyUsage,
    eku,
    subjectAltName,
    subjectKeyIdentifier,
    nameConstraints,
    unknownCritical,
  };
}

/** The entries of the subjectAltName (each a `GeneralName` node); `[]` without the extension, `ReaderError` when it is unreadable. */
export function subjectAltNames(cert: Certificate): Node[] {
  if (!cert.subjectAltName) return [];
  try {
    const names = children(expect(parseDer(cert.subjectAltName), TAG.sequence));
    if (names.length === 0) throw new ReaderError('bad-certificate');
    return names;
  } catch {
    throw new ReaderError('bad-certificate');
  }
}

/**
 * The size of an RSA public key's modulus in bits (leading zero bits not counted), or null for another kind of
 * key. A key that claims to be RSA but cannot be read gives 0, so that a size rule refuses it.
 */
export function rsaModulusBits(cert: Certificate): number | null {
  if (cert.keyOid !== OID.rsaEncryption) return null;
  try {
    const spki = children(parseDer(cert.spki));
    const key = children(expect(parseDer(bitStringBytes(spki[1]!)), TAG.sequence));
    if (key.length !== 2) return 0;
    const modulus = trimZeros(unsignedBytes(key[0]!));
    unsignedBytes(key[1]!);
    if (modulus.length === 0) return 0;
    return (modulus.length - 1) * 8 + (32 - Math.clz32(modulus[0]!));
  } catch {
    return 0;
  }
}

function equalNode(a: Node, b: Node): boolean {
  return a.raw.length === b.raw.length && a.raw.every((v, k) => v === b.raw[k]);
}

const OUTER_SPACE = /^[ \t\n\v\f\r]+|[ \t\n\v\f\r]+$/g;
const INNER_SPACE = /[ \t\n\v\f\r]+/g;

/** One byte per character (Latin-1, as OpenSSL reads T61String); `String.fromCharCode` maps 0x80 to U+0080, a decoder named `latin1` would not. */
function latin1(v: Uint8Array): string {
  let text = '';
  for (const b of v) text += String.fromCharCode(b);
  return text;
}

/** UniversalString: four bytes per character, none above U+10FFFF or in the surrogate range; null otherwise. */
function ucs4(v: Uint8Array): string | null {
  if (v.length % 4 !== 0) return null;
  let text = '';
  for (let k = 0; k < v.length; k += 4) {
    const cp = ((v[k]! << 24) | (v[k + 1]! << 16) | (v[k + 2]! << 8) | v[k + 3]!) >>> 0;
    if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return null;
    text += String.fromCodePoint(cp);
  }
  return text;
}

/**
 * The text of a directory string, or the bytes as hex (with the tag) when the type is unknown or not decodable.
 * UTF8String, BMPString, UniversalString and the one-byte types (Printable, Teletex, IA5, Visible) become one
 * text; NumericString and the unknown types are compared by tag and bytes, as OpenSSL does.
 */
function nameValue(node: Node): string {
  const v = node.value;
  let text: string | null = null;
  try {
    // `ignoreBOM`: a byte order mark stays a character of the name and is not dropped
    if (node.tag === 0x0c)
      text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(v);
    else if (node.tag === 0x1e)
      text = new TextDecoder('utf-16be', { fatal: true, ignoreBOM: true }).decode(v);
    else if (node.tag === 0x1c) text = ucs4(v);
    else if (node.tag === 0x13 || node.tag === 0x14 || node.tag === 0x16 || node.tag === 0x1a)
      text = latin1(v);
  } catch {
    text = null;
  }
  if (text === null)
    return `#${node.tag.toString(16)}:${Array.from(v, (b) => b.toString(16).padStart(2, '0')).join('')}`;
  // RFC 5280 § 7.1, simplified as in OpenSSL: ASCII letters case-insensitive; a run of ASCII white space (space,
  // tab, line feed, vertical tab, form feed, carriage return) becomes one space, outer runs are dropped. No other
  // character is white space (U+00A0, U+2003, a byte order mark stay what they are)
  const folded = text
    .replace(/[A-Z]/g, (c) => c.toLowerCase())
    .replace(OUTER_SPACE, '')
    .replace(INNER_SPACE, ' ');
  return `s:${folded}`;
}

const canonicalNames = new WeakMap<Uint8Array, string[] | null>();

/**
 * The name as a list of comparable texts, one per RDN (attribute types exact, values as `nameValue`, the
 * attributes of a multi-valued RDN sorted), or null when unreadable. Two names are the same when the lists are.
 */
export function canonicalRdns(name: Uint8Array): string[] | null {
  const known = canonicalNames.get(name);
  if (known !== undefined) return known;
  let out: string[] | null;
  try {
    out = children(expect(parseDer(name), TAG.sequence)).map((rdn) =>
      JSON.stringify(
        children(expect(rdn, TAG.set))
          .map((atv) => {
            const parts = children(expect(atv, TAG.sequence));
            if (parts.length !== 2) throw new ReaderError('bad-structure'); // type and value, nothing else
            return `${oid(parts[0]!)}=${nameValue(parts[1]!)}`;
          })
          .sort(),
      ),
    );
  } catch {
    out = null;
  }
  canonicalNames.set(name, out);
  return out;
}

/**
 * Whether two distinguished names (DER) name the same party, by the simplified rule of RFC 5280 § 7.1:
 * attribute types exact; values decoded (UTF8String, PrintableString, IA5String, TeletexString, BMPString),
 * ASCII letters case-insensitive, outer spaces removed, inner runs of spaces collapsed; an unknown value type
 * is compared by its bytes. A name that cannot be read is compared byte for byte. This only picks which
 * issuer candidates are tried: the signature against the candidate's key decides.
 */
export function sameName(a: Uint8Array, b: Uint8Array): boolean {
  if (equalBytes(a, b)) return true;
  const x = canonicalRdns(a);
  const y = canonicalRdns(b);
  return x !== null && y !== null && x.length === y.length && x.every((r, i) => r === y[i]);
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
