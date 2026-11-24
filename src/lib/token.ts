import { toHex, trimZeros } from './bytes.ts';
import {
  TAG,
  boolean,
  children,
  ctx,
  ctxPrimitive,
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
import { HASHES, OID, SKI_BYTES, type HashName } from './oids.ts';
import { ReaderError, fail, guard, ok, type Result } from './result.ts';
import { parseCertificate, type Certificate } from './x509.ts';

/** The content of a time stamp token (`TSTInfo`, RFC 3161 § 2.4.2), read as the schema (fixed order, each field once). */
export interface TstInfo {
  policy: string;
  hashOid: string;
  hashName: HashName | null;
  imprint: Uint8Array;
  /** Serial number as hex. */
  serial: string;
  genTime: number;
  /** Total accuracy in milliseconds when given. */
  accuracyMs: number | null;
  nonce: Uint8Array | null;
  /** The `tsa` field: the DER of the `GeneralName` it holds (verified against the signer by `verifyTimestampToken`), or null. */
  tsa: Uint8Array | null;
}

/**
 * How the SignerInfo names the signing certificate (`SignerIdentifier`, RFC 5652 § 5.3): by issuer and serial number
 * (SignerInfo version 1) or by `subjectKeyIdentifier` `[0]` (version 3).
 */
export type SignerId =
  | { kind: 'issuerAndSerialNumber'; issuer: Uint8Array; serial: Uint8Array }
  | { kind: 'subjectKeyIdentifier'; ski: Uint8Array };

export interface SignerParts {
  /** The signing certificate as named by the SignerInfo. */
  sid: SignerId;
  digestOid: string;
  /** The signed attributes as the SET OF that was signed (tag 0x31), and the parsed attributes. */
  signedAttributesDer: Uint8Array;
  attributes: Map<string, Node>;
  signatureOid: string;
  signature: Uint8Array;
}

export interface ParsedToken {
  raw: Uint8Array;
  /** DER of the TSTInfo (the signed content). */
  content: Uint8Array;
  info: TstInfo;
  /** The readable certificates of the token. */
  certificates: Certificate[];
  /** Certificates in the token that could not be read: skipped, never a candidate (they still count against the limit). */
  skippedCertificates: number;
  signer: SignerParts;
}

/** Most certificates a token may carry. */
export const MAX_CERTIFICATES = 16;

const bad = () => new ReaderError('bad-tst-info');

/** Any reader error inside the optional fields of the TSTInfo is `bad-tst-info`. */
function inTstInfo<T>(run: () => T): T {
  try {
    return run();
  } catch {
    throw bad();
  }
}

/** `Accuracy` (RFC 3161 § 2.4.2): seconds, `[0]` millis (1..999), `[1]` micros (1..999), each at most once, in this order. */
function readAccuracy(node: Node): number {
  const parts = children(node);
  let at = 0;
  let ms = 0;
  if (parts[at]?.tag === TAG.integer) {
    ms += integerNumber(parts[at]!) * 1000;
    at += 1;
  }
  for (const [tag, scale] of [
    [ctxPrimitive(0), 1],
    [ctxPrimitive(1), 1000],
  ] as const) {
    const part = parts[at];
    if (part?.tag !== tag) continue;
    const v = integerNumber({ ...part, tag: TAG.integer });
    if (v < 1 || v > 999) throw bad();
    ms += v / scale;
    at += 1;
  }
  if (at !== parts.length) throw bad();
  return ms;
}

/** Checks that a `GeneralName` (RFC 5280 § 4.2.1.6) is one of the nine forms and shaped as that form. */
function checkGeneralName(gn: Node): void {
  switch (gn.tag) {
    case ctx(0): {
      // otherName: type-id OID, value [0] EXPLICIT
      const parts = children(gn);
      if (parts.length !== 2) throw bad();
      oid(parts[0]!);
      expect(parts[1], ctx(0));
      return;
    }
    case ctxPrimitive(1): // rfc822Name
    case ctxPrimitive(2): // dNSName
    case ctxPrimitive(6): // uniformResourceIdentifier
      if (gn.value.length === 0 || gn.value.some((b) => b > 0x7f)) throw bad(); // IA5String
      return;
    case ctx(3): // x400Address, ctx(5) ediPartyName: only checked to be well-formed
    case ctx(5):
      children(gn);
      return;
    case ctx(4): // directoryName: an EXPLICIT Name
      expect(inner(gn), TAG.sequence);
      return;
    case ctxPrimitive(7): // iPAddress
      if (gn.value.length !== 4 && gn.value.length !== 16) throw bad();
      return;
    case ctxPrimitive(8): // registeredID
      oid({ ...gn, tag: TAG.oid });
      return;
    default:
      throw bad();
  }
}

/** `Extensions` of the TSTInfo: at least one `Extension` (OID, critical only when TRUE, value). Contents are not judged. */
function checkExtensions(node: Node): void {
  const list = children(node);
  if (list.length === 0) throw bad();
  for (const e of list) {
    const parts = children(expect(e, TAG.sequence));
    if (parts.length < 2 || parts.length > 3) throw bad();
    oid(parts[0]!);
    if (parts.length === 3 && !boolean(parts[1]!)) throw bad(); // DER: DEFAULT FALSE is not written
    octets(parts[parts.length - 1]!);
  }
}

/**
 * Reads the `TSTInfo` as the schema of RFC 3161 § 2.4.2: version, policy, messageImprint, serialNumber, genTime,
 * then accuracy?, ordering?, nonce?, tsa [0]?, extensions [1]? each at most once, in this order, nothing else.
 */
function readTstInfo(der: Uint8Array): TstInfo {
  const f = children(expect(parseDer(der), TAG.sequence));
  if (f.length < 5 || integerNumber(f[0]!) !== 1) throw bad();
  const policy = oid(f[1]!);
  const imprintParts = children(expect(f[2], TAG.sequence));
  if (imprintParts.length !== 2) throw bad();
  const algParts = children(expect(imprintParts[0], TAG.sequence));
  if (algParts.length < 1 || algParts.length > 2) throw bad();
  if (algParts[1] && (algParts[1].tag !== TAG.null || algParts[1].value.length !== 0)) throw bad();
  const hashOid = oid(algParts[0]!);
  const imprint = octets(imprintParts[1]!);
  const serial = toHex(trimZeros(unsignedBytes(f[3]!)));
  const genTime = time(expect(f[4], TAG.generalizedTime));
  let at = 5;
  let accuracyMs: number | null = null;
  if (f[at]?.tag === TAG.sequence) {
    accuracyMs = readAccuracy(f[at]!);
    at += 1;
  }
  if (f[at]?.tag === TAG.boolean) {
    if (!boolean(f[at]!)) throw bad(); // ordering FALSE is the DEFAULT: DER does not write it
    at += 1;
  }
  let nonce: Uint8Array | null = null;
  if (f[at]?.tag === TAG.integer) {
    nonce = trimZeros(unsignedBytes(f[at]!));
    at += 1;
  }
  let tsa: Uint8Array | null = null;
  if (f[at]?.tag === ctx(0)) {
    const names = children(f[at]!);
    if (names.length !== 1) throw bad();
    inTstInfo(() => checkGeneralName(names[0]!));
    tsa = names[0]!.raw;
    at += 1;
  }
  if (f[at]?.tag === ctx(1)) {
    inTstInfo(() => checkExtensions(f[at]!));
    at += 1;
  }
  if (at !== f.length) throw bad();
  const hash = HASHES[hashOid];
  if (hash && imprint.length !== hash.bytes) throw bad();
  return {
    policy,
    hashOid,
    hashName: hash?.name ?? null,
    imprint,
    serial,
    genTime,
    accuracyMs,
    nonce,
    tsa,
  };
}

function readAttributes(set: Node): Map<string, Node> {
  const map = new Map<string, Node>();
  for (const attr of children(expect(set, TAG.set))) {
    const [id, values] = children(expect(attr, TAG.sequence));
    const key = oid(id!);
    const vs = children(expect(values, TAG.set));
    if (vs.length !== 1 || map.has(key)) throw new ReaderError('bad-structure');
    map.set(key, vs[0]!);
  }
  return map;
}

/**
 * The `SignerIdentifier` of a SignerInfo (RFC 5652 § 5.3): version 1 goes with `issuerAndSerialNumber` (a
 * SEQUENCE of issuer and serial number), version 3 with `subjectKeyIdentifier` (`[0]` IMPLICIT OCTET STRING,
 * primitive, 1 to 64 bytes). Another version, or a form that does not belong to the version, is
 * `unsupported-version`; any other shape is `bad-structure`.
 */
function readSignerId(version: number, node: Node | undefined): SignerId {
  if (version !== 1 && version !== 3) throw new ReaderError('unsupported-version');
  if (node?.tag === TAG.sequence) {
    if (version !== 1) throw new ReaderError('unsupported-version');
    const parts = children(node);
    const issuer = expect(parts[0], TAG.sequence).raw;
    const serial = trimZeros(unsignedBytes(parts[1]!));
    return { kind: 'issuerAndSerialNumber', issuer, serial };
  }
  if (node?.tag === ctxPrimitive(0)) {
    if (version !== 3) throw new ReaderError('unsupported-version');
    if (node.value.length < SKI_BYTES.min || node.value.length > SKI_BYTES.max) {
      throw new ReaderError('bad-structure');
    }
    return { kind: 'subjectKeyIdentifier', ski: node.value };
  }
  throw new ReaderError('bad-structure');
}

/** Reads a token (`ContentInfo` holding `SignedData` over a `TSTInfo`). Throws `ReaderError`. */
export function readToken(bytes: Uint8Array): ParsedToken {
  try {
    return readTokenStrict(bytes);
  } catch (e) {
    throw e instanceof ReaderError ? e : new ReaderError('malformed');
  }
}

function readTokenStrict(bytes: Uint8Array): ParsedToken {
  const ci = children(expect(parseDer(bytes), TAG.sequence));
  if (oid(ci[0]!) !== OID.signedData || ci.length !== 2) throw new ReaderError('not-signed-data');
  const sd = children(expect(inner(expect(ci[1], ctx(0))), TAG.sequence));
  if (integerNumber(sd[0]!) !== 3) throw new ReaderError('unsupported-version');
  const declaredDigests = children(expect(sd[1], TAG.set)).map((n) =>
    oid(children(expect(n, TAG.sequence))[0]!),
  );
  const encap = children(expect(sd[2], TAG.sequence));
  if (oid(encap[0]!) !== OID.tstInfo) throw new ReaderError('bad-content-type');
  const content = octets(inner(expect(encap[1], ctx(0))));
  let i = 3;
  const certificates: Certificate[] = [];
  let skippedCertificates = 0;
  if (sd[i]?.tag === ctx(0)) {
    const certs = children(sd[i]!);
    if (certs.length > MAX_CERTIFICATES) throw new ReaderError('too-large');
    for (const c of certs) {
      if (c.tag !== TAG.sequence) continue;
      try {
        certificates.push(parseCertificate(c.raw));
      } catch (e) {
        // an unreadable extra certificate is no reason to refuse the token: it is no candidate; the signer's
        // own certificate is looked up later (`signer-certificate-missing`), the anchors are read strictly
        if (!(e instanceof ReaderError)) throw e;
        skippedCertificates += 1;
      }
    }
    i += 1;
  }
  if (sd[i]?.tag === ctx(1)) i += 1; // revocation lists: ignored
  const signers = children(expect(sd[i], TAG.set));
  if (sd.length !== i + 1) throw new ReaderError('bad-structure');
  if (signers.length !== 1) throw new ReaderError('one-signer-required');
  const s = children(expect(signers[0], TAG.sequence));
  const version = integerNumber(s[0]!);
  const sid = readSignerId(version, s[1]);
  const digestOid = oid(children(expect(s[2], TAG.sequence))[0]!);
  if (!declaredDigests.includes(digestOid)) throw new ReaderError('bad-structure');
  const attrNode = s[3];
  if (!attrNode || attrNode.tag !== ctx(0)) throw new ReaderError('signed-attributes-missing');
  const signedAttributesDer = Uint8Array.from(attrNode.raw);
  signedAttributesDer[0] = TAG.set; // the signature covers the SET OF, not the [0] tag
  const attributes = readAttributes(parseDer(signedAttributesDer));
  const signatureOid = oid(children(expect(s[4], TAG.sequence))[0]!);
  const signature = octets(s[5]!);
  if (s.length > 7 || (s.length === 7 && s[6]!.tag !== ctx(1)))
    throw new ReaderError('bad-structure');
  return {
    raw: bytes,
    content,
    info: readTstInfo(content),
    certificates,
    skippedCertificates,
    signer: { sid, digestOid, signedAttributesDer, attributes, signatureOid, signature },
  };
}

/** What a `TimeStampResp` holds. `status` 0 granted, 1 granted with modifications. */
export interface TimestampResponse {
  status: number;
  /** The token (`ContentInfo`, DER): what a verifier needs. */
  token: Uint8Array;
  info: TstInfo;
}

/**
 * Reads a `TimeStampResp`. A refusal (status above 1) is `rejected` with the status number in
 * `detail`; a granted answer without a token is `no-token`.
 */
export function readTimestampResponse(bytes: Uint8Array): Result<TimestampResponse> {
  const read = guard(() => {
    const top = children(expect(parseDer(bytes), TAG.sequence));
    const statusInfo = children(expect(top[0], TAG.sequence));
    const status = integerNumber(statusInfo[0]!);
    return { top, status };
  });
  if (!read.ok) return read;
  const { top, status } = read.value;
  if (status > 1) return fail('rejected', String(status));
  if (top.length !== 2) return fail('no-token');
  const parsed = guard(() => ({ token: top[1]!.raw, parsed: readToken(top[1]!.raw) }));
  if (!parsed.ok) return parsed;
  return ok({ status, token: parsed.value.token, info: parsed.value.parsed.info });
}
