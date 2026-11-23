import { toHex, trimZeros } from './bytes.ts';
import {
  TAG,
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
import { HASHES, OID, type HashName } from './oids.ts';
import { ReaderError, fail, guard, ok, type Result } from './result.ts';
import { parseCertificate, type Certificate } from './x509.ts';

/** The content of a time stamp token (`TSTInfo`, RFC 3161 § 2.4.2). */
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
}

export interface SignerParts {
  /** Issuer name (DER) and serial of the signing certificate. */
  issuer: Uint8Array;
  serial: Uint8Array;
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
  certificates: Certificate[];
  signer: SignerParts;
}

/** Most certificates a token may carry. */
export const MAX_CERTIFICATES = 16;

function readTstInfo(der: Uint8Array): TstInfo {
  const f = children(expect(parseDer(der), TAG.sequence));
  if (f.length < 5 || integerNumber(f[0]!) !== 1) throw new ReaderError('bad-tst-info');
  const policy = oid(f[1]!);
  const imprintParts = children(expect(f[2], TAG.sequence));
  const hashOid = oid(children(expect(imprintParts[0], TAG.sequence))[0]!);
  const imprint = octets(imprintParts[1]!);
  const serial = toHex(trimZeros(unsignedBytes(f[3]!)));
  const genTime = time(expect(f[4], TAG.generalizedTime));
  let accuracyMs: number | null = null;
  let nonce: Uint8Array | null = null;
  for (const n of f.slice(5)) {
    if (n.tag === TAG.sequence && accuracyMs === null) {
      let ms = 0;
      for (const part of children(n)) {
        if (part.tag === TAG.integer) ms += integerNumber(part) * 1000;
        else if (part.tag === 0x80) ms += integerNumber({ ...part, tag: TAG.integer });
        else if (part.tag === 0x81) ms += integerNumber({ ...part, tag: TAG.integer }) / 1000;
        else throw new ReaderError('bad-tst-info');
      }
      accuracyMs = ms;
    } else if (n.tag === TAG.integer && nonce === null) {
      nonce = trimZeros(unsignedBytes(n));
    } else if (n.tag === TAG.boolean || n.tag === ctx(0) || n.tag === ctx(1)) {
      if (n.tag === TAG.boolean) boolean(n);
    } else {
      throw new ReaderError('bad-tst-info');
    }
  }
  const hash = HASHES[hashOid];
  if (hash && imprint.length !== hash.bytes) throw new ReaderError('bad-tst-info');
  return {
    policy,
    hashOid,
    hashName: hash?.name ?? null,
    imprint,
    serial,
    genTime,
    accuracyMs,
    nonce,
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
  if (sd[i]?.tag === ctx(0)) {
    const certs = children(sd[i]!);
    if (certs.length > MAX_CERTIFICATES) throw new ReaderError('too-large');
    for (const c of certs) if (c.tag === TAG.sequence) certificates.push(parseCertificate(c.raw));
    i += 1;
  }
  if (sd[i]?.tag === ctx(1)) i += 1; // revocation lists: ignored
  const signers = children(expect(sd[i], TAG.set));
  if (sd.length !== i + 1) throw new ReaderError('bad-structure');
  if (signers.length !== 1) throw new ReaderError('one-signer-required');
  const s = children(expect(signers[0], TAG.sequence));
  const version = integerNumber(s[0]!);
  const sid = children(expect(s[1], TAG.sequence)); // issuer and serial number only
  if (version !== 1) throw new ReaderError('unsupported-version');
  const issuer = expect(sid[0], TAG.sequence).raw;
  const serial = trimZeros(unsignedBytes(sid[1]!));
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
    signer: { issuer, serial, digestOid, signedAttributesDer, attributes, signatureOid, signature },
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
