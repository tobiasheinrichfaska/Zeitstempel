import { equalBytes, trimZeros } from './bytes.ts';
import { TAG, children, expect, integerBytes, octets, oid, parseDer } from './der.ts';
import { CURVES, HASHES, OID, SIGNATURES, type HashName } from './oids.ts';
import { ReaderError, fail, guard, ok, type Result } from './result.ts';
import { readToken, type ParsedToken, type TstInfo } from './token.ts';
import { parsePemCertificates, type Certificate } from './x509.ts';

/** Trusted root (or intermediate) certificates, as PEM text. The caller decides whom to trust. */
export type TrustAnchors = readonly string[];

export interface VerifyOptions {
  /** The nonce that was sent. When given, the token must carry exactly this nonce. */
  expectedNonce?: Uint8Array;
  /** The moment at which certificates must be valid. Default: the token's own time. */
  at?: Date;
  /** The current time: a token from the future (beyond the skew) is refused. Default: not checked. */
  now?: Date;
  /** Allowed difference between the token time and `now`. Default 5 minutes. */
  maxSkewMs?: number;
  /** RFC 3161 wants the extended key usage to be critical. Default true. */
  requireCriticalEku?: boolean;
}

export interface VerifiedTimestamp {
  /** The time the service attests, ISO 8601 (UTC). */
  genTime: string;
  accuracyMs: number | null;
  policy: string;
  serial: string;
  /** The signing certificate's subject as `CN=…, O=…` (readable, not for comparisons). */
  signer: string;
  /** Number of certificates from the signer up to the trust anchor (anchor included). */
  chainLength: number;
}

const MAX_CHAIN = 6;
const DEFAULT_SKEW_MS = 5 * 60 * 1000;

const subtle = (): SubtleCrypto => {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new ReaderError('unsupported-signature');
  return s;
};

async function digest(name: HashName, data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest(name, data as BufferSource));
}

/** DER `ECDSA-Sig-Value` → the fixed-size `r || s` that WebCrypto verifies. */
function ecdsaRaw(der: Uint8Array, size: number): Uint8Array {
  const [r, s] = children(expect(parseDer(der), TAG.sequence)).map((n) =>
    trimZeros(integerBytes(n)),
  );
  if (!r || !s || r.length > size || s.length > size) throw new ReaderError('signature-invalid');
  const out = new Uint8Array(size * 2);
  out.set(r, size - r.length);
  out.set(s, size * 2 - s.length);
  return out;
}

/** Verifies `signature` over `data` with the key in `cert`; `hash` names the digest. */
async function verifyWithKey(
  cert: Certificate,
  algOid: string,
  fallbackHash: HashName | null,
  data: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  const alg = SIGNATURES[algOid];
  const hash = alg?.hash ?? fallbackHash;
  if (!alg || !hash || hash === 'SHA-1') throw new ReaderError('unsupported-signature');
  try {
    if (alg.kind === 'rsa') {
      if (cert.keyOid !== OID.rsaEncryption) throw new ReaderError('unsupported-signature');
      const key = await subtle().importKey(
        'spki',
        cert.spki as BufferSource,
        { name: 'RSASSA-PKCS1-v1_5', hash },
        false,
        ['verify'],
      );
      return await subtle().verify(
        'RSASSA-PKCS1-v1_5',
        key,
        signature as BufferSource,
        data as BufferSource,
      );
    }
    const curve = cert.curveOid ? CURVES[cert.curveOid] : undefined;
    if (cert.keyOid !== OID.ecPublicKey || !curve) throw new ReaderError('unsupported-signature');
    const key = await subtle().importKey(
      'spki',
      cert.spki as BufferSource,
      { name: 'ECDSA', namedCurve: curve.name },
      false,
      ['verify'],
    );
    const raw = ecdsaRaw(signature, curve.size);
    return await subtle().verify(
      { name: 'ECDSA', hash },
      key,
      raw as BufferSource,
      data as BufferSource,
    );
  } catch (e) {
    if (e instanceof ReaderError) throw e;
    throw new ReaderError('unsupported-signature');
  }
}

/** Readable subject: the common name and the organisation, best effort. */
export function nameToString(name: Uint8Array): string {
  const parts: string[] = [];
  try {
    for (const rdn of children(expect(parseDer(name), TAG.sequence))) {
      for (const atv of children(rdn)) {
        const [id, value] = children(atv);
        const key = { '2.5.4.3': 'CN', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.6': 'C' }[
          oid(id!)
        ];
        if (key) parts.push(`${key}=${new TextDecoder().decode(value!.value)}`);
      }
    }
  } catch {
    return '?';
  }
  return parts.join(', ');
}

const same = (a: Uint8Array, b: Uint8Array) => equalBytes(a, b);

async function checkSigningCertificate(token: ParsedToken, signer: Certificate): Promise<void> {
  const attrs = token.signer.attributes;
  const v2 = attrs.get(OID.signingCertificateV2);
  const v1 = attrs.get(OID.signingCertificate);
  const node = v2 ?? v1;
  if (!node) throw new ReaderError('signing-certificate-missing');
  const certs = children(expect(children(expect(node, TAG.sequence))[0], TAG.sequence));
  const first = children(expect(certs[0], TAG.sequence));
  let hash: HashName = v2 ? 'SHA-256' : 'SHA-1';
  let at = 0;
  if (v2 && first[0]?.tag === TAG.sequence) {
    hash = HASHES[oid(children(first[0])[0]!)]?.name ?? hash;
    at = 1;
  }
  const expected = octets(first[at]!);
  if (!same(expected, await digest(hash, signer.raw))) {
    throw new ReaderError('signing-certificate-mismatch');
  }
}

function validAt(cert: Certificate, at: number): boolean {
  return cert.notBefore <= at && at <= cert.notAfter;
}

/** Looks for the issuer of `cert` among `pool` whose key verifies `cert`'s signature. */
async function findIssuer(
  cert: Certificate,
  pool: readonly Certificate[],
): Promise<Certificate | null> {
  for (const candidate of pool) {
    if (!same(candidate.subject, cert.issuer)) continue;
    const alg = SIGNATURES[cert.signatureOid];
    if (!alg?.hash) continue;
    try {
      if (await verifyWithKey(candidate, cert.signatureOid, null, cert.tbs, cert.signature)) {
        return candidate;
      }
    } catch {
      /* an unsupported key or signature: try the next candidate */
    }
  }
  return null;
}

/**
 * Verifies a time stamp token against the SHA-256 hash it must cover:
 * imprint, nonce (when given), the CMS signature, the signing-certificate attribute, the key usage of
 * the signer, the validity of every certificate at the stamped time, and a chain that ends in one
 * of the given trust anchors. Revocation is NOT checked; name constraints and path length are not
 * evaluated (see docs/grenzen.md). Never throws.
 */
export async function verifyTimestampToken(
  tokenBytes: Uint8Array,
  expectedSha256: Uint8Array,
  trust: TrustAnchors,
  options: VerifyOptions = {},
): Promise<Result<VerifiedTimestamp>> {
  if (!(expectedSha256 instanceof Uint8Array) || expectedSha256.length !== 32)
    return fail('bad-hash');
  const anchorsRead = guard(() => trust.flatMap((pem) => parsePemCertificates(pem)));
  if (!anchorsRead.ok) return anchorsRead;
  const anchors = anchorsRead.value;
  try {
    const token = readToken(tokenBytes);
    const info: TstInfo = token.info;
    if (info.hashName !== 'SHA-256') throw new ReaderError('unsupported-hash');
    if (!same(info.imprint, expectedSha256)) throw new ReaderError('imprint-mismatch');
    if (options.expectedNonce) {
      const want = trimZeros(options.expectedNonce);
      if (!info.nonce || !same(info.nonce, want)) throw new ReaderError('nonce-mismatch');
    }
    if (
      options.now &&
      info.genTime > options.now.getTime() + (options.maxSkewMs ?? DEFAULT_SKEW_MS)
    ) {
      throw new ReaderError('time-in-future');
    }
    const at = (options.at ?? new Date(info.genTime)).getTime();

    // signed attributes: content type, message digest, signing certificate
    const attrs = token.signer.attributes;
    const contentType = attrs.get(OID.contentType);
    if (!contentType || oid(contentType) !== OID.tstInfo) throw new ReaderError('bad-content-type');
    const digestHash = HASHES[token.signer.digestOid]?.name;
    if (!digestHash || digestHash === 'SHA-1') throw new ReaderError('unsupported-hash');
    const md = attrs.get(OID.messageDigest);
    if (!md || !same(octets(md), await digest(digestHash, token.content))) {
      throw new ReaderError('message-digest-mismatch');
    }

    // signer certificate
    const signer = token.certificates.find(
      (c) => same(c.issuer, token.signer.issuer) && same(trimZeros(c.serial), token.signer.serial),
    );
    if (!signer) throw new ReaderError('signer-certificate-missing');
    await checkSigningCertificate(token, signer);
    if (
      !(await verifyWithKey(
        signer,
        token.signer.signatureOid,
        digestHash,
        token.signer.signedAttributesDer,
        token.signer.signature,
      ))
    ) {
      throw new ReaderError('signature-invalid');
    }
    const eku = signer.eku;
    if (
      !eku ||
      !eku.oids.includes(OID.ekuTimeStamping) ||
      ((options.requireCriticalEku ?? true) && !eku.critical)
    ) {
      throw new ReaderError('bad-eku');
    }
    if (signer.keyUsage !== null && (signer.keyUsage & 0xc0) === 0)
      throw new ReaderError('bad-eku');
    if (!validAt(signer, at)) throw new ReaderError('certificate-not-valid-at-time');

    // chain to a trust anchor
    let current = signer;
    let length = 1;
    const pool = [...anchors, ...token.certificates]; // anchors first: a cross-signed twin of an anchor must not win
    for (;;) {
      const anchor = anchors.find((a) => same(a.raw, current.raw));
      if (anchor) break;
      if (length > MAX_CHAIN) throw new ReaderError('chain-too-long');
      const issuer = await findIssuer(current, pool);
      if (!issuer) throw new ReaderError('untrusted-chain');
      if (issuer.isCa !== true || (issuer.keyUsage !== null && (issuer.keyUsage & 0x04) === 0)) {
        throw new ReaderError('not-a-ca');
      }
      if (!validAt(issuer, at)) throw new ReaderError('certificate-not-valid-at-time');
      length += 1;
      if (same(issuer.raw, current.raw)) throw new ReaderError('untrusted-chain'); // self-signed, not an anchor
      current = issuer;
      if (anchors.some((a) => same(a.raw, current.raw))) break;
    }
    return ok({
      genTime: new Date(info.genTime).toISOString(),
      accuracyMs: info.accuracyMs,
      policy: info.policy,
      serial: info.serial,
      signer: nameToString(signer.subject),
      chainLength: length,
    });
  } catch (e) {
    return fail(e instanceof ReaderError ? e.reason : 'malformed');
  }
}
