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
  /** The moment at which certificates must be valid. Default: the token's own time. Must be a valid Date. */
  at?: Date;
  /** The current time: a token from the future (beyond the skew) is refused. Default: not checked. Given but not a valid Date: `bad-options`. */
  now?: Date;
  /** Allowed difference between the token time and `now`. Default 5 minutes; a number >= 0 (Infinity allowed), else `bad-options`. */
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
  const parts = children(expect(parseDer(der), TAG.sequence));
  if (parts.length !== 2) throw new ReaderError('signature-invalid');
  const [r, s] = parts.map((n) => {
    const bytes = integerBytes(n);
    if ((bytes[0]! & 0x80) !== 0) throw new ReaderError('signature-invalid'); // negative
    return trimZeros(bytes);
  });
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

const dedupe = (certs: readonly Certificate[]): Certificate[] =>
  certs.filter((c, i) => certs.findIndex((d) => same(d.raw, c.raw)) === i);

const isValidDate = (d: unknown): d is Date =>
  Object.prototype.toString.call(d) === '[object Date]' && Number.isFinite((d as Date).getTime());

const NONCE_BYTES = { min: 1, max: 16 } as const;

/** The options as read once and checked; the rest of the verification uses only this. */
interface OptionSnapshot {
  readonly now: number | undefined;
  readonly at: number | undefined;
  readonly maxSkewMs: number;
  readonly expectedNonce: Uint8Array | undefined;
  readonly requireCriticalEku: boolean;
}

/**
 * Reads every option exactly once into a frozen snapshot and checks it: a given option must be usable (no
 * silent skipping of a check because of a bad value). Only own properties count (nothing inherited from
 * `Object.prototype`); a getter is read once and one that throws gives `bad-options`; arrays and
 * functions are refused; `Date` values become milliseconds and the nonce is copied.
 */
function checkOptions(options: unknown): OptionSnapshot {
  const bad = () => new ReaderError('bad-options');
  const snapshot = (read: (key: string) => unknown): OptionSnapshot => {
    const now = read('now');
    const at = read('at');
    const skew = read('maxSkewMs');
    const nonce = read('expectedNonce');
    const critical = read('requireCriticalEku');
    if (now !== undefined && !isValidDate(now)) throw bad();
    if (at !== undefined && !isValidDate(at)) throw bad();
    if (skew !== undefined && (typeof skew !== 'number' || Number.isNaN(skew) || skew < 0)) {
      throw bad();
    }
    if (nonce !== undefined && !(nonce instanceof Uint8Array)) throw bad();
    const nonceCopy = nonce === undefined ? undefined : Uint8Array.from(nonce as Uint8Array);
    if (nonceCopy && (nonceCopy.length < NONCE_BYTES.min || nonceCopy.length > NONCE_BYTES.max)) {
      throw bad();
    }
    if (critical !== undefined && typeof critical !== 'boolean') throw bad();
    return Object.freeze({
      now: (now as Date | undefined)?.getTime(),
      at: (at as Date | undefined)?.getTime(),
      maxSkewMs: skew ?? DEFAULT_SKEW_MS,
      expectedNonce: nonceCopy,
      requireCriticalEku: critical ?? true,
    });
  };
  if (options === undefined) return snapshot(() => undefined);
  if (typeof options !== 'object' || options === null || Array.isArray(options)) throw bad();
  const o = options as Record<string, unknown>;
  try {
    return snapshot((key) => (Object.hasOwn(o, key) ? o[key] : undefined));
  } catch (e) {
    throw e instanceof ReaderError ? e : bad(); // a getter or proxy trap that throws
  }
}

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

const MAX_CANDIDATES = 8; // usable, signature-valid issuer candidates tried per certificate
const MAX_SIGNATURE_CHECKS = 64; // signature verifications for the whole chain search

/** Why a candidate issuer is unusable at time `at`, or null when it is fine. */
function issuerFlaw(issuer: Certificate, anchors: readonly Certificate[], at: number) {
  if (issuer.isCa !== true || (issuer.keyUsage !== null && (issuer.keyUsage & 0x04) === 0)) {
    return 'not-a-ca' as const;
  }
  if (!validAt(issuer, at)) return 'certificate-not-valid-at-time' as const;
  if (issuer.unknownCritical && !anchors.some((a) => same(a.raw, issuer.raw))) {
    return 'bad-certificate' as const; // a trust anchor is the caller's decision, not checked
  }
  return null;
}

/**
 * Builds the chain from `signer` up to a trust anchor. Every usable, signature-valid candidate issuer is
 * tried (depth, usable candidates per step and signature checks are bounded), so a look-alike certificate
 * with the same name cannot hide the real intermediate. The cheap checks (`issuerFlaw`) come before the
 * signature check: an unusable look-alike costs no signature check and does not count against
 * MAX_CANDIDATES; it is only verified (once per step) when no usable candidate exists, to report why.
 * Returns the number of certificates (anchor included) or throws the reason of the first failed branch.
 */
async function buildChain(
  signer: Certificate,
  anchors: readonly Certificate[],
  pool: readonly Certificate[],
  at: number,
): Promise<number> {
  let checks = 0;
  let firstFailure: ReaderError | null = null;
  const remember = (reason: ConstructorParameters<typeof ReaderError>[0]) => {
    firstFailure ??= new ReaderError(reason);
  };
  const walk = async (
    current: Certificate,
    length: number,
    path: readonly Certificate[],
  ): Promise<number | null> => {
    if (anchors.some((a) => same(a.raw, current.raw))) return length;
    if (length > MAX_CHAIN) {
      remember('chain-too-long');
      return null;
    }
    const verifies = async (candidate: Certificate): Promise<boolean> => {
      checks += 1;
      try {
        return await verifyWithKey(
          candidate,
          current.signatureOid,
          null,
          current.tbs,
          current.signature,
        );
      } catch {
        return false; // an unsupported key or signature: try the next candidate
      }
    };
    const named = SIGNATURES[current.signatureOid]?.hash
      ? pool.filter(
          (c) => same(c.subject, current.issuer) && !path.some((p) => same(p.raw, c.raw)), // not self-signed, no loop
        )
      : [];
    const usable: Certificate[] = [];
    const flawed: { candidate: Certificate; flaw: NonNullable<ReturnType<typeof issuerFlaw>> }[] =
      [];
    for (const candidate of named) {
      const flaw = issuerFlaw(candidate, anchors, at);
      if (flaw) flawed.push({ candidate, flaw });
      else usable.push(candidate);
    }
    let found = 0;
    for (const candidate of usable) {
      if (checks >= MAX_SIGNATURE_CHECKS || found >= MAX_CANDIDATES) break;
      if (!(await verifies(candidate))) continue;
      found += 1;
      const result = await walk(candidate, length + 1, [...path, candidate]);
      if (result !== null) return result;
    }
    if (found === 0) {
      // nothing usable signed it: report why the first look-alike that did sign it is unusable
      for (const { candidate, flaw } of flawed) {
        if (checks >= MAX_SIGNATURE_CHECKS) break;
        if (await verifies(candidate)) {
          remember(flaw);
          found += 1;
          break;
        }
      }
    }
    if (found === 0) remember('untrusted-chain');
    return null;
  };
  const length = await walk(signer, 1, [signer]);
  if (length !== null) return length;
  throw firstFailure ?? new ReaderError('untrusted-chain');
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
    const opts = checkOptions(options);
    const token = readToken(tokenBytes);
    const info: TstInfo = token.info;
    if (info.hashName !== 'SHA-256') throw new ReaderError('unsupported-hash');
    if (!same(info.imprint, expectedSha256)) throw new ReaderError('imprint-mismatch');
    if (opts.expectedNonce !== undefined) {
      const want = trimZeros(opts.expectedNonce);
      if (!info.nonce || !same(info.nonce, want)) throw new ReaderError('nonce-mismatch');
    }
    if (opts.now !== undefined && info.genTime > opts.now + opts.maxSkewMs) {
      throw new ReaderError('time-in-future');
    }
    const at = opts.at ?? info.genTime;

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
      eku.oids.length !== 1 || // RFC 3161 § 2.3: exactly one purpose, id-kp-timeStamping
      eku.oids[0] !== OID.ekuTimeStamping ||
      (opts.requireCriticalEku && !eku.critical)
    ) {
      throw new ReaderError('bad-eku');
    }
    if (signer.unknownCritical && !anchors.some((a) => same(a.raw, signer.raw))) {
      throw new ReaderError('bad-certificate');
    }
    if (signer.keyUsage !== null && (signer.keyUsage & 0xc0) === 0)
      throw new ReaderError('bad-eku');
    if (!validAt(signer, at)) throw new ReaderError('certificate-not-valid-at-time');

    // chain to a trust anchor
    const pool = dedupe([...anchors, ...token.certificates]); // anchors first: a cross-signed twin of an anchor must not win
    const length = await buildChain(signer, anchors, pool, at);
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
