// Name constraints (RFC 5280 § 4.2.1.10, § 6.1.3 (b) and (c)): the reader of the extension and the check of a finished chain.
// Rules measured against `openssl ts -verify` 3.0.13 (tests/name-constraints.test.ts, rows F31 to F41 of docs/grenzen.md).
import { TAG, children, ctx, expect, inner, oid, ownBytes, parseDer, type Node } from './der.ts';
import { OID } from './oids.ts';
import { ReaderError } from './result.ts';
import { canonicalRdns, sameName, subjectAltNames, type Certificate } from './x509.ts';

/** Bounds: subtrees per list, bytes of a name base, names checked per certificate. */
export const NAME_CONSTRAINT_LIMITS = {
  maxSubtrees: 64,
  maxBaseBytes: 253,
  maxNames: 256,
} as const;

// GeneralName tags (context specific): the forms that are evaluated and the forms that are not
const T_EMAIL = 0x81;
const T_DNS = 0x82;
const T_DIR = 0xa4;
const T_URI = 0x86;
const T_IP = 0x87;
const UNSUPPORTED_TAGS: ReadonlySet<number> = new Set([0xa0, 0xa3, 0xa5, 0x88]); // otherName, x400Address, ediPartyName, registeredID

export interface Subtree {
  tag: number;
  /** dNSName, rfc822Name, URI: the ASCII bytes; iPAddress: address and mask (8 or 32 bytes); directoryName: unused. */
  base: Uint8Array;
  /** directoryName: the RDNs of the base name as comparable texts. */
  rdns: string[] | null;
}

export interface NameConstraints {
  permitted: Subtree[];
  excluded: Subtree[];
  /** A subtree names a form this library does not evaluate (otherName, x400Address, ediPartyName, registeredID). */
  unsupported: boolean;
  /** The GeneralName tags of those subtrees. */
  unsupportedTags: ReadonlySet<number>;
}

const bad = () => new ReaderError('bad-certificate');

function isAscii(bytes: Uint8Array): boolean {
  return bytes.every((b) => b > 0 && b < 0x80);
}

/** A mask of 4 or 16 bytes that is a prefix: ones, then zeros. */
function isPrefixMask(mask: Uint8Array): boolean {
  let zeros = false;
  for (const b of mask) {
    for (let bit = 7; bit >= 0; bit -= 1) {
      const one = ((b >> bit) & 1) === 1;
      if (zeros && one) return false;
      if (!one) zeros = true;
    }
  }
  return true;
}

function readSubtree(node: Node): { subtree: Subtree | null; tag: number } {
  const parts = children(expect(node, TAG.sequence));
  // GeneralSubtree: base, then `minimum` [0] and `maximum` [1], which RFC 5280 requires to be 0 and absent; DER
  // leaves a default out, so nothing may follow the base
  if (parts.length !== 1) throw bad();
  const base = parts[0]!;
  const tag = base.tag;
  if (UNSUPPORTED_TAGS.has(tag)) {
    // the content of the form is not looked at; `parseDer` has already walked every constructed element, so it is
    // well-formed (tests/name-constraints-gaps.test.ts)
    return { subtree: null, tag };
  }
  if (tag === T_DNS || tag === T_EMAIL || tag === T_URI) {
    if (base.value.length > NAME_CONSTRAINT_LIMITS.maxBaseBytes || !isAscii(base.value))
      throw bad();
    return { subtree: { tag, base: base.value, rdns: null }, tag };
  }
  if (tag === T_IP) {
    const n = base.value.length;
    if (n !== 8 && n !== 32) throw bad();
    if (!isPrefixMask(base.value.subarray(n / 2))) throw bad();
    return { subtree: { tag, base: base.value, rdns: null }, tag };
  }
  if (tag === T_DIR) {
    const name = expect(inner(base), TAG.sequence);
    const rdns = canonicalRdns(name.raw);
    if (!rdns) throw bad();
    return { subtree: { tag, base: name.raw, rdns }, tag };
  }
  throw bad();
}

/**
 * Reads the value of a nameConstraints extension (the DER inside its OCTET STRING) as a closed schema: at least
 * one of `permittedSubtrees` [0] and `excludedSubtrees` [1], in this order, each 1 to 64 subtrees, no `minimum`
 * or `maximum`, every base well-formed. Throws `ReaderError('bad-certificate')` and nothing else.
 */
export function parseNameConstraints(der: Uint8Array): NameConstraints {
  try {
    const root = expect(parseDer(ownBytes(der)), TAG.sequence);
    const parts = children(root);
    let at = 0;
    const out: NameConstraints = {
      permitted: [],
      excluded: [],
      unsupported: false,
      unsupportedTags: new Set<number>(),
    };
    const read = (node: Node, into: Subtree[]) => {
      const kids = children(node);
      if (kids.length < 1 || kids.length > NAME_CONSTRAINT_LIMITS.maxSubtrees) throw bad();
      for (const kid of kids) {
        const { subtree, tag } = readSubtree(kid);
        if (subtree) into.push(subtree);
        else {
          out.unsupported = true;
          (out.unsupportedTags as Set<number>).add(tag);
        }
      }
    };
    if (parts[at]?.tag === ctx(0)) read(parts[at++]!, out.permitted);
    if (parts[at]?.tag === ctx(1)) read(parts[at++]!, out.excluded);
    if (at === 0 || at !== parts.length) throw bad();
    return out;
  } catch {
    throw bad();
  }
}

// --- matching (the rules of OpenSSL's v3_ncons.c, measured) -----------------------------------------------

type Verdict = 'match' | 'no' | 'syntax';

const lower = (b: number) => (b >= 0x41 && b <= 0x5a ? b + 32 : b);
/** ASCII case-insensitive equality of `a` and `b` over `n` bytes starting at the given offsets. */
function eqNoCase(a: Uint8Array, ai: number, b: Uint8Array, bi: number, n: number): boolean {
  if (ai < 0 || bi < 0 || ai + n > a.length || bi + n > b.length) return false;
  for (let k = 0; k < n; k += 1) if (lower(a[ai + k]!) !== lower(b[bi + k]!)) return false;
  return true;
}

function matchDns(name: Uint8Array, base: Uint8Array): Verdict {
  if (base.length === 0) return 'match'; // an empty base matches every name
  if (name.length < base.length) return 'no';
  const off = name.length - base.length;
  // a longer name must add whole labels: the base starts with a dot, or a dot precedes the common part
  if (off > 0 && base[0] !== 0x2e && name[off - 1] !== 0x2e) return 'no';
  return eqNoCase(base, 0, name, off, base.length) ? 'match' : 'no';
}

function matchEmail(name: Uint8Array, base: Uint8Array): Verdict {
  // the host of a mailbox stands behind the LAST @ (the local part may be a quoted string with an @ inside)
  const at = name.lastIndexOf(0x40);
  if (at < 0) return 'syntax';
  const baseAt = base.lastIndexOf(0x40);
  if (baseAt < 0 && base.length > 0 && base[0] === 0x2e) {
    // a base that starts with a dot: any mailbox in a host below it
    return name.length > base.length &&
      eqNoCase(base, 0, name, name.length - base.length, base.length)
      ? 'match'
      : 'no';
  }
  let hostBase = 0;
  if (baseAt >= 0) {
    if (baseAt > 0) {
      // the local part is compared byte for byte
      if (baseAt !== at) return 'no';
      for (let k = 0; k < at; k += 1) if (base[k] !== name[k]) return 'no';
    }
    hostBase = baseAt + 1;
  }
  const hostLen = base.length - hostBase;
  if (hostLen !== name.length - (at + 1)) return 'no';
  return eqNoCase(base, hostBase, name, at + 1, hostLen) ? 'match' : 'no';
}

/** The host of a URI (RFC 3986 authority without user information and port), or null without `://` or a host. */
function uriHost(uri: Uint8Array): { start: number; length: number } | null {
  const colon = uri.indexOf(0x3a);
  if (colon < 0 || uri[colon + 1] !== 0x2f || uri[colon + 2] !== 0x2f) return null;
  let start = colon + 3;
  let end = start;
  while (end < uri.length && uri[end] !== 0x2f && uri[end] !== 0x3f && uri[end] !== 0x23) end += 1;
  // a backslash (a browser reads it as `/`, so the host ends there) or a second @ (user information may not hold
  // one, readers disagree on where the host starts): no host name that can be trusted
  let ats = 0;
  for (let k = start; k < end; k += 1) {
    if (uri[k] === 0x5c) return null;
    if (uri[k] === 0x40) ats += 1;
  }
  if (ats > 1) return null;
  for (let k = end - 1; k >= start; k -= 1) {
    if (uri[k] === 0x40) {
      start = k + 1; // user information ends at the last @
      break;
    }
  }
  let hostEnd = end;
  if (uri[start] === 0x5b) {
    const close = uri.indexOf(0x5d, start);
    if (close >= 0 && close < end) hostEnd = close + 1; // an IPv6 literal keeps its colons
  } else {
    for (let k = start; k < end; k += 1) {
      if (uri[k] === 0x3a) {
        hostEnd = k; // the port starts here
        break;
      }
    }
  }
  return hostEnd > start ? { start, length: hostEnd - start } : null;
}

function matchUri(name: Uint8Array, base: Uint8Array): Verdict {
  const host = uriHost(name);
  if (!host) return 'syntax';
  if (base.length > 0 && base[0] === 0x2e) {
    return host.length > base.length &&
      eqNoCase(name, host.start + host.length - base.length, base, 0, base.length)
      ? 'match'
      : 'no';
  }
  return base.length === host.length && eqNoCase(name, host.start, base, 0, host.length)
    ? 'match'
    : 'no';
}

function matchIp(name: Uint8Array, base: Uint8Array): Verdict {
  const n = base.length / 2;
  if (name.length !== n) return 'no'; // IPv4 against IPv6, or an address of another length
  for (let k = 0; k < n; k += 1) if (((name[k]! ^ base[k]!) & base[n + k]!) !== 0) return 'no';
  return 'match';
}

function matchDir(rdns: string[], base: string[]): Verdict {
  if (base.length > rdns.length) return 'no';
  return base.every((r, k) => r === rdns[k]) ? 'match' : 'no';
}

/** A name to check: the form (GeneralName tag), its bytes, for a directory name its RDNs. */
interface Name {
  tag: number;
  bytes: Uint8Array;
  rdns?: string[];
}

function matches(name: Name, st: Subtree): Verdict {
  switch (name.tag) {
    case T_DNS:
      return matchDns(name.bytes, st.base);
    case T_EMAIL:
      return matchEmail(name.bytes, st.base);
    case T_URI:
      return matchUri(name.bytes, st.base);
    case T_IP:
      return matchIp(name.bytes, st.base);
    default:
      return matchDir(name.rdns!, st.rdns!);
  }
}

/** The names of a certificate that the constraints apply to; `ReaderError('bad-certificate')` when it cannot be read. */
function namesOf(
  cert: Certificate,
  isSigner: boolean,
): { names: Name[]; sanTags: Set<number>; nulCn: boolean } {
  const names: Name[] = [];
  const sanTags = new Set<number>();
  const rdns = canonicalRdns(cert.subject);
  if (!rdns) throw bad();
  // the attributes of the subject: emailAddress is an rfc822Name; a commonName of the signer may be a host name
  const cns: { tag: number; value: Uint8Array }[] = [];
  let nulCn = false;
  try {
    for (const rdn of children(expect(parseDer(cert.subject), TAG.sequence))) {
      for (const atv of children(expect(rdn, TAG.set))) {
        const [type, value] = children(expect(atv, TAG.sequence));
        const id = oid(type!);
        if (id === OID.emailAddress) names.push({ tag: T_EMAIL, bytes: value!.value });
        else if (id === OID.commonName && isSigner)
          cns.push({ tag: value!.tag, value: value!.value });
      }
    }
  } catch {
    throw bad();
  }
  let hasDns = false;
  const entries = subjectAltNames(cert);
  if (entries.length + names.length > NAME_CONSTRAINT_LIMITS.maxNames) throw bad();
  for (const entry of entries) {
    sanTags.add(entry.tag);
    if (entry.tag === T_DNS) hasDns = true;
    if (entry.tag === T_DNS || entry.tag === T_EMAIL || entry.tag === T_URI || entry.tag === T_IP) {
      names.push({ tag: entry.tag, bytes: entry.value });
    } else if (entry.tag === T_DIR) {
      let inside: string[] | null;
      try {
        inside = canonicalRdns(expect(inner(entry), TAG.sequence).raw);
      } catch {
        inside = null;
      }
      if (!inside) throw bad();
      names.push({ tag: T_DIR, bytes: entry.value, rdns: inside });
    } else if (!UNSUPPORTED_TAGS.has(entry.tag)) {
      throw bad(); // a form that does not exist
    }
  }
  if (!hasDns) {
    // a signer without a dNSName: its commonName counts as a host name when it looks like one (as OpenSSL does)
    for (const cn of cns) {
      const raw = cnText(cn.tag, cn.value);
      if (!raw) {
        nulCn = true; // a type or an encoding that cannot be read as text: it could hide a host name
        continue;
      }
      let end = raw.length;
      while (end > 0 && raw[end - 1] === 0) end -= 1;
      const text = raw.subarray(0, end);
      if (text.includes(0)) {
        nulCn = true;
        continue;
      }
      if (isHostName(text)) names.push({ tag: T_DNS, bytes: text });
    }
  }
  if (names.length > NAME_CONSTRAINT_LIMITS.maxNames) throw bad(); // the subject itself does not count
  if (rdns.length > 0) names.push({ tag: T_DIR, bytes: cert.subject, rdns }); // an empty subject is not checked
  return { names, sanTags, nulCn };
}

/**
 * The commonName of a signer as bytes for the host name test, or null when it cannot be read as text. UTF8String,
 * NumericString, PrintableString, TeletexString and IA5String as they are; BMPString and UniversalString by
 * character (a character above 127 becomes the byte 0x80, which is no part of a host name). Any other type
 * (VisibleString, an unknown tag) and any broken encoding is null (OpenSSL cannot read such a name at all).
 */
function cnText(tag: number, v: Uint8Array): Uint8Array | null {
  if (tag === 0x13 || tag === 0x14 || tag === 0x16 || tag === 0x12) return v;
  if (tag === 0x0c) {
    try {
      new TextDecoder('utf-8', { fatal: true }).decode(v);
      return v;
    } catch {
      return null;
    }
  }
  if (tag !== 0x1e && tag !== 0x1c) return null;
  const width = tag === 0x1e ? 2 : 4;
  if (v.length % width !== 0) return null;
  const out = new Uint8Array(v.length / width);
  for (let k = 0; k < out.length; k += 1) {
    let cp = 0;
    for (let j = 0; j < width; j += 1) cp = cp * 256 + v[k * width + j]!;
    if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return null;
    out[k] = cp < 0x80 ? cp : 0x80;
  }
  return out;
}

/** At least two labels of letters, digits, `_` and inner `-`, no empty label (a trailing dot makes it no host name). */
function isHostName(text: Uint8Array): boolean {
  let labels = 0;
  let start = 0;
  for (let k = 0; k <= text.length; k += 1) {
    if (k < text.length && text[k] !== 0x2e) continue;
    const len = k - start;
    if (len === 0 || text[start] === 0x2d || text[k - 1] === 0x2d) return false;
    labels += 1;
    start = k + 1;
  }
  return (
    labels >= 2 &&
    text.every(
      (c) =>
        c === 0x2e ||
        c === 0x2d ||
        c === 0x5f ||
        (c >= 0x30 && c <= 0x39) ||
        (c >= 0x41 && c <= 0x5a) ||
        (c >= 0x61 && c <= 0x7a),
    )
  );
}

const parsed = new WeakMap<Certificate, NameConstraints | ReaderError>();
function constraintsOf(cert: Certificate): NameConstraints | ReaderError | null {
  if (!cert.nameConstraints) return null;
  let known = parsed.get(cert);
  if (!known) {
    try {
      known = parseNameConstraints(cert.nameConstraints.value);
    } catch (e) {
      known = e instanceof ReaderError ? e : bad();
    }
    parsed.set(cert, known);
  }
  return known;
}

/**
 * Applies the name constraints of a finished chain (`path`: signer first, trust anchor last). The constraints of
 * every certificate above a certificate, the trust anchor included, apply to its names (subject, emailAddress of
 * the subject, subjectAltName, a signer's commonName that looks like a host name). A self-issued intermediate is
 * not checked itself, but its constraints apply below it (RFC 5280 § 6.1.3 (b)); the signer is always checked.
 * Returns the refusal or null.
 */
export function checkNameConstraints(path: readonly Certificate[]): ReaderError | null {
  try {
    const last = path.length - 1;
    const sources: { at: number; nc: NameConstraints }[] = [];
    for (let j = last; j >= 1; j -= 1) {
      const nc = constraintsOf(path[j]!);
      if (nc instanceof ReaderError) return nc;
      if (nc) sources.push({ at: j, nc });
    }
    if (sources.length === 0) return null;
    for (let i = 0; i < last; i += 1) {
      const cert = path[i]!;
      if (i > 0 && sameName(cert.subject, cert.issuer)) continue; // self-issued, not the signer
      const above = sources.filter((s) => s.at > i);
      if (above.length === 0) continue;
      const { names, sanTags, nulCn } = namesOf(cert, i === 0);
      if (nulCn) return new ReaderError('name-constraint-violation');
      for (const { at, nc } of above) {
        // a form this library does not evaluate: the extension is critical and the certificate uses that form
        if (nc.unsupported && path[at]!.nameConstraints!.critical) {
          for (const tag of nc.unsupportedTags) if (sanTags.has(tag)) return bad();
        }
        for (const name of names) {
          const permitted = nc.permitted.filter((s) => s.tag === name.tag);
          const excluded = nc.excluded.filter((s) => s.tag === name.tag);
          if (permitted.length === 0 && excluded.length === 0) continue;
          // an address of neither 4 nor 16 bytes can be no address: against any constraint of its kind it is
          // refused, an excluded subtree cannot be compared with it (OpenSSL: an error)
          if (name.tag === T_IP && name.bytes.length !== 4 && name.bytes.length !== 16) {
            return new ReaderError('name-constraint-violation');
          }
          if (name.tag !== T_DIR && !(name.tag === T_IP) && !isAscii(name.bytes)) {
            return new ReaderError('name-constraint-violation'); // a NUL or a byte above 127: a C string would end or differ
          }
          let inPermitted = permitted.length === 0;
          for (const st of permitted) {
            const v = matches(name, st);
            if (v === 'syntax') return new ReaderError('name-constraint-violation');
            if (v === 'match') inPermitted = true;
          }
          if (!inPermitted) return new ReaderError('name-constraint-violation');
          for (const st of excluded) {
            if (matches(name, st) !== 'no') return new ReaderError('name-constraint-violation');
          }
        }
      }
    }
    return null;
  } catch (e) {
    return e instanceof ReaderError ? e : bad();
  }
}
