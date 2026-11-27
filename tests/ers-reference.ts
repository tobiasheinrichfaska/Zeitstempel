// An independent reader and writer for the evidence record of RFC 4998, written from the ASN.1 text of the RFC
// (section 3.1, 4.1, 5.1; the module is IMPLICIT TAGS) and NOT from src/lib: no import of der.ts or ers.ts. The tests
// use it so that the writer is not only checked by its own reader.
//
//   EvidenceRecord ::= SEQUENCE { version INTEGER { v1(1) }, digestAlgorithms SEQUENCE OF AlgorithmIdentifier,
//     cryptoInfos [0] CryptoInfos OPTIONAL, encryptionInfo [1] EncryptionInfo OPTIONAL,
//     archiveTimeStampSequence ArchiveTimeStampSequence }
//   ArchiveTimeStampSequence ::= SEQUENCE OF ArchiveTimeStampChain
//   ArchiveTimeStampChain ::= SEQUENCE OF ArchiveTimeStamp
//   ArchiveTimeStamp ::= SEQUENCE { digestAlgorithm [0] AlgorithmIdentifier OPTIONAL, attributes [1] Attributes OPTIONAL,
//     reducedHashtree [2] SEQUENCE OF PartialHashtree OPTIONAL, timeStamp ContentInfo }

export interface Tlv {
  tag: number;
  start: number;
  headerLength: number;
  length: number;
  end: number;
}

/** One element at `at` (definite length only, as DER requires); throws on anything else. */
export function tlvAt(b: Uint8Array, at: number, limit = b.length): Tlv {
  const tag = b[at]!;
  let length = b[at + 1]!;
  let headerLength = 2;
  if (length === 0x80) throw new Error('indefinite');
  if (length > 0x80) {
    const n = length & 0x7f;
    length = 0;
    for (let i = 0; i < n; i += 1) length = length * 256 + b[at + 2 + i]!;
    headerLength = 2 + n;
  }
  const end = at + headerLength + length;
  if (end > limit) throw new Error('length lies');
  return { tag, start: at, headerLength, length, end };
}

export const contentOf = (b: Uint8Array, t: Tlv) => b.subarray(t.start + t.headerLength, t.end);
export const rawOf = (b: Uint8Array, t: Tlv) => b.subarray(t.start, t.end);

/** The elements inside a constructed element. */
export function elements(b: Uint8Array, t: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let at = t.start + t.headerLength;
  while (at < t.end) {
    const e = tlvAt(b, at, t.end);
    out.push(e);
    at = e.end;
  }
  return out;
}

const SHA256 = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

export interface DecodedRecord {
  version: number;
  digestAlgorithms: string[];
  /** Which optional top-level fields are present. */
  cryptoInfos: boolean;
  encryptionInfo: boolean;
  chains: {
    stamps: {
      digestAlgorithm: string | null;
      attributes: boolean;
      reducedHashtree: boolean;
      /** The ContentInfo bytes of the time stamp. */
      timeStamp: Uint8Array;
    }[];
  }[];
}

const algorithmText = (b: Uint8Array, t: Tlv): string => {
  const parts = elements(b, t);
  const oid = parts[0]!;
  const hex = Buffer.from(rawOf(b, oid)).toString('hex');
  const known = hex === Buffer.from(SHA256).toString('hex') ? 'sha256' : `oid:${hex}`;
  const params = parts[1] ? Buffer.from(rawOf(b, parts[1])).toString('hex') : 'none';
  return `${known}/${params}`;
};

/** Walks the structure with the tag numbers of the ASN.1 text; every deviation throws. */
export function decodeRecord(b: Uint8Array): DecodedRecord {
  const root = tlvAt(b, 0);
  if (root.tag !== 0x30 || root.end !== b.length) throw new Error('EvidenceRecord');
  const parts = elements(b, root);
  let i = 0;
  const version = parts[i++]!;
  if (version.tag !== 0x02) throw new Error('version');
  const versionBytes = contentOf(b, version);
  const algs = parts[i++]!;
  if (algs.tag !== 0x30) throw new Error('digestAlgorithms');
  const digestAlgorithms = elements(b, algs).map((a) => {
    if (a.tag !== 0x30) throw new Error('AlgorithmIdentifier');
    return algorithmText(b, a);
  });
  let cryptoInfos = false;
  let encryptionInfo = false;
  if (parts[i]?.tag === 0xa0) {
    cryptoInfos = true;
    i += 1;
  }
  if (parts[i]?.tag === 0xa1) {
    encryptionInfo = true;
    i += 1;
  }
  const sequence = parts[i++]!;
  if (sequence.tag !== 0x30 || i !== parts.length) throw new Error('archiveTimeStampSequence');
  const chains = elements(b, sequence).map((chain) => {
    if (chain.tag !== 0x30) throw new Error('ArchiveTimeStampChain');
    return {
      stamps: elements(b, chain).map((ats) => {
        if (ats.tag !== 0x30) throw new Error('ArchiveTimeStamp');
        const kids = elements(b, ats);
        let k = 0;
        let digestAlgorithm: string | null = null;
        if (kids[k]?.tag === 0xa0) {
          digestAlgorithm = algorithmText(b, kids[k]!);
          k += 1;
        }
        const attributes = kids[k]?.tag === 0xa1;
        if (attributes) k += 1;
        const reducedHashtree = kids[k]?.tag === 0xa2;
        if (reducedHashtree) k += 1;
        const info = kids[k++]!;
        if (info.tag !== 0x30 || k !== kids.length) throw new Error('timeStamp');
        return { digestAlgorithm, attributes, reducedHashtree, timeStamp: rawOf(b, info).slice() };
      }),
    };
  });
  return {
    version: versionBytes.length === 1 ? versionBytes[0]! : -1,
    digestAlgorithms,
    cryptoInfos,
    encryptionInfo,
    chains,
  };
}

// ----- writer (for the hostile variants) -----

export const der = (tag: number, ...parts: Uint8Array[]): Uint8Array => {
  const size = parts.reduce((n, p) => n + p.length, 0);
  const head =
    size < 0x80
      ? [tag, size]
      : size < 0x100
        ? [tag, 0x81, size]
        : size < 0x10000
          ? [tag, 0x82, size >> 8, size & 0xff]
          : [tag, 0x83, size >> 16, (size >> 8) & 0xff, size & 0xff];
  const out = new Uint8Array(head.length + size);
  out.set(head, 0);
  let at = head.length;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};

export const ALG_SHA256 = der(0x30, Uint8Array.from(SHA256), der(0x05));
export const ALG_SHA256_BARE = der(0x30, Uint8Array.from(SHA256));
export const ALG_SHA1 = der(
  0x30,
  Uint8Array.from([0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a]),
  der(0x05),
);
export const ALG_SHA384 = der(
  0x30,
  Uint8Array.from([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]),
  der(0x05),
);

export interface RecordParts {
  version?: Uint8Array;
  algorithms?: Uint8Array[];
  /** Raw elements between the algorithms and the sequence (`[0]`, `[1]`). */
  between?: Uint8Array[];
  /** The chains; each chain is a list of ArchiveTimeStamp elements. */
  chains?: Uint8Array[][];
  /** Raw elements after the sequence. */
  after?: Uint8Array[];
}

/** An evidence record from parts; every part can be replaced by a flawed one. */
export function writeRecord(p: RecordParts): Uint8Array {
  return der(
    0x30,
    p.version ?? der(0x02, Uint8Array.of(1)),
    der(0x30, ...(p.algorithms ?? [ALG_SHA256])),
    ...(p.between ?? []),
    der(0x30, ...(p.chains ?? []).map((chain) => der(0x30, ...chain))),
    ...(p.after ?? []),
  );
}

/** An ArchiveTimeStamp: optional `[0]` algorithm (content of an AlgorithmIdentifier) and the time stamp. */
export function writeStamp(
  timeStamp: Uint8Array,
  o: { algorithm?: Uint8Array | null; extra?: Uint8Array[] } = {},
): Uint8Array {
  const alg = o.algorithm === undefined ? ALG_SHA256 : o.algorithm;
  const implicit = alg === null ? [] : [der(0xa0, alg.subarray(2))];
  return der(0x30, ...implicit, ...(o.extra ?? []), timeStamp);
}
