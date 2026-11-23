import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { tlv, encodeOid, ctx } from '../src/lib/der.ts';

/** Builds small, valid time stamp tokens (own CA and signer, ECDSA P-256) with single flaws on demand. */
const u = (b: Uint8Array): Uint8Array<ArrayBuffer> => new Uint8Array(b);
const seq = (...p: Uint8Array[]) => tlv(0x30, ...p);
const set = (...p: Uint8Array[]) => tlv(0x31, ...p);
const oidT = encodeOid;
const int = (n: number) => tlv(2, Uint8Array.of(n));
const octet = (b: Uint8Array) => tlv(4, b);
const name = (cn: string) =>
  seq(set(seq(oidT('2.5.4.3'), tlv(0x0c, new TextEncoder().encode(cn)))));
const gt = (s: string) => tlv(0x18, new TextEncoder().encode(s));
const ecdsa256 = seq(oidT('1.2.840.10045.4.3.2'));
const sha256 = (b: Uint8Array) => u(createHash('sha256').update(b).digest());
const ext = (id: string, crit: boolean, val: Uint8Array) =>
  crit ? seq(oidT(id), tlv(1, Uint8Array.of(0xff)), octet(val)) : seq(oidT(id), octet(val));

export interface Opts {
  ekuOids?: string[];
  ekuCritical?: boolean;
  extraTsaExts?: Uint8Array[]; // extra cert extensions
  tstExtra?: Uint8Array[]; // extra TSTInfo fields after genTime
  nonceBytes?: Uint8Array; // raw INTEGER content
  nonceRaw?: boolean;
  serialRaw?: Uint8Array; // TSA cert serial INTEGER content
  signerSerialRaw?: Uint8Array;
  sigMangle?: (derSig: Uint8Array) => Uint8Array;
  crl?: Uint8Array; // content for [1]
  hash?: Uint8Array;
  tstSerialRaw?: Uint8Array; // TSTInfo serial INTEGER content
  tsaCertOverride?: Uint8Array; // certificate sent in the token instead of the signer's
  caExts?: Uint8Array[]; // extra extensions of the root (trust anchor)
  /** Puts an intermediate CA ("INT") between the root and the signer; the token carries it. */
  intermediate?: {
    extraExts?: Uint8Array[];
    validity?: [string, string]; // not-before, not-after (GeneralizedTime)
    noKeyCertSign?: boolean; // key usage without keyCertSign
  };
  /**
   * Look-alikes of the intermediate (same name and key, other serial, signed by the root), sent in the
   * token before the real one. Needs `intermediate`.
   */
  twins?: {
    extraExts?: Uint8Array[];
    validity?: [string, string];
    noCa?: boolean;
    /** Signed by an unrelated key instead of the root: looks usable, but never leads to an anchor. */
    forged?: boolean;
    /** Carries an unrelated public key: it never verifies the certificate below it. */
    wrongKey?: boolean;
  }[];
  /** `n` chained intermediates I1..In (I1 signed by the root); the signer hangs below In. */
  deepChain?: number;
  /**
   * An unsolvable maze: `width` look-alikes (same name and key, signed upwards by the next level) on each
   * of `levels` levels; the top level is signed by an unrelated key, so no path reaches the root.
   */
  ladder?: {
    levels: number;
    width: number;
    /** Replaces one top certificate by a look-alike of the anchor that is no CA (flawed, but signs). */
    topTwin?: boolean;
  };
  /** Content of the signer's key usage BIT STRING (unused-bits byte, then the bits). Default: digitalSignature. */
  tsaKeyUsage?: Uint8Array;
  /**
   * `n` cross-signed twins of the anchor (same name and key, other bytes, signed by an unrelated key), sent
   * in the token. They look usable and never lead to an anchor.
   */
  anchorTwins?: number;
  caValidity?: [string, string]; // validity of the root
  genTime?: string; // GeneralizedTime text of TSTInfo.genTime (default 20260101000000Z)
  selfSignedSigner?: boolean; // the signer certificate is its own issuer
}
export function build(o: Opts = {}) {
  const ca = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const tsa = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const spki = (k: any) => u(k.publicKey.export({ type: 'spki', format: 'der' }));
  const validity = seq(gt('20200101000000Z'), gt('20400101000000Z'));
  const mkCert = (
    subject: string,
    issuer: string,
    k: any,
    signKey: any,
    exts: Uint8Array[],
    serial: Uint8Array,
    validityOverride?: Uint8Array,
  ) => {
    const tbs = seq(
      tlv(ctx(0), int(2)),
      tlv(2, serial),
      ecdsa256,
      name(issuer),
      validityOverride ?? validity,
      name(subject),
      spki(k),
      tlv(ctx(3), seq(...exts)),
    );
    const sig = u(sign('sha256', tbs, signKey.privateKey));
    return seq(tbs, ecdsa256, tlv(3, Uint8Array.of(0), sig));
  };
  const caCert = mkCert(
    'CA',
    'CA',
    ca,
    ca,
    [
      ext('2.5.29.19', true, seq(tlv(1, Uint8Array.of(0xff)))),
      ext('2.5.29.15', true, tlv(3, Uint8Array.of(1, 0x04))),
      ...(o.caExts ?? []),
    ],
    Uint8Array.of(1),
    o.caValidity ? seq(gt(o.caValidity[0]), gt(o.caValidity[1])) : undefined,
  );
  const attacker = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const mid = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const caExts = (extra: Uint8Array[], isCa = true, keyCertSign = true) => [
    ext('2.5.29.19', true, isCa ? seq(tlv(1, Uint8Array.of(0xff))) : seq()),
    ext('2.5.29.15', true, tlv(3, keyCertSign ? Uint8Array.of(1, 0x04) : Uint8Array.of(7, 0x80))),
    ...extra,
  ];
  const intCert = mkCert(
    'INT',
    'CA',
    mid,
    ca,
    caExts(o.intermediate?.extraExts ?? [], true, !o.intermediate?.noKeyCertSign),
    Uint8Array.of(2),
    o.intermediate?.validity
      ? seq(gt(o.intermediate.validity[0]), gt(o.intermediate.validity[1]))
      : undefined,
  );
  const twinCerts = (o.twins ?? []).map((t, i) =>
    mkCert(
      'INT',
      'CA',
      t.wrongKey ? attacker : mid,
      t.forged ? attacker : ca,
      caExts(t.extraExts ?? [], !t.noCa),
      Uint8Array.of(20 + i),
      t.validity ? seq(gt(t.validity[0]), gt(t.validity[1])) : undefined,
    ),
  );
  // further certificates carried in the token (deep chain, maze)
  const more: Uint8Array[] = [];
  let tsaIssuer = o.intermediate ? 'INT' : 'CA';
  let tsaIssuerKey = o.intermediate ? mid : ca;
  if (o.deepChain) {
    let parentName = 'CA';
    let parentKey = ca;
    for (let j = 1; j <= o.deepChain; j += 1) {
      const k = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      more.push(mkCert(`I${j}`, parentName, k, parentKey, caExts([]), Uint8Array.of(60 + j)));
      parentName = `I${j}`;
      parentKey = k;
    }
    tsaIssuer = parentName;
    tsaIssuerKey = parentKey;
  }
  if (o.ladder) {
    const keys = Array.from({ length: o.ladder.levels }, () =>
      generateKeyPairSync('ec', { namedCurve: 'P-256' }),
    );
    for (let lvl = 0; lvl < o.ladder.levels; lvl += 1) {
      const top = lvl === o.ladder.levels - 1;
      for (let w = 0; w < o.ladder.width; w += 1) {
        if (o.ladder.topTwin && top && w === o.ladder.width - 1) {
          more.push(mkCert('CA', 'CA', attacker, ca, caExts([], false), Uint8Array.of(99)));
          continue;
        }
        more.push(
          mkCert(
            `L${lvl + 1}`,
            top ? 'CA' : `L${lvl + 2}`,
            keys[lvl],
            top ? attacker : keys[lvl + 1],
            caExts([]),
            Uint8Array.of(70 + lvl * 6 + w),
          ),
        );
      }
    }
    tsaIssuer = 'L1';
    tsaIssuerKey = keys[0]!;
  }
  for (let i = 0; i < (o.anchorTwins ?? 0); i += 1) {
    more.push(mkCert('CA', 'CA', ca, attacker, caExts([]), Uint8Array.of(100 + i)));
  }
  if (o.selfSignedSigner) {
    tsaIssuer = 'TSA';
    tsaIssuerKey = tsa;
  }
  const ekus = o.ekuOids ?? ['1.3.6.1.5.5.7.3.8'];
  const tsaSerial = o.serialRaw ?? Uint8Array.of(7);
  const tsaCert = mkCert(
    'TSA',
    tsaIssuer,
    tsa,
    tsaIssuerKey,
    [
      ext('2.5.29.15', true, tlv(3, o.tsaKeyUsage ?? Uint8Array.of(0, 0x80))),
      ext('2.5.29.37', o.ekuCritical ?? true, seq(...ekus.map(oidT))),
      ...(o.extraTsaExts ?? []),
    ],
    tsaSerial,
  );
  const imprint = o.hash ?? sha256(new TextEncoder().encode('x'));
  const nonceField = o.nonceBytes ? [tlv(2, o.nonceBytes)] : [];
  const tst = seq(
    int(1),
    oidT('1.2.3.4'),
    seq(seq(oidT('2.16.840.1.101.3.4.2.1')), octet(imprint)),
    tlv(2, o.tstSerialRaw ?? Uint8Array.of(9)),
    gt(o.genTime ?? '20260101000000Z'),
    ...nonceField,
    ...(o.tstExtra ?? []),
  );
  const attrs = [
    seq(oidT('1.2.840.113549.1.9.3'), set(oidT('1.2.840.113549.1.9.16.1.4'))),
    seq(oidT('1.2.840.113549.1.9.4'), set(octet(sha256(tst)))),
    seq(oidT('1.2.840.113549.1.9.16.2.47'), set(seq(seq(seq(octet(sha256(tsaCert))))))),
  ];
  const attrsSet = set(...attrs);
  let sig: Uint8Array = u(sign('sha256', attrsSet, tsa.privateKey));
  if (o.sigMangle) {
    sig = o.sigMangle(sig);
  }
  const attrCtx = Uint8Array.from(attrsSet);
  attrCtx[0] = 0xa0;
  const signerInfo = seq(
    int(1),
    seq(name(tsaIssuer), tlv(2, o.signerSerialRaw ?? tsaSerial)),
    seq(oidT('2.16.840.1.101.3.4.2.1')),
    attrCtx,
    ecdsa256,
    octet(sig),
  );
  const sd = seq(
    int(3),
    set(seq(oidT('2.16.840.1.101.3.4.2.1'))),
    seq(oidT('1.2.840.113549.1.9.16.1.4'), tlv(ctx(0), octet(tst))),
    tlv(
      ctx(0),
      o.tsaCertOverride ?? tsaCert,
      ...(o.intermediate ? [...twinCerts, intCert] : []),
      ...more,
    ),
    ...(o.crl ? [tlv(ctx(1), o.crl)] : []),
    set(signerInfo),
  );
  const token = seq(oidT('1.2.840.113549.1.7.2'), tlv(ctx(0), sd));
  const pem = (c: Uint8Array) =>
    `-----BEGIN CERTIFICATE-----\n${Buffer.from(c).toString('base64')}\n-----END CERTIFICATE-----\n`;
  return {
    token,
    caPem: pem(caCert),
    intPem: pem(intCert),
    tsaPem: pem(tsaCert),
    imprint,
    tst,
    tsaCert,
  };
}
export { seq, set, oidT, int, octet, tlv, ext };
