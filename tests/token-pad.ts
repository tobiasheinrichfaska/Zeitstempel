import { contentOf, der, elements, tlvAt } from './ers-reference.ts';

/** `extra` as the last child of the SignerInfo (last child of the signerInfos SET, last child of SignedData). */
export function addUnsigned(token: Uint8Array, extra: Uint8Array): Uint8Array {
  const rebuild = (b: Uint8Array, start: number, path: number[]): Uint8Array => {
    const t = tlvAt(b, start);
    const kids = elements(b, t);
    if (path.length === 0) return der(t.tag, contentOf(b, t), extra);
    const idx = path[0] === -1 ? kids.length - 1 : path[0]!;
    return der(
      t.tag,
      ...kids.map((k, i) =>
        i === idx ? rebuild(b, k.start, path.slice(1)) : b.subarray(k.start, k.end),
      ),
    );
  };
  return rebuild(token, 0, [1, 0, -1, 0]);
}

const OID_ATTR = Uint8Array.of(6, 3, 0x2a, 3, 4);

/** The token with an unsigned attribute that carries `n` filler bytes (the signature does not cover it). */
export function padToken(token: Uint8Array, n: number): Uint8Array {
  return addUnsigned(
    token,
    der(0xa1, der(0x30, OID_ATTR, der(0x31, der(0x04, new Uint8Array(n))))),
  );
}

/** The token with an unsigned attribute whose value is nested `depth` SEQUENCEs deep. */
export function nestToken(token: Uint8Array, depth: number): Uint8Array {
  let x = der(0x05);
  for (let i = 0; i < depth; i += 1) x = der(0x30, x);
  return addUnsigned(token, der(0xa1, der(0x30, OID_ATTR, der(0x31, x))));
}
