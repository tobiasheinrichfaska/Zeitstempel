// Encoders for name constraints tests: names, GeneralNames, subtrees, the extension.
import { tlv, encodeOid } from '../src/lib/der.ts';
import { ext, seq, set, int } from './token-builder.ts';

const text = (s: string) => new TextEncoder().encode(s);

/** A distinguished name from RDNs; an RDN is `[oid, value, tag?]` (tag default 0x0c UTF8String) or a list of those (multi-valued). */
export type Rdn = [string, string, number?] | [string, string, number?][];
export function dn(...rdns: Rdn[]): Uint8Array {
  const atv = ([id, v, tag]: [string, string, number?]) =>
    seq(encodeOid(id), tlv(tag ?? 0x0c, text(v)));
  return seq(
    ...rdns.map((r) =>
      set(
        ...(typeof r[0] === 'string'
          ? [atv(r as [string, string, number?])]
          : (r as [string, string, number?][]).map(atv)),
      ),
    ),
  );
}
export const C = (v: string): Rdn => ['2.5.4.6', v, 0x13];
export const O = (v: string): Rdn => ['2.5.4.10', v];
export const OU = (v: string): Rdn => ['2.5.4.11', v];
export const CN = (v: string): Rdn => ['2.5.4.3', v];
export const EMAIL = (v: string): Rdn => ['1.2.840.113549.1.9.1', v, 0x16];

// GeneralName
export const gnDns = (s: string) => tlv(0x82, text(s));
export const gnEmail = (s: string) => tlv(0x81, text(s));
export const gnUri = (s: string) => tlv(0x86, text(s));
export const gnIp = (...bytes: number[]) => tlv(0x87, Uint8Array.from(bytes));
export const gnDir = (name: Uint8Array) => tlv(0xa4, name);
export const gnOther = () => tlv(0xa0, encodeOid('1.2.3.4'), tlv(0xa0, tlv(0x0c, text('x'))));
export const gnRid = (id: string) => tlv(0x88, encodeOid(id).subarray(2));

/** GeneralSubtree (`minimum` / `maximum` as small numbers, for the cases that must be refused). */
export const sub = (base: Uint8Array, minimum?: number, maximum?: number) =>
  seq(
    base,
    ...(minimum === undefined ? [] : [tlv(0x80, Uint8Array.of(minimum))]),
    ...(maximum === undefined ? [] : [tlv(0x81, Uint8Array.of(maximum))]),
  );

/** The nameConstraints extension (default critical). */
export function nc(o: {
  permitted?: Uint8Array[];
  excluded?: Uint8Array[];
  critical?: boolean;
}): Uint8Array {
  return ext(
    '2.5.29.30',
    o.critical ?? true,
    seq(
      ...(o.permitted ? [tlv(0xa0, ...o.permitted)] : []),
      ...(o.excluded ? [tlv(0xa1, ...o.excluded)] : []),
    ),
  );
}
/** The subjectAltName extension. */
export const san = (...names: Uint8Array[]) => ext('2.5.29.17', false, seq(...names));
export { int };
