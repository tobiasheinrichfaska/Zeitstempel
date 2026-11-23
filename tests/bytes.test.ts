import {
  equalBytes,
  fromBase64,
  fromBase64Url,
  toBase64,
  toBase64Url,
  toHex,
} from '../src/index.ts';

const WRONG: [string, unknown][] = [
  ['a string', 'abc'],
  ['an array of numbers', [1, 2, 3]],
  ['undefined', undefined],
  ['null', null],
  ['a number', 5],
  ['an ArrayBuffer', new ArrayBuffer(3)],
  ['an object with length', { length: 2, 0: 1, 1: 2 }],
];

describe('E7: byte helpers never accept a wrong type silently', () => {
  for (const [name, v] of WRONG) {
    it(`the writers throw a TypeError for ${name}`, () => {
      expect(() => toHex(v as Uint8Array)).toThrow(TypeError);
      expect(() => toBase64(v as Uint8Array)).toThrow(TypeError);
      expect(() => toBase64Url(v as Uint8Array)).toThrow(TypeError);
    });
    if (typeof v !== 'string') {
      it(`the strict readers answer null for ${name}`, () => {
        expect(fromBase64(v as string)).toBeNull();
        expect(fromBase64Url(v as string)).toBeNull();
      });
    }
    it(`equalBytes answers false for ${name}`, () => {
      expect(equalBytes(v as Uint8Array, new Uint8Array(0))).toBe(false);
      expect(equalBytes(new Uint8Array(0), v as Uint8Array)).toBe(false);
    });
  }
  it('toHex("abc") is not "0a0b0c"', () => {
    expect(() => toHex('abc' as unknown as Uint8Array)).toThrow();
  });
  it('equalBytes of two equal strings or two equal arrays is false, not true', () => {
    expect(equalBytes('ab' as unknown as Uint8Array, 'ab' as unknown as Uint8Array)).toBe(false);
    expect(equalBytes([1] as unknown as Uint8Array, [1] as unknown as Uint8Array)).toBe(false);
  });
  it('the correct types still work (also a Buffer, which is a Uint8Array)', () => {
    expect(toHex(Uint8Array.of(1, 171))).toBe('01ab');
    expect(toBase64(Uint8Array.of(104, 105))).toBe('aGk=');
    expect(toBase64Url(Buffer.from('hi'))).toBe('aGk');
    expect(fromBase64('aGk=')).toEqual(Uint8Array.of(104, 105));
    expect(fromBase64Url('aGk')).toEqual(Uint8Array.of(104, 105));
    expect(equalBytes(Uint8Array.of(1), Buffer.of(1))).toBe(true);
    expect(equalBytes(Uint8Array.of(1), Uint8Array.of(2))).toBe(false);
  });
});
