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

describe('L3: equalBytes reads each length once, from the built-in getter, and only compares genuine arrays', () => {
  /** A transparent proxy around `target` that counts every trap call (all traps, one counter). */
  const counting = (target: Uint8Array, lie?: () => number) => {
    const seen = { count: 0 };
    const trap =
      (name: string) =>
      (...args: unknown[]) => {
        seen.count += 1;
        if (name === 'get' && args[1] === 'length' && lie) return lie();
        return (Reflect as unknown as Record<string, (...a: unknown[]) => unknown>)[name]!(...args);
      };
    const handler = {
      get: trap('get'),
      getPrototypeOf: trap('getPrototypeOf'),
      has: trap('has'),
      ownKeys: trap('ownKeys'),
      getOwnPropertyDescriptor: trap('getOwnPropertyDescriptor'),
    } as ProxyHandler<Uint8Array>;
    const proxy = new Proxy(target, handler);
    return { proxy, seen };
  };
  it('a proxy whose length is 32 the first time and 0 afterwards is false', () => {
    let reads = 0;
    const { proxy } = counting(new Uint8Array(32), () => (reads++ === 0 ? 32 : 0));
    expect(equalBytes(proxy, new Uint8Array(32))).toBe(false);
    expect(equalBytes(new Uint8Array(32), proxy)).toBe(false);
  });
  it('a proxy is asked at most once per argument, whatever the order', () => {
    const a = counting(new Uint8Array(4));
    const b = counting(new Uint8Array(4));
    expect(equalBytes(a.proxy, b.proxy)).toBe(false);
    expect(a.seen.count).toBeLessThanOrEqual(1);
    expect(b.seen.count).toBeLessThanOrEqual(1);
    const c = counting(new Uint8Array(4));
    expect(equalBytes(new Uint8Array(4), c.proxy)).toBe(false);
    expect(c.seen.count).toBeLessThanOrEqual(1);
  });
  it('an own length property does not fool it (40 bytes claiming 4 are not equal to 4 bytes)', () => {
    const lie = new Uint8Array(40);
    Object.defineProperty(lie, 'length', { value: 4 });
    expect(equalBytes(lie, new Uint8Array(4))).toBe(false);
    expect(equalBytes(new Uint8Array(4), lie)).toBe(false);
  });
  it("the writers give a TypeError (not the proxy's own Error) for a proxy with a throwing trap", () => {
    const boom = () => {
      throw new Error('trap');
    };
    for (const trap of ['getPrototypeOf', 'get'] as const) {
      const p = new Proxy(new Uint8Array(2), { [trap]: boom }) as Uint8Array;
      expect(() => toBase64(p)).toThrow(TypeError);
      expect(() => toBase64Url(p)).toThrow(TypeError);
      expect(() => toHex(p)).toThrow(TypeError);
    }
  });
});

describe('writers read the built-in length (a subclass or an own length cannot change the output)', () => {
  class Liar extends Uint8Array {
    override get length(): number {
      return 5;
    }
  }
  it('toBase64, toBase64Url and toHex ignore a lying length', () => {
    const x = new Liar([1, 2]);
    expect(toBase64(x)).toBe(toBase64(new Uint8Array([1, 2])));
    expect(toBase64Url(x)).toBe(toBase64Url(new Uint8Array([1, 2])));
    expect(toHex(x)).toBe('0102');
  });
});
