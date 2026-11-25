import { existsSync, readFileSync } from 'node:fs';
import { parsePemCertificates, readServices } from '../src/index.ts';
import { loadServices } from '../relay/load.ts';
import { readSettings, serverLimits } from '../relay/main.ts';

const file = JSON.parse(readFileSync(new URL('../services.json', import.meta.url), 'utf8')) as {
  services: Record<string, unknown>[];
};
const clone = () => structuredClone(file);

describe('services.json', () => {
  it('is valid, and every anchor file exists and holds certificates', () => {
    const r = readServices(file);
    expect(r.ok).toBe(true);
    for (const s of loadServices()) {
      expect(s.qualified).toBe(false);
      for (const [i, a] of s.anchors.entries()) {
        expect(existsSync(new URL(`../${a}`, import.meta.url)), a).toBe(true);
        const certs = parsePemCertificates(s.anchorPems[i]!);
        expect(certs.length).toBeGreaterThan(0);
      }
    }
  });
  it('lists the http-only services as such (the relay refuses them by default)', () => {
    const plain = loadServices()
      .filter((s) => new URL(s.url).protocol === 'http:')
      .map((s) => s.id);
    expect(plain).toEqual(['digicert', 'certum']);
  });
});

describe('readServices refuses', () => {
  const bad = (edit: (d: ReturnType<typeof clone>) => void) => {
    const d = clone();
    edit(d);
    return readServices(d);
  };
  it('unknown or missing members, other versions and non-objects', () => {
    expect(readServices(null)).toEqual({ ok: false, reason: 'bad-services' });
    expect(readServices([])).toEqual({ ok: false, reason: 'bad-services' });
    expect(bad((d) => ((d as unknown as { version: number }).version = 2)).ok).toBe(false);
    expect(bad((d) => (d.services[0]!.extra = 1)).ok).toBe(false);
    expect(bad((d) => delete d.services[0]!.terms).ok).toBe(false);
    expect(bad((d) => ((d as unknown as { more: number }).more = 1)).ok).toBe(false);
  });
  it('bad ids, duplicate ids, empty lists', () => {
    expect(bad((d) => (d.services[0]!.id = 'Free TSA')).ok).toBe(false);
    expect(bad((d) => (d.services[1]!.id = d.services[0]!.id)).ok).toBe(false);
    expect(bad((d) => (d.services.length = 0)).ok).toBe(false);
  });
  it('urls that could make the relay an open proxy or leak credentials', () => {
    for (const url of [
      'ftp://x.example/tsr',
      'https://user:pw@x.example/',
      'https://x.example/tsr?a=b',
      'https://x.example/#f',
      'not a url',
    ]) {
      expect(bad((d) => (d.services[0]!.url = url)).ok, url).toBe(false);
    }
  });
  it('anchors outside the anchors folder, a hash other than sha256, bad intervals', () => {
    expect(bad((d) => (d.services[0]!.anchors = ['../secret.pem'])).ok).toBe(false);
    expect(bad((d) => (d.services[0]!.anchors = [])).ok).toBe(false);
    expect(bad((d) => (d.services[0]!.hash = 'sha1')).ok).toBe(false);
    expect(bad((d) => (d.services[0]!.minIntervalMs = 10)).ok).toBe(false);
    expect(bad((d) => (d.services[0]!.minIntervalMs = 1.5)).ok).toBe(false);
    expect(bad((d) => (d.services[0]!.qualified = 'yes')).ok).toBe(false);
  });
});

describe('relay settings', () => {
  it('reads origins, port and switches', () => {
    expect(
      readSettings({
        RELAY_ORIGINS: 'https://a.example, http://localhost:5178',
        PORT: '9000',
        RELAY_ALLOW_PLAIN_HTTP: '1',
      }),
    ).toEqual({
      origins: ['https://a.example', 'http://localhost:5178'],
      port: 9000,
      host: '127.0.0.1',
      allowPlainHttp: true,
      only: [],
      authOff: false,
      keysFile: '',
      audience: '',
      batchMax: 128,
      keyShare: 100,
    });
    expect(readSettings({})).toEqual({
      origins: [],
      port: 8080,
      host: '127.0.0.1',
      allowPlainHttp: false,
      only: [],
      authOff: false,
      keysFile: '',
      audience: '',
      batchMax: 128,
      keyShare: 100,
    });
    expect(readSettings({ RELAY_AUTH: 'off' }).authOff).toBe(true);
    // Befund 7: with authentication on, the default is loopback too; a wider address is the operator's decision
    expect(readSettings({ RELAY_KEYS_FILE: '/x/k.json' }).host).toBe('127.0.0.1');
    expect(readSettings({ RELAY_KEYS_FILE: '/x/k.json', RELAY_HOST: '0.0.0.0' }).host).toBe(
      '0.0.0.0',
    );
    expect(readSettings({ RELAY_KEYS_FILE: '/x/k.json', RELAY_HOST: '  ' }).host).toBe('127.0.0.1');
    expect(readSettings({ RELAY_KEYS_FILE: '/x/k.json' }).keysFile).toBe('/x/k.json');
  });
  it('RELAY_KEEPALIVE_MS: unset or empty means the binding decides; a whole number from 1000 to 120000 is taken', () => {
    expect(readSettings({}).keepAliveMs).toBeUndefined();
    expect(readSettings({ RELAY_KEEPALIVE_MS: '' }).keepAliveMs).toBeUndefined();
    expect(readSettings({ RELAY_KEEPALIVE_MS: '1000' }).keepAliveMs).toBe(1000);
    expect(readSettings({ RELAY_KEEPALIVE_MS: '65000' }).keepAliveMs).toBe(65000);
    expect(readSettings({ RELAY_KEEPALIVE_MS: '120000' }).keepAliveMs).toBe(120000);
  });
  it('RELAY_KEEPALIVE_MS: anything else is a German configuration error that names the variable', () => {
    for (const v of [
      '999',
      '120001',
      '0',
      '-5000',
      '1e4',
      '5000.5',
      '5000ms',
      ' 5000',
      '5000 ',
      '+5000',
      '0x1388',
      'abc',
      'NaN',
      'Infinity',
      '99999999999999',
    ]) {
      expect(() => readSettings({ RELAY_KEEPALIVE_MS: v }), v).toThrow(
        /^RELAY_KEEPALIVE_MS: ungültig \(ganze Zahl von 1000 bis 120000 erwartet\)$/,
      );
    }
  });
  it('the settings reach the server: the host and an explicit keep-alive, nothing else', () => {
    expect(serverLimits(readSettings({}))).toEqual({ host: '127.0.0.1' });
    expect(
      serverLimits(readSettings({ RELAY_HOST: '0.0.0.0', RELAY_KEEPALIVE_MS: '7000' })),
    ).toEqual({
      host: '0.0.0.0',
      keepAliveMs: 7000,
    });
  });
  it('refuses origins that are not exact, plain-http origins other than localhost, and bad ports', () => {
    for (const o of [
      'https://a.example/',
      'https://a.example/path',
      'http://a.example',
      '*',
      'a.example',
    ]) {
      // the variable is named, the text is German like the other configuration errors, and a string
      // that is no URL at all gives the same message instead of the URL parser's English one
      expect(() => readSettings({ RELAY_ORIGINS: o }), o).toThrow(
        /^RELAY_ORIGINS: Herkunft muss genau https:\/\/host\[:port\] sein/,
      );
    }
    expect(() => readSettings({ PORT: '0' })).toThrow(/^PORT: /);
    expect(() => readSettings({ PORT: 'abc' })).toThrow(/^PORT: /);
    expect(() => readSettings({ PORT: '70000' })).toThrow(/^PORT: /);
    expect(() =>
      readSettings({
        RELAY_ORIGINS: Array.from({ length: 17 }, (_, i) => `https://o${i}.example`).join(','),
      }),
    ).toThrow(/^RELAY_ORIGINS: zu viele Herkünfte/);
  });
});

describe('E7: readServices never throws', () => {
  const boom = () => {
    throw new Error('boom');
  };
  it('a getter that throws at the top, in the list or in an entry gives bad-services', () => {
    const top = {
      version: 1,
      get services(): unknown {
        return boom();
      },
    };
    expect(readServices(top)).toEqual({ ok: false, reason: 'bad-services' });
    const inEntry = clone();
    Object.defineProperty(inEntry.services[0]!, 'name', { get: boom, enumerable: true });
    expect(readServices(inEntry)).toEqual({ ok: false, reason: 'bad-services' });
    const inAnchors = clone();
    Object.defineProperty(inAnchors.services[0]!, 'anchors', { get: boom, enumerable: true });
    expect(readServices(inAnchors)).toEqual({ ok: false, reason: 'bad-services' });
  });
  it('a proxy that throws gives bad-services', () => {
    const p = new Proxy({}, { getPrototypeOf: boom, ownKeys: boom, get: boom, has: boom });
    expect(readServices(p)).toEqual({ ok: false, reason: 'bad-services' });
    const inList = { version: 1, services: [p] };
    expect(readServices(inList)).toEqual({ ok: false, reason: 'bad-services' });
  });
});

describe('readServices reads every member strictly (nothing is accepted by coercion)', () => {
  const asText = { toString: () => 'https://x.example/tsr' };
  const coerced = (text: string): Record<string, unknown> => ({
    toString: () => text,
    valueOf: () => text,
  });
  const wrongs: Record<string, (good: unknown) => unknown> = {
    'an array of one text': (good) => [good],
    'an object with toString': (good) => coerced(String(good)),
    'a number': () => 12345,
    'a boolean': () => true,
    null: () => null,
  };
  const members = [
    'id',
    'name',
    'url',
    'hash',
    'intendedUse',
    'terms',
    'qualified',
    'minIntervalMs',
  ] as const;
  for (const member of members) {
    for (const [name, make] of Object.entries(wrongs)) {
      // 12345 and `true` are the right type for these two members (the range and the value are checked elsewhere)
      if (
        (member === 'qualified' && name === 'a boolean') ||
        (member === 'minIntervalMs' && name === 'a number')
      )
        continue;
      it(`${member} as ${name} is refused`, () => {
        const d = clone();
        d.services[0]![member] = make(d.services[0]![member]);
        expect(readServices(d)).toEqual({ ok: false, reason: 'bad-services' });
      });
    }
  }
  it('an anchor path as an array or an object with toString is refused', () => {
    for (const wrong of [['anchors/freetsa.pem'], coerced('anchors/freetsa.pem')]) {
      const d = clone();
      d.services[0]!.anchors = [wrong];
      expect(readServices(d)).toEqual({ ok: false, reason: 'bad-services' });
    }
  });
  it('the url as an object that turns into a valid address is refused, the text itself is read', () => {
    const d = clone();
    d.services[0]!.url = asText;
    expect(readServices(d).ok).toBe(false);
    d.services[0]!.url = 'https://x.example/tsr';
    expect(readServices(d).ok).toBe(true);
  });
});

describe('PORT is read as strictly as the other numbers (audit 2)', () => {
  it('takes decimal digits from 1 to 65535 only', () => {
    expect(readSettings({}).port).toBe(8080);
    expect(readSettings({ PORT: '80' }).port).toBe(80);
    expect(readSettings({ PORT: '1' }).port).toBe(1);
    expect(readSettings({ PORT: '65535' }).port).toBe(65535);
    for (const bad of [
      '0x50',
      '1e2',
      ' 80',
      '80 ',
      '80.0',
      '+80',
      '-1',
      '0',
      '00',
      '65536',
      '123456',
      '',
      'abc',
      '８０',
      '8_0',
      '0b101',
      '80\n',
    ]) {
      expect(() => readSettings({ PORT: bad }), JSON.stringify(bad)).toThrow(
        /^PORT: ungültig \(ganze Zahl von 1 bis 65535 erwartet/,
      );
    }
  });
});
