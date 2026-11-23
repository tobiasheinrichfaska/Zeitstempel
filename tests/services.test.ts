import { existsSync, readFileSync } from 'node:fs';
import { parsePemCertificates, readServices } from '../src/index.ts';
import { loadServices } from '../relay/load.ts';
import { readSettings } from '../relay/main.ts';

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
      allowPlainHttp: true,
      only: [],
      authOff: false,
      keysFile: '',
    });
    expect(readSettings({})).toEqual({
      origins: [],
      port: 8080,
      allowPlainHttp: false,
      only: [],
      authOff: false,
      keysFile: '',
    });
    expect(readSettings({ RELAY_AUTH: 'off' }).authOff).toBe(true);
    expect(readSettings({ RELAY_KEYS_FILE: '/x/k.json' }).keysFile).toBe('/x/k.json');
  });
  it('refuses origins that are not exact, plain-http origins other than localhost, and bad ports', () => {
    for (const o of [
      'https://a.example/',
      'https://a.example/path',
      'http://a.example',
      '*',
      'a.example',
    ]) {
      expect(() => readSettings({ RELAY_ORIGINS: o }), o).toThrow();
    }
    expect(() => readSettings({ PORT: '0' })).toThrow();
    expect(() => readSettings({ PORT: 'abc' })).toThrow();
    expect(() =>
      readSettings({
        RELAY_ORIGINS: Array.from({ length: 17 }, (_, i) => `https://o${i}.example`).join(','),
      }),
    ).toThrow();
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
