import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { toBase64Url } from '../src/index.ts';
import { loadKeys, readKeyFile } from '../relay/keys.ts';
import { readConfig, startEvent } from '../relay/main.ts';
import { loadServices } from '../relay/load.ts';

const SERVICES = loadServices();
const verifier = () =>
  toBase64Url(new Uint8Array(createHash('sha256').update(randomBytes(32)).digest()));
const file = (keys: unknown[], over: Record<string, unknown> = {}) => ({
  version: 1,
  keys,
  ...over,
});

describe('relay key file reader', () => {
  it('reads keys with an id and a 32-byte verifier', () => {
    const v = verifier();
    const r = readKeyFile(
      file([
        { id: 'app-1', verifier: v },
        { id: 'b', verifier: verifier() },
      ]),
    );
    expect(r.ok && r.value.map((k) => k.id)).toEqual(['app-1', 'b']);
    expect(r.ok && r.value[0]!.verifier.length).toBe(32);
  });
  it('refuses what is not exactly the format', () => {
    const v = verifier();
    const bad: [string, unknown][] = [
      [
        'duplicate id',
        file([
          { id: 'a', verifier: v },
          { id: 'a', verifier: verifier() },
        ]),
      ],
      [
        'duplicate verifier',
        file([
          { id: 'a', verifier: v },
          { id: 'b', verifier: v },
        ]),
      ],
      ['short verifier', file([{ id: 'a', verifier: toBase64Url(new Uint8Array(31)) }])],
      ['long verifier', file([{ id: 'a', verifier: toBase64Url(new Uint8Array(33)) }])],
      ['padded verifier', file([{ id: 'a', verifier: v + '=' }])],
      ['verifier not a string', file([{ id: 'a', verifier: 5 }])],
      ['id uppercase', file([{ id: 'App', verifier: v }])],
      ['id too long', file([{ id: 'a'.repeat(33), verifier: v }])],
      ['id starts with digit', file([{ id: '1a', verifier: v }])],
      ['extra field', file([{ id: 'a', verifier: v, note: 'x' }])],
      ['extra top-level field', file([{ id: 'a', verifier: v }], { more: 1 })],
      ['wrong version', file([{ id: 'a', verifier: v }], { version: 2 })],
      ['no keys', file([])],
      ['keys not an array', file([], { keys: {} })],
      ['not an object', []],
      ['null', null],
      [
        'more than 64 keys',
        file(Array.from({ length: 65 }, (_, i) => ({ id: `k${i}`, verifier: verifier() }))),
      ],
    ];
    for (const [name, data] of bad) {
      expect(readKeyFile(data), name).toMatchObject({ ok: false, reason: 'bad-key-file' });
    }
  });
  it('accepts exactly 64 keys', () => {
    const many = Array.from({ length: 64 }, (_, i) => ({ id: `k${i}`, verifier: verifier() }));
    expect(readKeyFile(file(many)).ok).toBe(true);
  });
  it('loadKeys names the problem without printing the file', () => {
    const secretish = 'SECRETISH-CONTENT';
    expect(() => loadKeys('/x/keys.json', () => secretish)).toThrow(/keys\.json/);
    try {
      loadKeys('/x/keys.json', () => secretish);
    } catch (e) {
      expect((e as Error).message).not.toContain(secretish);
    }
    expect(() => loadKeys('/x/keys.json', () => JSON.stringify(file([])))).toThrow(/bad-key-file/);
    expect(
      loadKeys('/x/keys.json', () => JSON.stringify(file([{ id: 'a', verifier: verifier() }]))),
    ).toHaveLength(1);
  });
});

describe('relay start: authentication', () => {
  const env = { RELAY_ORIGINS: 'https://app.example' };
  it('refuses to start without a key file', () => {
    expect(() => readConfig(env, () => SERVICES)).toThrow(/RELAY_KEYS_FILE/);
  });
  it('starts without keys only with RELAY_AUTH=off said expressly', () => {
    expect(readConfig({ ...env, RELAY_AUTH: 'off' }, () => SERVICES).keys).toBe('off');
    expect(() => readConfig({ ...env, RELAY_AUTH: 'no' }, () => SERVICES)).toThrow(/RELAY_AUTH/);
    expect(() => readConfig({ ...env, RELAY_AUTH: '' }, () => SERVICES)).toThrow(/RELAY_KEYS_FILE/);
  });
  it('reads the key file when one is named', () => {
    const keys = [{ id: 'a', verifier: verifier() }];
    const read = (): string => JSON.stringify(file(keys));
    const config = readConfig(
      { ...env, RELAY_KEYS_FILE: '/x/k.json' },
      () => SERVICES,
      (p) => loadKeys(p, read),
    );
    expect(config.keys).toHaveLength(1);
  });
  it('refuses to start with RELAY_AUTH=off and a key file at the same time', () => {
    expect(() =>
      readConfig({ ...env, RELAY_AUTH: 'off', RELAY_KEYS_FILE: '/x/k.json' }, () => SERVICES),
    ).toThrow(/RELAY_AUTH/);
  });
  it('reports the authentication mode on the start line', () => {
    expect(startEvent(8080, SERVICES, 'off')).toMatchObject({ event: 'start', auth: 'off' });
    expect(startEvent(8080, SERVICES, [{ id: 'a', verifier: new Uint8Array(32) }])).toMatchObject({
      auth: 'on',
    });
    expect(
      JSON.stringify(startEvent(8080, SERVICES, [{ id: 'a', verifier: new Uint8Array(32) }])),
    ).not.toContain('"a"');
  });
  it('the process ends with exit code 1 and one error line when the key file is missing', () => {
    const root = new URL('..', import.meta.url);
    const r = spawnSync(process.execPath, ['relay/main.ts'], {
      cwd: root,
      encoding: 'utf8',
      env: { PATH: process.env.PATH ?? '', RELAY_ORIGINS: 'https://app.example' },
      timeout: 15_000,
    });
    expect(r.status).toBe(1);
    expect(r.stdout).toBe('');
    expect(r.stderr).toContain('config-error');
    expect(r.stderr).toContain('RELAY_KEYS_FILE');
  });
});
