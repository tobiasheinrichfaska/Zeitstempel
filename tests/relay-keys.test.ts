import { spawnSync } from 'node:child_process';
import { verify } from 'node:crypto';
import { fromBase64Url, signRelayRequest, toBase64Url } from '../src/index.ts';
import { loadKeys, publicKeyObject, readKeyFile } from '../relay/keys.ts';
import { readConfig, startEvent } from '../relay/main.ts';
import { loadServices } from '../relay/load.ts';
import { authMessage, makeTestKey } from './auth-helpers.ts';

const SERVICES = loadServices();
const pub = () => toBase64Url(makeTestKey('x').publicKey);
const file = (keys: unknown[], over: Record<string, unknown> = {}) => ({
  version: 2,
  keys,
  ...over,
});
const keyOf = (id: string) => ({ id, publicKey: pub() });

describe('relay key file reader', () => {
  it('reads keys with an id and a public key (uncompressed P-256 point)', () => {
    const a = makeTestKey('app-1');
    const r = readKeyFile(file([{ id: 'app-1', publicKey: toBase64Url(a.publicKey) }, keyOf('b')]));
    expect(r.ok && r.value.map((k) => k.id)).toEqual(['app-1', 'b']);
    expect(r.ok && Buffer.from(r.value[0]!.publicKey).equals(Buffer.from(a.publicKey))).toBe(true);
  });
  it('refuses what is not exactly the format', () => {
    const p = pub();
    const point = makeTestKey('x').publicKey;
    const offCurve = Uint8Array.from(point);
    offCurve[64] = offCurve[64]! ^ 1; // Y changed by one bit: no longer on the curve
    const compressed = Uint8Array.from([2, ...point.subarray(1, 33)]);
    const bad: [string, unknown][] = [
      ['duplicate id', file([{ id: 'a', publicKey: p }, keyOf('a')])],
      [
        'duplicate key',
        file([
          { id: 'a', publicKey: p },
          { id: 'b', publicKey: p },
        ]),
      ],
      ['point not on the curve', file([{ id: 'a', publicKey: toBase64Url(offCurve) }])],
      ['compressed point', file([{ id: 'a', publicKey: toBase64Url(compressed) }])],
      ['64 bytes (no prefix)', file([{ id: 'a', publicKey: toBase64Url(point.subarray(1)) }])],
      ['66 bytes', file([{ id: 'a', publicKey: toBase64Url(Uint8Array.from([...point, 0])) }])],
      [
        'wrong prefix byte',
        file([{ id: 'a', publicKey: toBase64Url(Uint8Array.from([5, ...point.subarray(1)])) }]),
      ],
      ['all zero', file([{ id: 'a', publicKey: toBase64Url(new Uint8Array(65)) }])],
      ['padded key', file([{ id: 'a', publicKey: p + '=' }])],
      ['key not a string', file([{ id: 'a', publicKey: 5 }])],
      ['old field name verifier', file([{ id: 'a', verifier: p }])],
      ['id uppercase', file([{ id: 'App', publicKey: p }])],
      ['id too long', file([{ id: 'a'.repeat(33), publicKey: p }])],
      ['id starts with digit', file([{ id: '1a', publicKey: p }])],
      ['extra field', file([{ id: 'a', publicKey: p, note: 'x' }])],
      ['extra top-level field', file([{ id: 'a', publicKey: p }], { more: 1 })],
      ['version 1 (HMAC file)', file([{ id: 'a', publicKey: p }], { version: 1 })],
      ['no key list', { version: 2 }],
      ['keys not an array', file([], { keys: {} })],
      ['not an object', []],
      ['null', null],
      ['more than 64 keys', file(Array.from({ length: 65 }, (_, i) => keyOf(`k${i}`)))],
    ];
    for (const [name, data] of bad) {
      expect(readKeyFile(data), name).toMatchObject({ ok: false, reason: 'bad-key-file' });
    }
  });
  it('names the rule that failed, never the content', () => {
    const p = pub();
    const off = Uint8Array.from(makeTestKey('x').publicKey);
    off[64] = off[64]! ^ 1;
    const r = readKeyFile(file([{ id: 'a', publicKey: toBase64Url(off) }]));
    expect(r).toMatchObject({ ok: false, detail: 'public-key-point in keys[0]' });
    expect(JSON.stringify(r)).not.toContain(toBase64Url(off));
    expect(
      JSON.stringify(readKeyFile(file([{ id: 'a', publicKey: p }, keyOf('a')]))),
    ).not.toContain(p);
  });
  it('names the index of the faulty entry, and loadKeys carries it into its message', () => {
    const third = file([keyOf('a'), keyOf('b'), { id: 'Bad', publicKey: pub() }]);
    expect(readKeyFile(third)).toMatchObject({ ok: false, detail: 'id in keys[2]' });
    const dup = file([keyOf('a'), keyOf('b'), keyOf('a')]);
    expect(readKeyFile(dup)).toMatchObject({ ok: false, detail: 'duplicate-id in keys[2]' });
    // a rule of the whole file has no index
    expect(readKeyFile(file([], { keys: {} }))).toMatchObject({ ok: false, detail: 'key-count' });
    expect(() => loadKeys('/x/keys.json', () => JSON.stringify(third))).toThrow(
      /\(bad-key-file: id in keys\[2\]\)/,
    );
  });
  it('checks the point itself: only a point of the curve gives a key object', () => {
    const point = makeTestKey('x').publicKey;
    expect(publicKeyObject(point)).not.toBeNull();
    const off = Uint8Array.from(point);
    off[40] = off[40]! ^ 0x80;
    expect(publicKeyObject(off)).toBeNull();
  });
  it('accepts exactly 64 keys', () => {
    const many = Array.from({ length: 64 }, (_, i) => keyOf(`k${i}`));
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
    // an expressly empty list is valid (it blocks everybody, docs/relay.md); a missing list is not
    expect(loadKeys('/x/keys.json', () => JSON.stringify(file([])))).toEqual([]);
    expect(() => loadKeys('/x/keys.json', () => JSON.stringify({ version: 2 }))).toThrow(
      /bad-key-file/,
    );
    expect(loadKeys('/x/keys.json', () => JSON.stringify(file([keyOf('a')])))).toHaveLength(1);
  });
});

describe('relay start: authentication', () => {
  const env = { RELAY_ORIGINS: 'https://app.example', RELAY_SERVICES: 'freetsa' };
  it('refuses to start without a key file', () => {
    expect(() => readConfig(env, () => SERVICES)).toThrow(/RELAY_KEYS_FILE/);
  });
  it('starts without keys only with RELAY_AUTH=off said expressly', () => {
    expect(readConfig({ ...env, RELAY_AUTH: 'off' }, () => SERVICES).keys).toBe('off');
    expect(() => readConfig({ ...env, RELAY_AUTH: 'no' }, () => SERVICES)).toThrow(/RELAY_AUTH/);
    expect(() => readConfig({ ...env, RELAY_AUTH: '' }, () => SERVICES)).toThrow(/RELAY_KEYS_FILE/);
  });
  it('reads the key file when one is named', () => {
    const read = (): string => JSON.stringify(file([keyOf('a')]));
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
    const keys = [{ id: 'a', publicKey: makeTestKey('a').publicKey }];
    expect(startEvent(8080, SERVICES, 'off')).toMatchObject({ event: 'start', auth: 'off' });
    expect(startEvent(8080, SERVICES, keys)).toMatchObject({ auth: 'on' });
    expect(JSON.stringify(startEvent(8080, SERVICES, keys))).not.toContain('"a"');
  });
  it('the process ends with exit code 1 and one error line when the key file is missing', () => {
    const root = new URL('..', import.meta.url);
    const r = spawnSync(process.execPath, ['relay/main.ts'], {
      cwd: root,
      encoding: 'utf8',
      env: {
        PATH: process.env.PATH ?? '',
        RELAY_ORIGINS: 'https://app.example',
        RELAY_SERVICES: 'freetsa',
      },
      timeout: 15_000,
    });
    expect(r.status).toBe(1);
    expect(r.stdout).toBe('');
    expect(r.stderr).toContain('config-error');
    expect(r.stderr).toContain('RELAY_KEYS_FILE');
  });
  it('the process ends with exit code 1 and a config-error naming the ids when RELAY_SERVICES is missing', () => {
    const root = new URL('..', import.meta.url);
    const r = spawnSync(process.execPath, ['relay/main.ts'], {
      cwd: root,
      encoding: 'utf8',
      env: { PATH: process.env.PATH ?? '', RELAY_AUTH: 'off' },
      timeout: 15_000,
    });
    expect(r.status).toBe(1);
    expect(r.stdout).toBe('');
    const line = JSON.parse(r.stderr.trim()) as { event: string; message: string };
    expect(line.event).toBe('config-error');
    expect(line.message).toMatch(/^RELAY_SERVICES fehlt/);
    for (const id of ['freetsa', 'sectigo', 'digicert', 'certum']) {
      expect(line.message).toContain(id);
    }
    expect(line.message).toContain('docs/dienste.md');
  });
});

describe('scripts/make-key.ts', () => {
  const run = (...args: string[]) =>
    spawnSync(process.execPath, ['scripts/make-key.ts', ...args], {
      cwd: new URL('..', import.meta.url),
      encoding: 'utf8',
      timeout: 15_000,
    });
  it('prints a private key and a file entry that belong together, and nothing else', async () => {
    const r = run('app-1');
    expect(r.status).toBe(0);
    const lines = r.stdout.trimEnd().split('\n');
    expect(lines).toHaveLength(2);
    const privateKey = fromBase64Url(lines[0]!);
    const entry = JSON.parse(lines[1]!) as { id: string; publicKey: string };
    expect(Object.keys(entry).sort()).toEqual(['id', 'publicKey']);
    // the entry is exactly what the relay's reader takes
    expect(readKeyFile({ version: 2, keys: [entry] }).ok).toBe(true);
    // the library signs with the private key and the relay's key (from the entry) verifies it
    const signed = await signRelayRequest({
      privateKey: privateKey!,
      keyId: entry.id,
      method: 'POST',
      path: '/v1/stamp/freetsa',
      body: new Uint8Array(3),
      nowMs: 1_700_000_000_000,
    });
    expect(signed.ok).toBe(true);
    const key = publicKeyObject(fromBase64Url(entry.publicKey)!)!;
    const message = authMessage('POST', '/v1/stamp/freetsa', 1_700_000_000, new Uint8Array(3));
    const sig = Buffer.from((signed as { value: string }).value.split('.')[3]!, 'base64url');
    expect(verify('sha256', Buffer.from(message), { key, dsaEncoding: 'ieee-p1363' }, sig)).toBe(
      true,
    );
    // the private key is not in the entry, and each run makes a new pair
    expect(lines[1]).not.toContain(lines[0]);
    expect(run('app-1').stdout).not.toBe(r.stdout);
  });
  it('refuses a bad key id and prints no key', () => {
    const r = run('App');
    expect(r.status).toBe(2);
    expect(r.stdout).toBe('');
  });
});
