// The container start for hosts without a file mount: the key file comes from `RELAY_KEYS_JSON`.
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { keyFileFromEnv } from '../relay/container-start.ts';

const JSON_TEXT = '{"version":3,"keys":[]}';

describe('keyFileFromEnv', () => {
  let dir = '';
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'zs-start-'));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));
  const target = () => join(dir, 'keys.json');

  it('does nothing without the variable: the mounted file stays in charge', () => {
    for (const value of [undefined, '']) {
      const env: NodeJS.ProcessEnv = { RELAY_KEYS_FILE: '/etc/x.json', RELAY_KEYS_JSON: value };
      keyFileFromEnv(env, target());
      expect(env.RELAY_KEYS_FILE).toBe('/etc/x.json');
      expect(() => statSync(target())).toThrow();
    }
  });

  it('writes the text unchanged, points RELAY_KEYS_FILE at it and takes the variable away', () => {
    const env: NodeJS.ProcessEnv = { RELAY_KEYS_FILE: '/etc/x.json', RELAY_KEYS_JSON: JSON_TEXT };
    keyFileFromEnv(env, target());
    expect(readFileSync(target(), 'utf8')).toBe(JSON_TEXT);
    expect(env.RELAY_KEYS_FILE).toBe(target());
    expect('RELAY_KEYS_JSON' in env).toBe(false);
    if (process.platform !== 'win32') expect(statSync(target()).mode & 0o777).toBe(0o600);
  });

  it('replaces a file left from an earlier start', () => {
    writeFileSync(target(), 'old');
    keyFileFromEnv({ RELAY_KEYS_JSON: JSON_TEXT }, target());
    expect(readFileSync(target(), 'utf8')).toBe(JSON_TEXT);
  });
});
