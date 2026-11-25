import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as client from '../src/client/index.ts';
import type { ClientReason } from '../src/client/index.ts';
import { CLIENT_LIMITS } from '../src/client/client.ts';
import { EVIDENCE_LIMITS } from '../src/client/evidence.ts';
import * as core from '../src/index.ts';
import { DER_LIMITS } from '../src/lib/der.ts';
import { sha256 } from './helpers.ts';
import { KEY_1, TEST_AUDIENCE, TRUST } from './client-harness.ts';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (path: string) => readFileSync(join(ROOT, path), 'utf8');
const model = read('docs/data-model.html');
const files = (dir: string): string[] =>
  readdirSync(dir).flatMap((n) =>
    statSync(join(dir, n)).isDirectory() ? files(join(dir, n)) : [join(dir, n)],
  );

describe('the client is a separate entry point', () => {
  const sources = files(join(ROOT, 'src', 'client')).filter((f) => f.endsWith('.ts'));
  it('has sources', () => expect(sources.length).toBeGreaterThanOrEqual(4));
  for (const file of sources) {
    it(`${file.slice(ROOT.length)} imports nothing from node: and uses no Buffer or process`, () => {
      const text = readFileSync(file, 'utf8');
      expect(text).not.toMatch(/['"]node:/);
      expect(text).not.toMatch(/\bBuffer\b(?!Source)|\bprocess\b|\brequire\(/);
      expect(text).not.toMatch(/\bimport\(/);
    });
  }
  it('only the client calls fetch: no other source of src/ does', () => {
    for (const file of files(join(ROOT, 'src')).filter((f) => f.endsWith('.ts'))) {
      if (file.includes(join('src', 'client'))) continue;
      expect(readFileSync(file, 'utf8'), file).not.toMatch(/\bfetch\b/);
    }
  });
  it('the main entry does not re-export the client, and the library does not import it', () => {
    for (const name of Object.keys(client)) expect(Object.keys(core), name).not.toContain(name);
    for (const file of files(join(ROOT, 'src', 'lib'))) {
      expect(readFileSync(file, 'utf8'), file).not.toMatch(/from ['"]\.\.\/client/);
    }
    expect(read('src/index.ts')).not.toMatch(/client/);
    expect(read('src/lib/index.ts')).not.toMatch(/client/);
  });
  it('package.json exports ./client with types and keeps the other entries', () => {
    const pkg = JSON.parse(read('package.json')) as {
      exports: Record<string, unknown>;
      files: string[];
    };
    expect(pkg.exports['./client']).toEqual({
      types: './dist/client/index.d.ts',
      import: './dist/client/index.js',
    });
    expect(pkg.exports['.']).toEqual({ types: './dist/index.d.ts', import: './dist/index.js' });
    expect(pkg.files).toContain('dist');
  });
});

describe('the built package (after `npm run build`)', () => {
  const built = existsSync(join(ROOT, 'dist', 'client', 'index.js'));
  if (!built) console.warn('SKIPPED: dist/client is missing, run `npm run build` first');
  it.skipIf(!built)('dist/client/index.js loads and makes a working client', async () => {
    const mod = (await import(
      new URL('../dist/client/index.js', import.meta.url).href
    )) as typeof client;
    expect(Object.keys(mod).sort()).toEqual(Object.keys(client).sort());
    const made = mod.createRelayClient({
      relayUrl: 'https://relay.example',
      audience: TEST_AUDIENCE,
      keyId: KEY_1.id,
      privateKey: KEY_1.privateKey,
      trust: TRUST,
      services: ['freetsa'],
      fetch: () => Promise.reject(new Error('offline')),
    });
    expect(made.ok).toBe(true);
    if (made.ok) {
      const r = await made.value.stamp(sha256('built'));
      expect(r).toMatchObject({ ok: false, reason: 'network-error' });
    }
  });
  it.skipIf(!built)(
    'the declarations of the client point to .js files and the library next to it',
    () => {
      for (const name of ['index', 'client', 'evidence']) {
        const text = read(`dist/client/${name}.d.ts`);
        expect(text).not.toMatch(/from ['"][^'"]+\.ts['"]/);
      }
      expect(existsSync(join(ROOT, 'dist', 'lib', 'bytes.js'))).toBe(true);
    },
  );
  it.skipIf(!built)('the built main entry has no client in it', async () => {
    const main = (await import(new URL('../dist/index.js', import.meta.url).href)) as object;
    expect(Object.keys(main)).not.toContain('createRelayClient');
  });
});

describe('docs and code agree on the client', () => {
  it('data-model.html names every export of the client entry', () => {
    for (const name of Object.keys(client)) {
      if (name.endsWith('_LIMITS')) continue; // the limits have rows of their own below
      expect(model, name).toContain(name);
    }
  });
  it('data-model.html lists the client limits with their values', () => {
    for (const [name, value] of Object.entries({ ...EVIDENCE_LIMITS, ...CLIENT_LIMITS })) {
      expect(model, name).toMatch(new RegExp(`<td>${name}</td><td>${value}</td>`));
    }
    expect(EVIDENCE_LIMITS.MAX_TOKEN_BYTES).toBe(DER_LIMITS.maxBytes);
  });
  it('data-model.html lists every client error code, and docs/client.md explains them', () => {
    const REASONS: Record<Exclude<ClientReason, core.Reason>, true> = {
      'network-error': true,
      timeout: true,
      aborted: true,
      paused: true,
      'relay-error': true,
      'bad-response': true,
    };
    const doc = read('docs/client.md');
    for (const code of Object.keys(REASONS)) {
      expect(model, code).toContain(`reason: ${code}`);
      expect(doc, code).toContain(`\`${code}\``);
    }
    for (const code of ['bad-evidence', 'evidence-hash-mismatch']) {
      expect(model, code).toContain(`<td>${code}</td>`);
      expect(doc, code).toContain(`\`${code}\``);
    }
  });
  it('every option of the client is in data-model.html and docs/client.md', () => {
    const doc = read('docs/client.md');
    for (const name of [
      'relayUrl',
      'audience',
      'keyId',
      'privateKey',
      'trust',
      'services',
      'fetch',
      'now',
      'random',
      'timeoutMs',
      'maxAttempts',
      'minGenTimeSlackMs',
      'maxClockOffsetMs',
      'monoNow',
      'attemptTimeoutMs',
    ]) {
      expect(model, name).toContain(`<tr><td>${name}</td>`);
      expect(doc, name).toContain(`\`${name}\``);
    }
  });
  it('docs/client.md states the defaults and the formula of the deadline', () => {
    const doc = read('docs/client.md').replace(/\s+/g, ' ');
    for (const text of [
      `${CLIENT_LIMITS.DEFAULT_TIMEOUT_MS}`,
      'RELAY_MAX_WAIT_MS` + Fenster + Kette + 17 s',
      'minGenTime',
      'Uhrabgleich',
      'jti',
      'im Browserspeicher',
      '`evidence` v1',
    ]) {
      expect(doc, text).toContain(text);
    }
  });
  it('the README shows the client', () => {
    const readme = read('README.md');
    expect(readme).toContain('zeitstempel/client');
    expect(readme).toContain('createRelayClient');
    expect(readme).toContain('verifyEvidence');
    expect(readme).toContain('docs/client.md');
  });
});
