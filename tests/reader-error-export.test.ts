// `ReaderError` is public: an app that calls `readToken`, `parseCertificate` or `parsePemCertificates` must be able
// to tell a reader error (`instanceof ReaderError`, `.reason`) from any other throw.
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import * as entry from '../src/index.ts';
import * as lib from '../src/lib/index.ts';

const DIST = new URL('../dist/index.js', import.meta.url);

function caught(run: () => unknown): unknown {
  try {
    run();
  } catch (e) {
    return e;
  }
  return undefined;
}

describe('ReaderError is exported', () => {
  it('from the package entry and from the library entry, as the same class', () => {
    expect(typeof entry.ReaderError).toBe('function');
    expect(entry.ReaderError).toBe(lib.ReaderError);
    expect(new entry.ReaderError('malformed')).toBeInstanceOf(Error);
    expect(new entry.ReaderError('bad-pem').reason).toBe('bad-pem');
  });

  it('is what readToken, parseCertificate and parsePemCertificates throw (instanceof through the entry)', () => {
    for (const run of [
      () => entry.readToken(new Uint8Array([1, 2, 3])),
      () => entry.parseCertificate(new Uint8Array([1, 2, 3])),
      () =>
        entry.parsePemCertificates('-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n'),
    ]) {
      const e = caught(run);
      expect(e).toBeInstanceOf(entry.ReaderError);
      expect(typeof (e as InstanceType<typeof entry.ReaderError>).reason).toBe('string');
    }
  });

  it('does not make the core functions throw: they still answer with a code', () => {
    expect(entry.readTimestampResponse(new Uint8Array([1, 2, 3])).ok).toBe(false);
  });

  // the build is made by `npm run build` (the CI runs it after the tests): no dist, a visible skip
  it.skipIf(!existsSync(DIST))(
    'is exported by the build in dist/index.js too (a class, the same one for every importer)',
    () => {
      const r = spawnSync(
        process.execPath,
        [
          '--input-type=module',
          '-e',
          `import * as m from ${JSON.stringify(DIST.href)};
         let e; try { m.readToken(new Uint8Array([1])); } catch (x) { e = x; }
         console.log(JSON.stringify([typeof m.ReaderError, e instanceof m.ReaderError, typeof e?.reason]));`,
        ],
        { encoding: 'utf8' },
      );
      expect(r.stderr).toBe('');
      expect(JSON.parse(r.stdout.trim())).toEqual(['function', true, 'string']);
    },
  );
});
