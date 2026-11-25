import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { toBase64Url } from '../src/index.ts';
import { RELAY_LIMITS } from '../relay/limits.ts';
import { createKeyWatcher } from '../relay/keywatch.ts';
import type { RelayKey } from '../relay/keys.ts';
import { makeTestKey, type TestKey } from './auth-helpers.ts';

// The key file is read again while the relay runs: a change is found whatever the file system says about it
// (same modification time, size and inode), and the file is read only if it is a plain, small file (no FIFO that
// blocks, no device, no huge file), with the permission check repeated at every look.

const posix = process.platform !== 'win32';
const A = makeTestKey('app-a');
const B = makeTestKey('app-b');
const C = makeTestKey('app-c'); // same id length as B: a file with C instead of B has the same size
const text = (keys: TestKey[]) =>
  JSON.stringify({
    version: 2,
    keys: keys.map((k) => ({ id: k.id, publicKey: toBase64Url(k.publicKey) })),
  });

let dir: string;
let path: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'zeitstempel-keyfile-'));
  path = join(dir, 'keys.json');
});
afterEach(() => {
  chmodSync(dir, 0o700);
  rmSync(dir, { recursive: true, force: true });
});

function watch(over: Partial<Parameters<typeof createKeyWatcher>[0]> = {}) {
  const sets: string[][] = [];
  const events: string[] = [];
  const watcher = createKeyWatcher({
    path,
    apply: (keys: readonly RelayKey[]) => void sets.push(keys.map((k) => k.id)),
    now: () => Date.now(),
    startMs: Date.now(),
    onRestart: () => void events.push('restart'),
    onReloaded: () => void events.push('reloaded'),
    onFailed: () => void events.push('failed'),
    ...over,
  });
  return { watcher, sets, events };
}

describe('the watcher finds a change whatever the file system says about it', () => {
  it.skipIf(!posix)(
    'a key removed in place, with the same size and the modification time put back, is found',
    () => {
      const fixed = new Date(1_700_000_000_000); // whole seconds: a time the file system keeps exactly
      writeFileSync(path, text([A, B]));
      utimesSync(path, fixed, fixed);
      const before = statSync(path);
      const { watcher, sets, events } = watch();
      watcher.check(); // the start state
      expect(sets).toEqual([['app-a', 'app-b']]);
      // B is blocked: replaced by C (same length), written in place (same inode), the old times put back
      writeFileSync(path, text([A, C]));
      utimesSync(path, fixed, fixed);
      const after = statSync(path);
      expect([after.size, after.ino, after.mtimeMs]).toEqual([
        before.size,
        before.ino,
        before.mtimeMs,
      ]);
      watcher.check();
      expect(sets).toEqual([
        ['app-a', 'app-b'],
        ['app-a', 'app-c'],
      ]);
      expect(events).toEqual(['reloaded']);
    },
  );

  it('the same content again is no change (a touch reloads nothing)', () => {
    writeFileSync(path, text([A, B]));
    const { watcher, sets, events } = watch();
    watcher.check();
    const later = new Date(Date.now() + 60_000);
    utimesSync(path, later, later);
    watcher.check();
    watcher.check();
    expect(sets).toHaveLength(1);
    expect(events).toEqual([]);
  });

  it('an invalid file is counted once; the same content later counts again after a good state', () => {
    writeFileSync(path, text([A]));
    const { watcher, events } = watch();
    watcher.check();
    writeFileSync(path, '{ nope');
    watcher.check();
    watcher.check();
    writeFileSync(path, text([A]));
    watcher.check(); // back to the state that is active: nothing to apply
    writeFileSync(path, '{ nope');
    watcher.check(); // the same bad content as before, but a new failure
    expect(events).toEqual(['failed', 'failed']);
  });
});

// A FIFO blocks a read for good: these cases run in a child process with a time limit, so a regression fails the
// test instead of hanging the whole run.
function inChild(code: string): string {
  const keys = new URL('../relay/keys.ts', import.meta.url).href;
  const watch = new URL('../relay/keywatch.ts', import.meta.url).href;
  const script = `import { loadKeyFile } from ${JSON.stringify(keys)};
import { createKeyWatcher } from ${JSON.stringify(watch)};
const target = process.argv[1];
${code}`;
  return execFileSync(process.execPath, ['--input-type=module', '-e', script, '--', ''], {
    timeout: 8000,
    encoding: 'utf8',
    env: { ...process.env, KEYFILE_TARGET: path },
  });
}
const probe = `const path = process.env.KEYFILE_TARGET;
let message = null;
try { loadKeyFile(path); } catch (e) { message = e.message; }
let failed = 0, applied = 0;
const w = createKeyWatcher({ path, apply: () => { applied += 1; }, now: () => Date.now(), startMs: Date.now(),
  onRestart: () => {}, onFailed: () => { failed += 1; } });
w.check(); w.check();
console.log(JSON.stringify({ message, failed, applied }));`;

describe.skipIf(!posix)('only a plain, small file is read', () => {
  const run = () =>
    JSON.parse(inChild(probe).trim()) as { message: string; failed: number; applied: number };

  it('a FIFO is refused at once, in the reader and in the watcher (no hang)', () => {
    execFileSync('mkfifo', [path]);
    const r = run();
    expect(r.message).toContain('keine reguläre Datei');
    expect(r).toMatchObject({ failed: 1, applied: 0 }); // counted once for the state
  });

  it('a symlink to a FIFO is refused as well', () => {
    const fifo = join(dir, 'fifo');
    execFileSync('mkfifo', [fifo]);
    symlinkSync(fifo, path);
    expect(run()).toMatchObject({ failed: 1, applied: 0 });
  });

  it('a directory is refused', () => {
    mkdirSync(path);
    const r = run();
    expect(r.message).toContain('keine reguläre Datei');
    expect(r).toMatchObject({ failed: 1, applied: 0 });
  });

  it('a file larger than the limit is refused without being parsed', () => {
    writeFileSync(path, ' '.repeat(RELAY_LIMITS.keyFileMaxBytes + 1) + text([A]));
    const r = run();
    expect(r.message).toContain('größer als');
    expect(r).toMatchObject({ failed: 1, applied: 0 });
  });

  it('a file of exactly the limit is read (padding is whitespace)', () => {
    const body = text([A]);
    writeFileSync(path, body + ' '.repeat(RELAY_LIMITS.keyFileMaxBytes - body.length));
    expect(run()).toMatchObject({ message: null, failed: 0, applied: 1 });
  });

  it('a symlink to a plain file is followed (a ConfigMap-like layout keeps working)', () => {
    const real = join(dir, 'real.json');
    writeFileSync(real, text([A]));
    symlinkSync(real, path);
    expect(run()).toMatchObject({ message: null, failed: 0, applied: 1 });
  });

  it('a file that is not there is a failure counted once', () => {
    expect(run()).toMatchObject({ failed: 1, applied: 0 });
  });
});

describe.skipIf(!posix)('the permission check is repeated at every look', () => {
  it('a file that becomes writable for group or others is reported once per change of state', () => {
    writeFileSync(path, text([A]));
    chmodSync(path, 0o600);
    const messages: string[] = [];
    const { watcher } = watch({ onWritable: (m: string) => void messages.push(m) });
    watcher.check();
    watcher.check();
    expect(messages).toEqual([]);
    chmodSync(path, 0o664);
    watcher.check();
    watcher.check(); // the same state: not again
    expect(messages).toHaveLength(1);
    expect(messages[0]).toContain(path);
    expect(messages[0]).toContain('Modus 664');
    expect(messages[0]).not.toContain(toBase64Url(A.publicKey)); // path and mode, nothing of the file
    chmodSync(path, 0o600);
    watcher.check();
    chmodSync(path, 0o666);
    watcher.check(); // writable again after a good state: reported again
    expect(messages).toHaveLength(2);
  });

  it('a file known to be writable at the start (reported there) is not reported a second time', () => {
    writeFileSync(path, text([A]));
    chmodSync(path, 0o666);
    const messages: string[] = [];
    const { watcher } = watch({
      onWritable: (m: string) => void messages.push(m),
      writableAtStart: true,
    });
    watcher.check();
    watcher.check();
    expect(messages).toEqual([]);
  });

  it('the file is still read: the warning is no refusal', () => {
    writeFileSync(path, text([A]));
    chmodSync(path, 0o666);
    const { watcher, sets } = watch({ onWritable: () => undefined });
    watcher.check();
    expect(sets).toEqual([['app-a']]);
  });
});
