import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { connect, createServer, type AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { toBase64Url } from '../src/index.ts';
import type { UpstreamCredentials } from '../relay/credentials.ts';
import type { RelayKey } from '../relay/keys.ts';
import { buildRelayOptions, listenErrorMessage, readConfig, stopServer } from '../relay/main.ts';
import { RELAY_LIMITS } from '../relay/limits.ts';
import type { RelayService } from '../relay/relay.ts';
import { createRelayServer } from '../relay/server.ts';
import type { Upstream } from '../relay/upstream.ts';
import { makeTestKey, nodeAuthHeader, type TestKey } from './auth-helpers.ts';
import { sha256 } from './helpers.ts';
import { build, int, seq } from './token-builder.ts';
import { children, integerBytes, octets, parseDer } from '../src/lib/der.ts';

// The wiring of relay/main.ts: what the settings hand to the relay, and what the process does around it (the key
// file watcher, the permission warning, SIGTERM). Nothing here reaches a real service: the in-process part uses a stub
// upstream, and the process part only sends requests that end before the service (bad hash after a good signature) or
// that are answered by `close()` before their window is stamped.

const SIGNER = build();
const KEY_A = makeTestKey('app-a');
const KEY_B = makeTestKey('app-b');
const SOLO = makeTestKey('app-solo');

const genTimeText = (ms: number) =>
  new Date(ms)
    .toISOString()
    .replace(/[-:T]/g, '')
    .replace(/\.\d+Z$/, 'Z');
const imprintOf = (request: Uint8Array): Uint8Array =>
  octets(children(children(parseDer(request))[1]!)[1]!);
function replyFor(request: Uint8Array, atMs: number): Uint8Array {
  const parts = children(parseDer(request));
  const made = build({
    keys: SIGNER.keys,
    hash: imprintOf(request),
    nonceBytes: integerBytes(parts[2]!),
    genTime: genTimeText(atMs),
  });
  return seq(seq(int(0)), made.token);
}

describe('buildRelayOptions: every setting reaches the relay', () => {
  const service = (over: Partial<RelayService>): RelayService => ({
    id: 'paid-relay',
    name: 'Paid',
    url: 'https://paid.example/tsr',
    hash: 'sha256',
    anchors: [],
    anchorPems: [SIGNER.caPem],
    qualified: false,
    minIntervalMs: 30_000, // two stamps per minute
    intendedUse: 'test',
    terms: 'test',
    auth: { kind: 'basic', source: 'relay' },
    ...over,
  });
  const keys: RelayKey[] = [
    { id: KEY_A.id, publicKey: KEY_A.publicKey },
    { id: SOLO.id, publicKey: SOLO.publicKey, solo: true },
  ];
  const env = {
    RELAY_SERVICES: 'paid-relay',
    RELAY_KEYS_FILE: '/x/keys.json',
    RELAY_UPSTREAM_AUTH_PAID_RELAY: 'relay-user:relay-pass',
    RELAY_BATCH_MS: '30000',
  };

  async function run(extraEnv: Record<string, string>, minIntervalMs = 30_000) {
    const config = readConfig(
      { ...env, ...extraEnv },
      () => [service({ minIntervalMs })],
      () => keys,
      () => null,
    );
    const clock = { now: Date.now() };
    const calls: { creds: UpstreamCredentials | undefined; at: number }[] = [];
    const upstream: Upstream = async (_target, body, creds) => {
      calls.push({ creds, at: clock.now });
      return {
        status: 200,
        contentType: 'application/timestamp-reply',
        body: replyFor(body, clock.now),
      };
    };
    const { server, relay } = createRelayServer(
      buildRelayOptions(config, {
        upstream,
        random: (n) => new Uint8Array(randomBytes(n)),
        now: () => clock.now,
      }),
    );
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    let n = 0;
    const post = (key: TestKey, tag: string, solo: boolean) => {
      const path = '/v1/stamp/paid-relay';
      const text = JSON.stringify({
        hash: toBase64Url(sha256(tag)),
        ...(solo ? { mode: 'solo' } : {}),
      });
      return fetch(base + path, {
        method: 'POST',
        body: text,
        headers: {
          'Content-Type': 'application/json',
          'X-Zeitstempel-Auth': nodeAuthHeader(
            key,
            key.id,
            'POST',
            path,
            Math.floor(clock.now / 1000) + (n++ % 20),
            new TextEncoder().encode(text),
          ),
        },
        signal: AbortSignal.timeout(8000),
      });
    };
    const close = () =>
      new Promise<void>((r) => {
        relay.close();
        server.closeAllConnections();
        server.close(() => r());
      });
    return { clock, calls, post, close, config };
  }

  it('upstreamAuth: the credentials the relay holds are sent to the service', async () => {
    const h = await run({});
    try {
      const res = await h.post(SOLO, 'creds', true);
      expect(res.status).toBe(200);
      expect(h.calls).toHaveLength(1);
      expect(h.calls[0]!.creds).toEqual({
        kind: 'basic',
        user: 'relay-user',
        password: 'relay-pass',
      });
    } finally {
      await h.close();
    }
  });

  it('batch: the window setting makes collecting operation (a normal request gets a receipt)', async () => {
    const h = await run({ RELAY_BATCH_MS: '1000' }, 1000);
    try {
      const res = await h.post(KEY_A, 'batched', false);
      expect(res.status).toBe(200);
      expect(Object.keys((await res.json()) as object)).toContain('batch');
    } finally {
      await h.close();
    }
  });

  it('maxWaitMs: RELAY_MAX_WAIT_MS decides whether a request waits for a slot or gets 429 at once', async () => {
    const h = await run({ RELAY_MAX_WAIT_MS: '1000' });
    try {
      // both slots of the minute are taken at t0; 57 s later the first frees in 3 s: more than 1 s of waiting
      for (const tag of ['s1', 's2']) expect((await h.post(SOLO, tag, true)).status).toBe(200);
      h.clock.now += 57_000;
      const started = Date.now();
      const refused = await h.post(SOLO, 's3', true);
      expect(refused.status).toBe(429); // with the default (30 s) it would wait the 3 s and be served
      expect(Date.now() - started).toBeLessThan(2000);
      expect(h.calls).toHaveLength(2);
    } finally {
      await h.close();
    }
  });

  it('without RELAY_MAX_WAIT_MS the default is used: the same request waits and is served', async () => {
    const h = await run({});
    try {
      for (const tag of ['s1', 's2']) expect((await h.post(SOLO, tag, true)).status).toBe(200);
      h.clock.now += 59_700; // the first slot frees in 300 ms (the clock of the test moves on by itself below)
      setTimeout(() => (h.clock.now += 1000), 500);
      const res = await h.post(SOLO, 's3', true);
      expect(res.status).toBe(200);
      expect(h.calls).toHaveLength(3);
    } finally {
      await h.close();
    }
  });
});

// ---- the process ----

const ROOT = new URL('..', import.meta.url);
const posix = process.platform !== 'win32';
const entry = (k: TestKey) => ({ id: k.id, publicKey: toBase64Url(k.publicKey) });
const keyFile = (keys: TestKey[]) => JSON.stringify({ version: 2, keys: keys.map(entry) });

async function freePort(): Promise<number> {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  const { port } = s.address() as AddressInfo;
  await new Promise<void>((r) => s.close(() => r()));
  return port;
}

interface Proc {
  port: number;
  out: string[];
  err: string[];
  exited: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
  child: ChildProcess;
  /** A signed request with a garbage hash: 401 when the key is not valid, 400 `bad-hash` when it is. */
  probe: (key: TestKey) => Promise<number>;
  /** A valid request of a valid key (it opens a window in collecting operation). */
  stampRequest: (key: TestKey) => Promise<Response>;
}

let dir: string;
let keysPath: string;
const running: ChildProcess[] = [];
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'zeitstempel-main-'));
  keysPath = join(dir, 'keys.json');
});
afterEach(() => {
  for (const c of running.splice(0)) c.kill('SIGKILL');
  rmSync(dir, { recursive: true, force: true });
});

async function startMain(extra: Record<string, string> = {}): Promise<Proc> {
  const port = await freePort();
  const child = spawn(process.execPath, ['relay/main.ts'], {
    cwd: ROOT,
    env: {
      PATH: process.env.PATH ?? '',
      PORT: String(port),
      RELAY_SERVICES: 'freetsa',
      RELAY_KEYS_FILE: keysPath,
      ...extra,
    },
  });
  running.push(child);
  const out: string[] = [];
  const err: string[] = [];
  let ready!: () => void;
  const started = new Promise<void>((r) => (ready = r));
  const lines = (into: string[], onLine?: (l: string) => void) => {
    let rest = '';
    return (chunk: Buffer) => {
      rest += chunk.toString('utf8');
      let at: number;
      while ((at = rest.indexOf('\n')) >= 0) {
        const line = rest.slice(0, at);
        rest = rest.slice(at + 1);
        into.push(line);
        onLine?.(line);
      }
    };
  };
  child.stdout!.on(
    'data',
    lines(out, (l) => l.includes('"event":"start"') && ready()),
  );
  child.stderr!.on('data', lines(err));
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((r) =>
    child.on('exit', (code, signal) => r({ code, signal })),
  );
  await Promise.race([
    started,
    exited.then((e) => {
      throw new Error(`relay ended at start: ${JSON.stringify(e)} ${err.join('\n')}`);
    }),
  ]);
  const send = (key: TestKey, text: string) => {
    const path = '/v1/stamp/freetsa';
    return fetch(`http://127.0.0.1:${port}${path}`, {
      method: 'POST',
      body: text,
      headers: {
        'Content-Type': 'application/json',
        'X-Zeitstempel-Auth': nodeAuthHeader(
          key,
          key.id,
          'POST',
          path,
          Math.floor(Date.now() / 1000),
          new TextEncoder().encode(text),
        ),
      },
      signal: AbortSignal.timeout(4000),
    });
  };
  return {
    port,
    out,
    err,
    exited,
    child,
    probe: async (key) => (await send(key, '{"hash":"x"}')).status,
    stampRequest: (key) => send(key, JSON.stringify({ hash: toBase64Url(sha256('wiring')) })),
  };
}

const until = async (check: () => Promise<boolean> | boolean, ms: number): Promise<boolean> => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await check()) return true;
    await new Promise((r) => setTimeout(r, 300));
  }
  return false;
};

describe('relay/main.ts as a process', () => {
  it('the key file watcher runs: a key added to the file counts, a key removed from it stops', async () => {
    writeFileSync(keysPath, keyFile([KEY_A]), { mode: 0o600 });
    const p = await startMain();
    expect(await p.probe(KEY_A)).toBe(400); // valid key, garbage hash: past the signature
    expect(await p.probe(KEY_B)).toBe(401); // not in the file
    writeFileSync(keysPath, keyFile([KEY_A, KEY_B]));
    expect(await until(async () => (await p.probe(KEY_B)) === 400, 15_000)).toBe(true);
    writeFileSync(keysPath, keyFile([KEY_A]));
    expect(await until(async () => (await p.probe(KEY_B)) === 401, 15_000)).toBe(true);
    expect(await p.probe(KEY_A)).toBe(400);
    p.child.kill('SIGTERM');
    expect((await p.exited).code).toBe(0);
  }, 45_000);

  it('a PORT that is not decimal ends the start with a German config-error line and exit code 1', async () => {
    const child = spawn(process.execPath, ['relay/main.ts'], {
      cwd: ROOT,
      env: {
        PATH: process.env.PATH ?? '',
        PORT: '0x50',
        RELAY_SERVICES: 'freetsa',
        RELAY_AUTH: 'off',
      },
    });
    running.push(child);
    let err = '';
    child.stderr!.on('data', (c: Buffer) => (err += c.toString('utf8')));
    const code = await new Promise((r) => child.on('exit', (c) => r(c)));
    expect(code).toBe(1);
    const line = JSON.parse(err.trim().split('\n')[0]!) as { event: string; message: string };
    expect(line.event).toBe('config-error');
    expect(line.message).toMatch(/^PORT: ungültig \(ganze Zahl von 1 bis 65535 erwartet/);
  }, 15_000);

  it('a port that is taken ends the start with a German config-error line (no stack trace) and exit code 1', async () => {
    const taken = createServer();
    await new Promise<void>((r) => taken.listen(0, '127.0.0.1', r));
    const { port } = taken.address() as AddressInfo;
    try {
      const child = spawn(process.execPath, ['relay/main.ts'], {
        cwd: ROOT,
        env: {
          PATH: process.env.PATH ?? '',
          PORT: String(port),
          RELAY_SERVICES: 'freetsa',
          RELAY_AUTH: 'off',
        },
      });
      running.push(child);
      let err = '';
      let out = '';
      child.stderr!.on('data', (c: Buffer) => (err += c.toString('utf8')));
      child.stdout!.on('data', (c: Buffer) => (out += c.toString('utf8')));
      const code = await new Promise((r) => child.on('exit', (c) => r(c)));
      expect(code).toBe(1);
      const lines = err.trim().split('\n');
      const error = lines.find((l) => l.includes('"event":"config-error"'));
      expect(error).toBeDefined();
      const line = JSON.parse(error!) as { event: string; message: string };
      expect(line.message).toContain(`Port ${port}`);
      expect(line.message).toContain('EADDRINUSE');
      expect(err).not.toMatch(/\n\s+at |node:events|Emitted 'error'/); // no stack trace
      expect(out).not.toContain('"event":"start"'); // it never said it was listening
    } finally {
      await new Promise<void>((r) => taken.close(() => r()));
    }
  }, 15_000);

  it('listenErrorMessage names the cause in German, by code only', () => {
    expect(listenErrorMessage('EADDRINUSE', 8080, '127.0.0.1')).toMatch(/^Port 8080 .*EADDRINUSE/);
    expect(listenErrorMessage('EACCES', 80, '127.0.0.1')).toMatch(/Port 80 .*EACCES/);
    expect(listenErrorMessage('EADDRNOTAVAIL', 8080, '10.9.8.7')).toContain('10.9.8.7');
    expect(listenErrorMessage('EMFILE', 8080, undefined)).toContain('EMFILE');
    expect(listenErrorMessage(undefined, 8080, undefined)).toContain('unbekannt');
  });

  it.skipIf(!posix)(
    'a key file that turns invalid is reported at once with one line (state only, no path, no content), not again for the same state',
    async () => {
      writeFileSync(keysPath, keyFile([KEY_A]), { mode: 0o600 });
      const p = await startMain();
      expect(p.err).toEqual([]);
      writeFileSync(keysPath, '{ "version": 2, "keys": [ not json SECRET-MARK');
      const failed = () => p.err.filter((l) => l.includes('Schlüsseldatei'));
      expect(await until(() => failed().length === 1, 15_000)).toBe(true);
      await new Promise((r) => setTimeout(r, 5500)); // another look: the same state, no second line
      expect(failed()).toHaveLength(1);
      expect(failed()[0]).toContain('"event":"warning"');
      expect(failed()[0]).not.toContain(keysPath);
      expect(failed()[0]).not.toContain('SECRET-MARK');
      expect(await p.probe(KEY_A)).toBe(400); // the old set stays active
      writeFileSync(keysPath, keyFile([KEY_A, KEY_B])); // fixed again: a later failure is a new state
      expect(await until(async () => (await p.probe(KEY_B)) === 400, 15_000)).toBe(true);
      writeFileSync(keysPath, 'broken again');
      expect(await until(() => failed().length === 2, 15_000)).toBe(true);
      p.child.kill('SIGTERM');
      expect((await p.exited).code).toBe(0);
    },
    60_000,
  );

  it('SIGTERM closes the relay (a waiting request gets 503 shutting-down) and the process ends with 0', async () => {
    writeFileSync(keysPath, keyFile([KEY_A]), { mode: 0o600 });
    const p = await startMain({ RELAY_BATCH_MS: '5000' });
    const waiting = p.stampRequest(KEY_A); // opens a window of 5 s: nothing is stamped before the signal
    await new Promise((r) => setTimeout(r, 600));
    p.child.kill('SIGTERM');
    const res = await waiting;
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: 'shutting-down' });
    const end = await p.exited;
    expect(end).toEqual({ code: 0, signal: null });
  }, 20_000);

  it.skipIf(!posix)(
    'a key file that turns writable for group or others is warned about once, with path and mode only',
    async () => {
      writeFileSync(keysPath, keyFile([KEY_A]), { mode: 0o600 });
      const p = await startMain();
      expect(p.err).toEqual([]);
      chmodSync(keysPath, 0o664);
      const warned = () => p.err.filter((l) => l.includes('"event":"warning"'));
      expect(await until(() => warned().length === 1, 15_000)).toBe(true);
      await new Promise((r) => setTimeout(r, 5500)); // another look: the same state, no second line
      expect(warned()).toHaveLength(1);
      expect(warned()[0]).toContain(keysPath);
      expect(warned()[0]).toContain('Modus 664');
      expect(warned()[0]).not.toContain(toBase64Url(KEY_A.publicKey));
      p.child.kill('SIGTERM');
      expect((await p.exited).code).toBe(0);
    },
    30_000,
  );

  it.skipIf(!posix)(
    'a key file that is writable at the start is warned about by the start only',
    async () => {
      writeFileSync(keysPath, keyFile([KEY_A]));
      chmodSync(keysPath, 0o666);
      const p = await startMain();
      await new Promise((r) => setTimeout(r, 5500)); // one look of the watcher after the start
      expect(p.err.filter((l) => l.includes('"event":"warning"'))).toHaveLength(1);
      p.child.kill('SIGTERM');
      await p.exited;
    },
    20_000,
  );

  // A connection with half a request: after `server.close()` Node no longer enforces the header and request deadlines,
  // so the process used to wait for it for ever (nothing ended it, a supervisor never restarted the relay).
  describe('ending with a connection that holds half a request', () => {
    const halfRequests: Record<string, string> = {
      'half a header': 'GET /health HTTP/1.1\r\nHost: x\r\nX-A:',
      'half a POST body':
        'POST /v1/stamp/freetsa HTTP/1.1\r\nHost: x\r\nContent-Length: 32\r\n\r\nabc',
    };
    for (const [name, head] of Object.entries(halfRequests)) {
      it(`SIGTERM with ${name} ends the process with 0 within the hard deadline`, async () => {
        writeFileSync(keysPath, keyFile([KEY_A]), { mode: 0o600 });
        const p = await startMain();
        const sock = connect(p.port, '127.0.0.1');
        sock.on('error', () => undefined);
        await new Promise<void>((r) => sock.once('connect', () => r()));
        sock.write(head);
        await new Promise((r) => setTimeout(r, 300));
        const t0 = Date.now();
        p.child.kill('SIGTERM');
        const end = await Promise.race([
          p.exited,
          new Promise<'hang'>((r) =>
            setTimeout(() => r('hang'), RELAY_LIMITS.shutdownHardMs + 3000),
          ),
        ]);
        sock.destroy();
        expect(end).toEqual({ code: 0, signal: null });
        expect(Date.now() - t0).toBeLessThan(RELAY_LIMITS.shutdownHardMs + 2000);
      }, 30_000);
    }

    it('restartAfter with half a request ends the process with 0 as well', async () => {
      writeFileSync(keysPath, keyFile([KEY_A]), { mode: 0o600 });
      const p = await startMain();
      const sock = connect(p.port, '127.0.0.1');
      sock.on('error', () => undefined);
      await new Promise<void>((r) => sock.once('connect', () => r()));
      sock.write('GET /health HTTP/1.1\r\nHost: x\r\nX-A:');
      // a restart time after the start that has passed at the next look of the watcher (every 5 s)
      const restartAfter = Math.floor(Date.now() / 1000) + 1;
      writeFileSync(keysPath, JSON.stringify({ version: 2, restartAfter, keys: [entry(KEY_A)] }), {
        mode: 0o600,
      });
      const end = await Promise.race([
        p.exited,
        new Promise<'hang'>((r) => setTimeout(() => r('hang'), 8000 + RELAY_LIMITS.shutdownHardMs)),
      ]);
      sock.destroy();
      expect(end).toEqual({ code: 0, signal: null });
      expect(p.out.some((l) => l.includes('restart-after'))).toBe(true);
    }, 40_000);
  });
});

describe('stopServer (the deadlines of ending)', () => {
  const stub = () => {
    const calls: string[] = [];
    let onClose: () => void = () => undefined;
    return {
      calls,
      closeDone: () => onClose(),
      server: {
        close: (cb?: () => void) => {
          calls.push('close');
          onClose = cb ?? (() => undefined);
          return undefined as never;
        },
        closeIdleConnections: () => void calls.push('idle'),
        closeAllConnections: () => void calls.push('all'),
      },
    };
  };
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('closes all connections after the grace time, not before, and exits at the hard deadline when nothing ends', () => {
    const s = stub();
    const exits: number[] = [];
    stopServer(s.server, (c) => exits.push(c), { graceMs: 2000, hardMs: 10_000 });
    vi.advanceTimersByTime(1999);
    expect(s.calls.includes('all')).toBe(false);
    vi.advanceTimersByTime(1);
    expect(s.calls.filter((c) => c === 'all')).toHaveLength(1);
    expect(exits).toEqual([]);
    vi.advanceTimersByTime(7999);
    expect(exits).toEqual([]);
    vi.advanceTimersByTime(1);
    expect(exits).toEqual([0]);
  });

  it('exits at once when the server reports itself closed', () => {
    const s = stub();
    const exits: number[] = [];
    stopServer(s.server, (c) => exits.push(c), { graceMs: 2000, hardMs: 10_000 });
    s.closeDone();
    expect(exits).toEqual([0]);
  });

  it('uses the limits of relay/limits.ts by default', () => {
    const s = stub();
    const exits: number[] = [];
    stopServer(s.server, (c) => exits.push(c));
    vi.advanceTimersByTime(RELAY_LIMITS.shutdownGraceMs);
    expect(s.calls).toContain('all');
    vi.advanceTimersByTime(RELAY_LIMITS.shutdownHardMs);
    expect(exits).toEqual([0]);
  });
});
