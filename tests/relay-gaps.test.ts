import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { cpSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import net, { type AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { toBase64Url } from '../src/index.ts';
import { loadServices } from '../relay/load.ts';
import { RELAY_LIMITS } from '../relay/limits.ts';
import { createRelayServer } from '../relay/server.ts';
import type { Upstream } from '../relay/upstream.ts';
import { sha256 } from './helpers.ts';
import { build, int, seq } from './token-builder.ts';
import { children, integerBytes, octets, parseDer } from '../src/lib/der.ts';

// Four rules of the relay that had no test of their own (found by mutation): the relay checks the nonce of the
// service's answer, it limits a body that comes in chunks, it takes only status 200 from a service, and the process
// takes the credentials out of its environment. The stubs answer with tokens that are correct in everything but the
// one thing under test, so only that rule can make the difference.

const SERVICES = loadServices();

/** A port that is free right now (opened and closed again). */
const freePort = (): Promise<number> =>
  new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address() as AddressInfo;
      s.close(() => resolve(port));
    });
  });
const SIGNER = build();
const NOW = Date.parse('2026-11-23T13:06:00Z');
const ROOT = new URL('../', import.meta.url);

const genTimeText = (ms: number) =>
  new Date(ms)
    .toISOString()
    .replace(/[-:T]/g, '')
    .replace(/\.\d+Z$/, 'Z');

/** A TimeStampResp for the imprint of `request`, with the nonce of the request or, when told, another one. */
function replyFor(request: Uint8Array, nonceBytes?: Uint8Array): Uint8Array {
  const parts = children(parseDer(request));
  const made = build({
    keys: SIGNER.keys,
    hash: octets(children(parts[1]!)[1]!),
    nonceBytes: nonceBytes ?? integerBytes(parts[2]!),
    genTime: genTimeText(NOW),
  });
  return seq(seq(int(0)), made.token);
}

interface Started {
  base: string;
  port: number;
  calls: number;
  stats: () => { stamped: number; refused: Record<string, number> };
  close: () => Promise<void>;
}

async function start(
  upstream: (body: Uint8Array) => ReturnType<Upstream>,
  batch?: { windowMs: number; max: number },
): Promise<Started> {
  const state = { calls: 0 };
  const { server, relay } = createRelayServer({
    services: SERVICES.map((s) => ({ ...s, anchorPems: [...s.anchorPems, SIGNER.caPem] })),
    origins: ['https://app.example'],
    allowPlainHttp: false,
    upstream: async (_t, body) => {
      state.calls += 1;
      return upstream(body);
    },
    random: (n) => new Uint8Array(randomBytes(n)),
    now: () => NOW,
    keys: 'off',
    ...(batch === undefined ? {} : { batch }),
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  return {
    base: `http://127.0.0.1:${port}`,
    port,
    get calls() {
      return state.calls;
    },
    stats: relay.stats,
    close: () =>
      new Promise((r) => {
        relay.close();
        server.closeAllConnections();
        server.close(() => r());
      }),
  };
}

const stampOnce = (h: Started, tag: string) =>
  fetch(`${h.base}/v1/stamp/freetsa`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hash: toBase64Url(sha256(tag)) }),
  });

const ok = (body: Uint8Array) => ({
  status: 200,
  contentType: 'application/timestamp-reply',
  body,
});

describe('the relay checks the nonce of the answer of a service', () => {
  const OTHER_NONCE = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
  let h: Started;
  afterEach(() => h.close());

  it('single operation: a valid token for the right hash but another nonce is refused (502 upstream-invalid, nonce-mismatch)', async () => {
    h = await start(async (body) => ok(replyFor(body, OTHER_NONCE)));
    const res = await stampOnce(h, 'n1');
    expect(res.status).toBe(502);
    expect(await res.json()).toEqual({ error: 'upstream-invalid', reason: 'nonce-mismatch' });
    expect(h.calls).toBe(1);
    expect(h.stats().stamped).toBe(0);
    expect(h.stats().refused['upstream-invalid']).toBe(1);
  });

  it('single operation, control: the same stub with the nonce of the request is accepted', async () => {
    h = await start(async (body) => ok(replyFor(body)));
    expect((await stampOnce(h, 'n2')).status).toBe(200);
    expect(h.stats().stamped).toBe(1);
  });

  it('collecting operation: the token of the window is refused as well, for every waiting request', async () => {
    h = await start(async (body) => ok(replyFor(body, OTHER_NONCE)), { windowMs: 120, max: 100 });
    const answers = await Promise.all([stampOnce(h, 'b1'), stampOnce(h, 'b2')]);
    expect(answers.map((a) => a.status)).toEqual([502, 502]);
    for (const a of answers) {
      expect(await a.json()).toEqual({ error: 'upstream-invalid', reason: 'nonce-mismatch' });
    }
    expect(h.calls).toBe(1);
    expect(h.stats().stamped).toBe(0);
  });

  it('collecting operation, control: the right nonce gives 200 for the window', async () => {
    h = await start(async (body) => ok(replyFor(body)), { windowMs: 120, max: 100 });
    const answers = await Promise.all([stampOnce(h, 'b3'), stampOnce(h, 'b4')]);
    expect(answers.map((a) => a.status)).toEqual([200, 200]);
  });
});

describe('the relay accepts only status 200 from a service', () => {
  let h: Started;
  afterEach(() => h.close());

  for (const status of [202, 204, 500]) {
    it(`status ${status} with a valid token as body is 502 upstream-refused`, async () => {
      h = await start(async (body) => ({ ...ok(replyFor(body)), status }));
      const res = await stampOnce(h, `s${status}`);
      expect(res.status).toBe(502);
      expect(await res.json()).toEqual({ error: 'upstream-refused' });
      expect(h.stats().stamped).toBe(0);
      expect(h.stats().refused['upstream-refused']).toBe(1);
    });
  }

  it('status 202 in collecting operation is refused for the whole window', async () => {
    h = await start(async (body) => ({ ...ok(replyFor(body)), status: 202 }), {
      windowMs: 120,
      max: 100,
    });
    const answers = await Promise.all([stampOnce(h, 'w1'), stampOnce(h, 'w2')]);
    expect(answers.map((a) => a.status)).toEqual([502, 502]);
    expect(h.stats().stamped).toBe(0);
  });
});

describe('the limit of the body holds for a body that comes in chunks (no Content-Length)', () => {
  let h: Started;
  beforeEach(async () => {
    h = await start(async (body) => ok(replyFor(body)));
  });
  afterEach(() => h.close());

  /** A POST with `Transfer-Encoding: chunked`; each element of `chunks` is one chunk. Resolves with the raw answer. */
  function chunked(chunks: Buffer[]): Promise<string> {
    return new Promise((resolve) => {
      const s = net.connect(h.port, '127.0.0.1', () => {
        s.write(
          'POST /v1/stamp/freetsa HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\n' +
            'Transfer-Encoding: chunked\r\n\r\n',
        );
        for (const c of chunks) {
          s.write(`${c.length.toString(16)}\r\n`);
          s.write(c);
          s.write('\r\n');
        }
        s.write('0\r\n\r\n');
      });
      let got = '';
      s.on('data', (c) => (got += c.toString('utf8')));
      s.on('error', () => undefined);
      s.on('close', () => (clearTimeout(timer), resolve(got)));
      const timer = setTimeout(() => (s.destroy(), resolve(got)), 3000);
    });
  }

  it('answers 413 for chunks that together pass the limit, and never calls the service', async () => {
    const half = Buffer.alloc(RELAY_LIMITS.bodyBytes / 2 + 1, 0x61);
    const answer = await chunked([half, half]);
    expect(answer.startsWith('HTTP/1.1 413')).toBe(true);
    expect(answer).toContain('too-large');
    expect(h.calls).toBe(0);
  });

  it('answers 413 for one chunk of the limit plus one byte', async () => {
    const answer = await chunked([Buffer.alloc(RELAY_LIMITS.bodyBytes + 1, 0x61)]);
    expect(answer.startsWith('HTTP/1.1 413')).toBe(true);
    expect(h.calls).toBe(0);
  });

  it('control: the same way of sending with a good 32-byte hash in two chunks gives 200', async () => {
    const hash = Buffer.from(sha256('chunked'));
    const answer = await chunked([hash.subarray(0, 10), hash.subarray(10)]);
    expect(answer.startsWith('HTTP/1.1 200')).toBe(true);
    expect(h.calls).toBe(1);
  });
});

describe('the process takes the credentials of the relay out of its environment', () => {
  const SECRET = 'probe-user:probe-secret-value-4711';
  let dir = '';
  beforeAll(() => {
    // A copy of the code with a service list of its own: one https service that takes credentials of the relay (the
    // shipped services take none). `relay/load.ts` reads the list and the anchors relative to its own place.
    dir = mkdtempSync(join(tmpdir(), 'zs-envprobe-'));
    for (const d of ['relay', 'src', 'anchors']) {
      cpSync(new URL(d, ROOT), join(dir, d), { recursive: true });
    }
    cpSync(new URL('package.json', ROOT), join(dir, 'package.json'));
    const list = {
      version: 1,
      services: [
        {
          id: 'probe-paid',
          name: 'Probe',
          url: 'https://probe.invalid/tsr',
          hash: 'sha256',
          anchors: ['anchors/freetsa-root.pem'],
          qualified: false,
          minIntervalMs: 5000,
          intendedUse: 'test',
          terms: 'test',
          auth: { kind: 'basic', source: 'relay' },
        },
      ],
    };
    writeFileSync(join(dir, 'services.json'), JSON.stringify(list));
    // Runs before main.ts: when the server starts to listen (after the credentials were taken out), it reports which
    // variables of the credential kind are still in the environment and whether the secret is anywhere in it.
    writeFileSync(
      join(dir, 'probe.mjs'),
      `import net from 'node:net';
const listen = net.Server.prototype.listen;
net.Server.prototype.listen = function (...args) {
  const names = Object.keys(process.env).filter((k) => k.startsWith('RELAY_UPSTREAM_AUTH_'));
  const leaked = Object.values(process.env).some((v) => String(v).includes(${JSON.stringify(SECRET.split(':')[1])}));
  console.error('ENVPROBE ' + JSON.stringify({ names, leaked }));
  return listen.apply(this, args);
};
`,
    );
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('after the start the variable and its value are gone from process.env, and the relay did read it', async () => {
    const child = spawn(
      process.execPath,
      ['--import', pathToFileURL(join(dir, 'probe.mjs')).href, join(dir, 'relay', 'main.ts')],
      {
        cwd: dir,
        env: {
          PATH: process.env.PATH ?? '',
          PORT: String(await freePort()),
          RELAY_SERVICES: 'probe-paid',
          RELAY_AUTH: 'off',
          RELAY_UPSTREAM_AUTH_PROBE_PAID: SECRET,
        },
      },
    );
    let out = '';
    let err = '';
    child.stdout.on('data', (c: Buffer) => (out += c.toString('utf8')));
    child.stderr.on('data', (c: Buffer) => (err += c.toString('utf8')));
    const exited = new Promise((r) => child.on('exit', r));
    try {
      await vi.waitFor(() => expect(out).toContain('"event":"start"'), { timeout: 15_000 });
      const line = err.split('\n').find((l) => l.startsWith('ENVPROBE '));
      expect(line, `stderr: ${err}`).toBeDefined();
      expect(JSON.parse(line!.slice('ENVPROBE '.length))).toEqual({ names: [], leaked: false });
      // the relay did take the credentials (otherwise the start would have ended: the variable is mandatory)
      expect(err).not.toContain('config-error');
      expect(out + err).not.toContain('probe-secret-value-4711');
    } finally {
      child.kill('SIGTERM');
      await exited;
    }
  }, 30_000);

  it('control: without the variable the same start ends with a config-error that names the variable', async () => {
    const child = spawn(
      process.execPath,
      ['--import', pathToFileURL(join(dir, 'probe.mjs')).href, join(dir, 'relay', 'main.ts')],
      {
        cwd: dir,
        env: {
          PATH: process.env.PATH ?? '',
          PORT: String(await freePort()),
          RELAY_SERVICES: 'probe-paid',
          RELAY_AUTH: 'off',
        },
      },
    );
    let err = '';
    child.stderr.on('data', (c: Buffer) => (err += c.toString('utf8')));
    const code = await new Promise((r) => child.on('exit', r));
    expect(code).toBe(1);
    expect(err).toContain('RELAY_UPSTREAM_AUTH_PROBE_PAID');
  }, 30_000);
});
