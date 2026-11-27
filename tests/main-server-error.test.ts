import { spawn } from 'node:child_process';
import { connect, createServer, type AddressInfo } from 'node:net';

// `relay/main.ts`, the `listening` flag: an error of the server BEFORE it listens ends the start (config-error, exit 1,
// covered in `main-wiring.test.ts`); an error AFTER it listens is logged by its code (`server-error`) and the relay keeps
// running (no exit, still listening, SIGTERM still ends it with 0). The error is injected by a preload that emits
// `EMFILE` on the server 300 ms after it listens.

const ROOT = new URL('..', import.meta.url);
const PRELOAD = new URL('./server-error-preload.mjs', import.meta.url).href;

async function freePort(): Promise<number> {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  const { port } = s.address() as AddressInfo;
  await new Promise<void>((r) => s.close(() => r()));
  return port;
}
const canConnect = (port: number) =>
  new Promise<boolean>((resolve) => {
    const c = connect(port, '127.0.0.1');
    c.on('connect', () => (c.destroy(), resolve(true)));
    c.on('error', () => resolve(false));
  });

describe('an error of the running server', () => {
  it.skipIf(process.platform === 'win32')(
    'after listening is logged by its code and the relay keeps running; it does not end like a start error',
    async () => {
      const port = await freePort();
      const child = spawn(process.execPath, ['--import', PRELOAD, 'relay/main.ts'], {
        cwd: ROOT,
        env: {
          PATH: process.env.PATH ?? '',
          PORT: String(port),
          RELAY_SERVICES: 'freetsa',
          RELAY_AUTH: 'off',
        },
      });
      let out = '';
      let err = '';
      let exited: { code: number | null } | null = null;
      child.stdout.on('data', (c: Buffer) => (out += c.toString('utf8')));
      child.stderr.on('data', (c: Buffer) => (err += c.toString('utf8')));
      const done = new Promise<{ code: number | null }>((r) =>
        child.on('exit', (code) => r((exited = { code }))),
      );
      try {
        const end = Date.now() + 10_000;
        while (!err.includes('"event":"server-error"') && exited === null && Date.now() < end) {
          await new Promise((r) => setTimeout(r, 50));
        }
        expect(out).toContain('"event":"start"');
        const lines = err.trim().split('\n');
        const line = lines.find((l) => l.includes('"event":"server-error"'));
        expect(line).toBeDefined();
        expect(JSON.parse(line!)).toEqual({ event: 'server-error', code: 'EMFILE' });
        expect(err).not.toContain('config-error'); // not the message of a start error
        expect(err).not.toMatch(/\n\s+at |node:events/); // no stack trace
        await new Promise((r) => setTimeout(r, 700)); // a process that was about to end has ended by now
        expect(exited).toBeNull();
        expect(await canConnect(port)).toBe(true); // still listening
        child.kill('SIGTERM');
        expect((await done).code).toBe(0);
      } finally {
        child.kill('SIGKILL');
      }
    },
    25_000,
  );
});
