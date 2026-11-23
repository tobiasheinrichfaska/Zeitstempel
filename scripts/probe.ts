// Probe: sends ONE hash of test data through the relay to a real service and checks the answer again.
//   npm run probe -- --service freetsa            runs the relay in this process (real service behind it)
//   npm run probe -- --service freetsa --relay https://relay.example   probes a running relay instead
// A running relay wants signed requests: set RELAY_KEY (the key, base64url) and RELAY_KEY_ID in the
// environment (never on the command line). The in-process relay makes a random key for the run.
// Only the SHA-256 of a short test text leaves this computer; no personal data.
import { createHash, randomBytes } from 'node:crypto';
import type { RelayKey } from '../relay/keys.ts';
import type { AddressInfo } from 'node:net';
import {
  deriveVerifier,
  fromBase64Url,
  signRelayRequest,
  toBase64Url,
  verifyTimestampToken,
} from '../src/index.ts';
import { loadServices } from '../relay/load.ts';
import { createRelayServer } from '../relay/server.ts';
import { networkUpstream } from '../relay/upstream.ts';

const args = process.argv.slice(2);
const option = (name: string): string | undefined => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
};
const id = option('service');
if (!id) {
  console.error('usage: npm run probe -- --service <id> [--relay <url>]');
  process.exit(2);
}
const service = loadServices().find((s) => s.id === id);
if (!service) {
  console.error(`unknown service "${id}"`);
  process.exit(2);
}

const text = `probe ${new Date().toISOString()}`;
const hash = new Uint8Array(createHash('sha256').update(text).digest());

let base = option('relay');
let close = async () => {};
let key: Uint8Array | null = null;
let keyId = process.env.RELAY_KEY_ID ?? '';
if (process.env.RELAY_KEY) {
  key = fromBase64Url(process.env.RELAY_KEY);
  if (!key) {
    console.error('RELAY_KEY is not base64url');
    process.exit(2);
  }
}
if (!base) {
  key = new Uint8Array(randomBytes(32));
  keyId = 'probe';
  const verifier = await deriveVerifier(key);
  if (!verifier.ok) throw new Error(verifier.reason);
  const keys: RelayKey[] = [{ id: keyId, verifier: verifier.value }];
  const { server } = createRelayServer({
    keys,
    services: [service],
    origins: [],
    allowPlainHttp: true, // a probe may use http-only services; the relay default stays off
    upstream: networkUpstream,
    random: (n) => new Uint8Array(randomBytes(n)),
    now: () => Date.now(),
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  close = () => new Promise((r) => (server.closeAllConnections(), server.close(() => r())));
}

const payload = JSON.stringify({ hash: toBase64Url(hash) });
const headers: Record<string, string> = { 'Content-Type': 'application/json' };
if (key) {
  const signed = await signRelayRequest({
    key,
    keyId,
    method: 'POST',
    path: `/v1/stamp/${id}`,
    body: new TextEncoder().encode(payload),
    nowMs: Date.now(),
  });
  if (!signed.ok) {
    console.error(`cannot sign: ${signed.reason}`);
    process.exit(2);
  }
  headers['X-Zeitstempel-Auth'] = signed.value;
}
const started = Date.now();
const res = await fetch(`${base}/v1/stamp/${id}`, { method: 'POST', headers, body: payload });
const ms = Date.now() - started;
const body = (await res.json()) as {
  token?: string;
  genTime?: string;
  error?: string;
  reason?: string;
};
await close();
if (res.status !== 200 || !body.token) {
  console.log(`FAILED: HTTP ${res.status} ${body.error ?? ''} ${body.reason ?? ''} (${ms} ms)`);
  process.exit(1);
}
const again = await verifyTimestampToken(fromBase64Url(body.token)!, hash, service.anchorPems);
console.log(
  `${id}: HTTP 200 in ${ms} ms, time ${body.genTime}, own verification of the returned token: ${again.ok ? 'OK' : `FAILED (${again.reason})`}`,
);
process.exit(again.ok ? 0 : 1);
