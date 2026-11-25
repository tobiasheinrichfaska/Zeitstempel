// Run by tests/copy.test.ts in a child process with a small heap: every case here would exhaust the memory
// (or never end) if an input were copied through its iterator. Prints one JSON line.
import {
  buildTimestampRequest,
  readTimestampResponse,
  verifyTimestampToken,
} from '../src/index.ts';
import { FREETSA_NONCE, fixture, fixtureText, sha256 } from './helpers.ts';

const endless = (target: object): void => {
  Object.defineProperty(target, Symbol.iterator, {
    value: function* () {
      for (;;) yield 1;
    },
  });
};

const ROOT = fixtureText('cacert.pem');
const response = readTimestampResponse(fixture('freetsa.tsr'));
if (!response.ok) throw new Error('fixture unreadable');
const token = response.value.token;
const hash = sha256('probe');
const now = new Date('2026-11-23T14:00:00Z');
const show = (r: { ok: boolean; reason?: string }) => (r.ok ? 'ok' : r.reason);

const out: Record<string, unknown> = {};

const h = new Uint8Array(32).fill(7);
endless(h);
const n = Uint8Array.of(1, 2, 3);
endless(n);
out.request = show(buildTimestampRequest(h, n));

const hash2 = new Uint8Array(hash);
endless(hash2);
const nonce = new Uint8Array(FREETSA_NONCE);
endless(nonce);
const token2 = new Uint8Array(token);
endless(token2);
out.verifyInputs = show(
  await verifyTimestampToken(token2, hash2, [ROOT], { expectedNonce: nonce, now }),
);

const trust = [ROOT];
endless(trust);
out.trustIterator = show(
  await verifyTimestampToken(token, hash, trust, { expectedNonce: FREETSA_NONCE, now }),
);

const huge: string[] = [];
huge.length = 2 ** 32 - 1; // sparse: costs nothing unless it is walked
out.trustHugeLength = show(await verifyTimestampToken(token, hash, huge));

const tooMany = new Array<string>(65).fill(ROOT);
out.trustTooMany = show(await verifyTimestampToken(token, hash, tooMany));

console.log(JSON.stringify(out));
