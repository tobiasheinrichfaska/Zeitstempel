// Writes a time stamp request for the SHA-256 of a text, with a fixed or random nonce.
// Usage: node scripts/make-request.ts <text> <out.tsq> [hexNonce]
import { createHash, randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { buildTimestampRequest } from '../src/lib/index.ts';

const [text, out, hexNonce] = process.argv.slice(2);
if (!text || !out) {
  console.error('usage: node scripts/make-request.ts <text> <out.tsq> [hexNonce]');
  process.exit(2);
}
const hash = new Uint8Array(createHash('sha256').update(text).digest());
const nonce = hexNonce
  ? Uint8Array.from(Buffer.from(hexNonce, 'hex'))
  : new Uint8Array(randomBytes(8));
const request = buildTimestampRequest(hash, nonce);
if (!request.ok) {
  console.error(`refused: ${request.reason}`);
  process.exit(1);
}
writeFileSync(out, request.value);
console.log(`request for sha256("${text}") written to ${out}`);
