// Makes a permission key for the relay (docs/relay.md, "Zugangsschlüssel"). Prints to the terminal only;
// it writes no file. Usage: node scripts/make-key.ts <key-id>
//   line 1: the key K (base64url): for the app that owns it; keep it secret, never put it in a repo
//   line 2: the entry for the relay's key file (id and verifier V = SHA-256(K)); V alone is no key
import { randomBytes } from 'node:crypto';
import { deriveVerifier, toBase64Url } from '../src/index.ts';

const id = process.argv[2] ?? '';
if (!/^[a-z][a-z0-9-]{0,31}$/.test(id)) {
  console.error('usage: node scripts/make-key.ts <key-id>   (key id: [a-z][a-z0-9-]{0,31})');
  process.exit(2);
}
const key = new Uint8Array(randomBytes(32));
const verifier = await deriveVerifier(key);
if (!verifier.ok) {
  console.error(verifier.reason);
  process.exit(1);
}
console.log(toBase64Url(key));
console.log(JSON.stringify({ id, verifier: toBase64Url(verifier.value) }));
