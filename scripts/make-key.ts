// Makes a permission key for the relay (docs/relay.md, "Zugangsschlüssel"). Prints to the terminal only;
// it writes no file. Usage: node scripts/make-key.ts <key-id>
//   line 1: the key K (base64url): for the app that owns it; keep it secret, never put it in a repo
//   line 2: the entry for the relay's key file (id and V = SHA-256(K)). V is the HMAC key: whoever has the
//           key file can sign requests, so the file is as secret as K (mode 0600, never in a repo)
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
console.error(
  'K (Zeile 1) gehört nur der App; die Zeile 2 enthält V = HMAC-Schlüssel: die Schlüsseldatei ist ebenso geheim (Rechte 0600).',
);
console.log(toBase64Url(key));
console.log(JSON.stringify({ id, verifier: toBase64Url(verifier.value) }));
