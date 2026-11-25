// Makes an access key pair for the relay (docs/relay.md, "Zugangsschlüssel"). Prints to the terminal only;
// it writes no file. Usage: node scripts/make-key.ts <key-id> [--solo]
//   --solo: the entry carries "solo": true (key type 2: may ask for a direct stamp; only the owner hands these out)
//   line 1: the PRIVATE key (ECDSA P-256, PKCS#8, base64url): for the app that owns it; keep it secret,
//           never put it in a repo or a file next to the relay's configuration
//   line 2: the entry for the relay's key file (id and public key, uncompressed point, base64url): not a
//           secret, but only the operator may write that file
import { toBase64Url } from '../src/index.ts';

const args = process.argv.slice(2);
const solo = args.includes('--solo');
const rest = args.filter((a) => a !== '--solo');
const id = rest.length === 1 ? rest[0]! : '';
if (!/^[a-z][a-z0-9-]{0,31}$/.test(id)) {
  console.error(
    'usage: node scripts/make-key.ts <key-id> [--solo]   (key id: [a-z][a-z0-9-]{0,31}; --solo: key type 2)',
  );
  process.exit(2);
}
const pair = await globalThis.crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  true,
  ['sign', 'verify'],
);
const privateKey = new Uint8Array(
  await globalThis.crypto.subtle.exportKey('pkcs8', pair.privateKey),
);
const publicKey = new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', pair.publicKey));
console.error(
  'Zeile 1 ist der PRIVATE Schlüssel und gehört nur der App; Zeile 2 ist der Eintrag für die Schlüsseldatei des Relays (öffentlicher Schlüssel, kein Geheimnis).',
);
console.log(toBase64Url(privateKey));
console.log(
  JSON.stringify({ id, publicKey: toBase64Url(publicKey), ...(solo ? { solo: true } : {}) }),
);
