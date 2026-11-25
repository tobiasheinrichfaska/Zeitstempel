// Makes an access key pair for the relay (docs/relay.md, "Zugangsschlüssel"). Prints to the terminal only;
// it writes no file. Usage:
//   node scripts/make-key.ts <key-id> [--solo] [--not-after <unix-seconds>] [--services a,b] [--per-minute N]
//   --solo: the entry carries "solo": true (key type 2: may ask for a direct stamp; only the owner hands these out)
//   --not-after: "notAfter" (Unix seconds): from then on the relay refuses the key like a revoked one (rotation)
//   --services: "services" (1 to 16 service ids): the key may stamp with these services only
//   --per-minute: "perMinute" (1 to 20): the key's own limit per minute instead of the general one
//   line 1: the PRIVATE key (ECDSA P-256, PKCS#8, base64url): for the app that owns it; keep it secret,
//           never put it in a repo or a file next to the relay's configuration
//   line 2: the entry for the relay's key file (id, public key, uncompressed point, base64url, and the fields
//           above): not a secret, but only the operator may write that file. The fields need "version": 3 in the file
//           (the owner puts the entry into the file; this script never writes it).
import { toBase64Url } from '../src/index.ts';
import { RELAY_LIMITS } from '../relay/limits.ts';
import { MAX_KEY_SERVICES, RESTART_AFTER_MAX, RESTART_AFTER_MIN } from '../relay/keys.ts';

const USAGE =
  'usage: node scripts/make-key.ts <key-id> [--solo] [--not-after <unix>] [--services a,b] [--per-minute N]   (key id: [a-z][a-z0-9-]{0,31}; --solo: key type 2)';
const refuse = (): never => {
  console.error(USAGE);
  process.exit(2);
};
const WHOLE = /^[0-9]{1,12}$/;
const SERVICE_ID = /^[a-z][a-z0-9-]{0,31}$/;

const args = process.argv.slice(2);
let solo = false;
let notAfter: number | undefined;
let services: string[] | undefined;
let perMinute: number | undefined;
const positional: string[] = [];
for (let i = 0; i < args.length; i++) {
  const a = args[i]!;
  if (a === '--solo') {
    solo = true;
  } else if (a === '--not-after' || a === '--services' || a === '--per-minute') {
    const value = args[++i];
    if (value === undefined) refuse();
    if (a === '--not-after') {
      if (notAfter !== undefined || !WHOLE.test(value!)) refuse();
      notAfter = Number(value);
      if (notAfter < RESTART_AFTER_MIN || notAfter > RESTART_AFTER_MAX) refuse();
    } else if (a === '--per-minute') {
      if (perMinute !== undefined || !WHOLE.test(value!)) refuse();
      perMinute = Number(value);
      if (perMinute < 1 || perMinute > RELAY_LIMITS.perMinutePerKey) refuse();
    } else {
      if (services !== undefined) refuse();
      services = value!.split(',');
      if (
        services.length > MAX_KEY_SERVICES ||
        services.some((s) => !SERVICE_ID.test(s)) ||
        new Set(services).size !== services.length
      ) {
        refuse();
      }
    }
  } else if (a.startsWith('--')) {
    refuse();
  } else {
    positional.push(a);
  }
}
const id = positional.length === 1 ? positional[0]! : '';
if (!/^[a-z][a-z0-9-]{0,31}$/.test(id)) refuse();
const version3 = notAfter !== undefined || services !== undefined || perMinute !== undefined;
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
  'Zeile 1 ist der PRIVATE Schlüssel und gehört nur der App; Zeile 2 ist der Eintrag für die Schlüsseldatei des Relays (öffentlicher Schlüssel, kein Geheimnis).' +
    (version3
      ? ' Die Felder notAfter, services und perMinute brauchen in der Datei "version": 3.'
      : ''),
);
console.log(toBase64Url(privateKey));
console.log(
  JSON.stringify({
    id,
    publicKey: toBase64Url(publicKey),
    ...(solo ? { solo: true } : {}),
    ...(notAfter === undefined ? {} : { notAfter }),
    ...(services === undefined ? {} : { services }),
    ...(perMinute === undefined ? {} : { perMinute }),
  }),
);
