import {
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  sign,
  type KeyObject,
} from 'node:crypto';

// Test keys are made per run: no key material is ever written down in the repo.
export interface TestKey {
  id: string;
  /** PKCS#8 (DER), as the library takes it. */
  privateKey: Uint8Array;
  /** Uncompressed point, 65 bytes, as the relay's key file names it. */
  publicKey: Uint8Array;
  object: KeyObject;
}

export function makeTestKey(id: string): TestKey {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const publicKey = new Uint8Array(
    Buffer.concat([
      Buffer.from([4]),
      Buffer.from(jwk.x!, 'base64url'),
      Buffer.from(jwk.y!, 'base64url'),
    ]),
  );
  const privateKey = new Uint8Array(pair.privateKey.export({ format: 'der', type: 'pkcs8' }));
  return {
    id,
    privateKey,
    publicKey,
    object: createPrivateKey({ key: Buffer.from(privateKey), format: 'der', type: 'pkcs8' }),
  };
}

/** The signed message of the specification, written out independently of the library. */
export function authMessage(method: string, path: string, ts: number, body: Uint8Array): string {
  return `zeitstempel-auth-v2\n${method}\n${path}\n${ts}\n${createHash('sha256').update(body).digest('hex')}`;
}

/** The 64 bytes (r || s) node:crypto makes for the message (IEEE P1363, as WebCrypto does). */
export function nodeSignature(key: TestKey, message: string): Buffer {
  return sign('sha256', Buffer.from(message), { key: key.object, dsaEncoding: 'ieee-p1363' });
}

/** The header value, signed with node:crypto: independent of the library. */
export function nodeAuthHeader(
  key: TestKey,
  kid: string,
  method: string,
  path: string,
  ts: number,
  body: Uint8Array,
): string {
  const sig = nodeSignature(key, authMessage(method, path, ts, body));
  return `v2.${kid}.${ts}.${sig.toString('base64url')}`;
}

const N = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'); // order of P-256

/** (r, s) -> (r, n - s): another valid signature of the same message. */
export function twinSignature(sig: Uint8Array): Buffer {
  const s = BigInt('0x' + Buffer.from(sig.subarray(32)).toString('hex'));
  const twin = (N - s).toString(16).padStart(64, '0');
  return Buffer.concat([Buffer.from(sig.subarray(0, 32)), Buffer.from(twin, 'hex')]);
}
