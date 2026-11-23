import {
  readTimestampResponse,
  verifyTimestampToken,
  type Reason,
  type VerifyOptions,
} from '../src/lib/index.ts';
import { equalBytes, fromBase64 } from '../src/lib/index.ts';
import { FREETSA_NONCE, fixture, fixtureText, sha256 } from './helpers.ts';

const ROOT = fixtureText('cacert.pem');
const response = readTimestampResponse(fixture('freetsa.tsr'));
if (!response.ok) throw new Error('fixture unreadable');
const TOKEN = response.value.token;
const HASH = sha256('probe');
const OPTIONS: VerifyOptions = {
  expectedNonce: FREETSA_NONCE,
  now: new Date('2026-11-23T14:00:00Z'),
};

async function reasonOf(
  token: Uint8Array,
  hash = HASH,
  trust: readonly string[] = [ROOT],
  options: VerifyOptions = OPTIONS,
): Promise<Reason | 'ok'> {
  const r = await verifyTimestampToken(token, hash, trust, options);
  return r.ok ? 'ok' : r.reason;
}

describe('verifyTimestampToken with a real token', () => {
  it('accepts it and reports what the service attests', async () => {
    const r = await verifyTimestampToken(TOKEN, HASH, [ROOT], OPTIONS);
    expect(r).toMatchObject({
      ok: true,
      value: {
        genTime: '2026-11-23T13:05:56.000Z',
        policy: '1.2.3.4.1',
        serial: '0a71c442',
        chainLength: 2,
      },
    });
    if (r.ok) expect(r.value.signer).toContain('CN=www.freetsa.org');
  });
  it('does not need the nonce or the clock', async () => {
    expect(await reasonOf(TOKEN, HASH, [ROOT], {})).toBe('ok');
  });
});

describe('verifyTimestampToken refuses', () => {
  it('another hash', async () => {
    expect(await reasonOf(TOKEN, sha256('other'))).toBe('imprint-mismatch');
  });
  it('a hash of the wrong length', async () => {
    expect(await reasonOf(TOKEN, new Uint8Array(31))).toBe('bad-hash');
  });
  it('another nonce, and a missing nonce check only when none is expected', async () => {
    expect(await reasonOf(TOKEN, HASH, [ROOT], { expectedNonce: Uint8Array.of(9, 9) })).toBe(
      'nonce-mismatch',
    );
  });
  it('a time in the future', async () => {
    expect(await reasonOf(TOKEN, HASH, [ROOT], { now: new Date('2026-11-23T12:00:00Z') })).toBe(
      'time-in-future',
    );
    expect(
      await reasonOf(TOKEN, HASH, [ROOT], {
        now: new Date('2026-11-23T12:00:00Z'),
        maxSkewMs: 2 * 3600_000,
      }),
    ).toBe('ok');
  });
  it('a chain that does not end in the given anchor', async () => {
    expect(await reasonOf(TOKEN, HASH, [fixtureText('other-root.pem')])).toBe('untrusted-chain');
  });
  it('the signer certificate alone as anchor chain only when it is the anchor itself', async () => {
    // the TSA certificate as the anchor: the signer IS the anchor, which is allowed
    expect(await reasonOf(TOKEN, HASH, [fixtureText('tsa.crt')])).toBe('ok');
  });
  it('a certificate that is not valid at the stamped time', async () => {
    expect(await reasonOf(TOKEN, HASH, [ROOT], { at: new Date('2041-01-01T00:00:00Z') })).toBe(
      'certificate-not-valid-at-time',
    );
    expect(await reasonOf(TOKEN, HASH, [ROOT], { at: new Date('2026-02-01T00:00:00Z') })).toBe(
      'certificate-not-valid-at-time',
    );
  });
  it('bad trust input', async () => {
    expect(await reasonOf(TOKEN, HASH, ['not a pem'])).toBe('bad-pem');
    expect(await reasonOf(TOKEN, HASH, [])).toBe('untrusted-chain');
  });
  it('garbage instead of a token', async () => {
    expect(await reasonOf(new Uint8Array(0))).toBe('malformed');
    expect(await reasonOf(Uint8Array.of(0x30, 0x80, 0, 0))).toBe('indefinite-length');
    expect(await reasonOf(new Uint8Array(300_000))).toBe('too-large');
  });
});

describe('changed tokens', () => {
  // The token also carries a copy of the root certificate; the verifier takes the root from the
  // trust anchors, so bytes inside that copy do not matter. Every other changed byte must be refused.
  const rootDer = fromBase64(ROOT.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''))!;
  const at = (hay: Uint8Array, needle: Uint8Array): number => {
    for (let i = 0; i + needle.length <= hay.length; i += 1) {
      if (equalBytes(hay.subarray(i, i + needle.length), needle)) return i;
    }
    return -1;
  };
  const rootAt = at(TOKEN, rootDer);

  it('finds the unused root copy in the recorded token', () => {
    expect(rootAt).toBeGreaterThan(0);
  });
  it('never verifies a token with a changed byte outside the unused root copy', async () => {
    const accepted: number[] = [];
    for (let i = 0; i < TOKEN.length; i += 3) {
      const copy = Uint8Array.from(TOKEN);
      copy[i] = copy[i]! ^ 0x01;
      if ((await reasonOf(copy)) === 'ok') accepted.push(i);
    }
    const outside = accepted.filter((i) => i < rootAt || i >= rootAt + rootDer.length);
    expect(outside).toEqual([]);
  });
  it('refuses a truncated token at every sampled length', async () => {
    for (let n = 0; n < TOKEN.length; n += 97) {
      expect(await reasonOf(TOKEN.subarray(0, n))).not.toBe('ok');
    }
  });
});
