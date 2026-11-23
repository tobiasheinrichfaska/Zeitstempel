import { readTimestampResponse, verifyTimestampToken } from '../src/lib/index.ts';
import { fixture, fixtureText, sha256 } from './helpers.ts';

// Browsers expose `crypto.subtle` only in secure contexts (https, localhost). On a page served over
// plain http it is missing; verification must then answer with a code, never throw.
describe('without WebCrypto (insecure page)', () => {
  afterEach(() => vi.unstubAllGlobals());
  it('answers unsupported-signature instead of throwing', async () => {
    const response = readTimestampResponse(fixture('freetsa.tsr'));
    if (!response.ok) throw new Error('unreadable');
    vi.stubGlobal('crypto', {});
    const v = await verifyTimestampToken(response.value.token, sha256('probe'), [
      fixtureText('cacert.pem'),
    ]);
    expect(v).toMatchObject({ ok: false, reason: 'unsupported-signature' });
  });
});
