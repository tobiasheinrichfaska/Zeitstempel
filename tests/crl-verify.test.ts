// `crls` in verifyTimestampToken: revoked, bad-crl, bad-options, and what stays as before.
import { verifyTimestampToken } from '../src/index.ts';
import { tlv } from '../src/lib/der.ts';
import { build, ext } from './token-builder.ts';
import { OID_CRL, buildCrl, type CrlEntry, type CrlOpts } from './crl-builder.ts';

// the builder's token: genTime 2026-01-01; root "CA" (serial 1), intermediate "INT" (serial 2), signer (serial 7)
const t = build({ intermediate: {}, crlSign: true });
const flat = build({ crlSign: true }); // signer directly below the root
const BEFORE = '20251210000000Z';
const AFTER = '20260301000000Z';

const rootCrl = (entries: CrlEntry[] = [], o: Partial<CrlOpts> = {}) =>
  buildCrl({ key: t.keys.ca, issuer: 'CA', entries, ...o });
const intCrl = (entries: CrlEntry[] = [], o: Partial<CrlOpts> = {}) =>
  buildCrl({ key: t.midKeys, issuer: 'INT', entries, ...o });

async function run(
  crls: unknown,
  tok: ReturnType<typeof build> = t,
  more: object = {},
): Promise<string> {
  const r = await verifyTimestampToken(tok.token, tok.imprint, [tok.caPem], {
    crls,
    ...more,
  } as never);
  return r.ok ? 'ok' : r.reason;
}

describe('crls: revoked', () => {
  it('no list, an empty list and lists without the serial change nothing', async () => {
    expect(await run(undefined)).toBe('ok');
    expect(await run([])).toBe('ok');
    expect(await run([rootCrl(), intCrl()])).toBe('ok');
    expect(await run([rootCrl([{ serial: 99, date: BEFORE }])])).toBe('ok');
  });
  it('the root revoked the intermediate before genTime', async () => {
    expect(await run([rootCrl([{ serial: 2, date: BEFORE }])])).toBe('revoked');
  });
  it('the intermediate revoked the signer before genTime', async () => {
    expect(await run([intCrl([{ serial: 7, date: BEFORE }])])).toBe('revoked');
  });
  it('the root revoked a signer that sits directly below it', async () => {
    const crl = buildCrl({ key: flat.keys.ca, entries: [{ serial: 7, date: BEFORE }] });
    expect(await run([crl], flat)).toBe('revoked');
    expect(await run([buildCrl({ key: flat.keys.ca })], flat)).toBe('ok');
  });
  it('a revocation at exactly genTime counts, one second later does not', async () => {
    expect(await run([intCrl([{ serial: 7, date: '20260101000000Z' }])])).toBe('revoked');
    expect(await run([intCrl([{ serial: 7, date: '20260101000001Z' }])])).toBe('ok');
  });
  it('a revocation after genTime leaves the token valid (the service is believed about the time)', async () => {
    expect(
      await run([intCrl([{ serial: 7, date: AFTER }], { nextUpdate: '20260401000000Z' })]),
    ).toBe('ok');
    expect(
      await run([
        rootCrl([{ serial: 2, date: AFTER, reason: 5 }], { nextUpdate: '20260401000000Z' }),
      ]),
    ).toBe('ok');
  });
  it('keyCompromise and cACompromise count whatever the date (the key could have been used before)', async () => {
    const next = { nextUpdate: '20260401000000Z' };
    expect(await run([intCrl([{ serial: 7, date: AFTER, reason: 1 }], next)])).toBe('revoked');
    expect(await run([rootCrl([{ serial: 2, date: AFTER, reason: 2 }], next)])).toBe('revoked');
    // other reasons do not
    for (const reason of [0, 3, 4, 5, 6, 9, 10]) {
      expect(
        await run([intCrl([{ serial: 7, date: AFTER, reason }], next)]),
        `reason ${reason}`,
      ).toBe('ok');
    }
  });
  it('an earlier invalidityDate moves the revocation back before genTime', async () => {
    const next = { nextUpdate: '20260401000000Z' };
    expect(
      await run([intCrl([{ serial: 7, date: AFTER, reason: 4, invalidity: BEFORE }], next)]),
    ).toBe('revoked');
    // a later invalidityDate does not move it forward
    expect(
      await run([intCrl([{ serial: 7, date: BEFORE, reason: 4, invalidity: AFTER }], next)]),
    ).toBe('revoked');
  });
  it('certificateHold counts like any other reason', async () => {
    expect(await run([intCrl([{ serial: 7, date: BEFORE, reason: 6 }])])).toBe('revoked');
  });
  it('a serial with the high bit set (a leading zero byte in the INTEGER) is found; a non-minimal one is unreadable', async () => {
    const high = build({ intermediate: {}, crlSign: true, serialRaw: Uint8Array.of(0, 0x90) });
    const crl = (serial: Uint8Array) =>
      buildCrl({ key: high.midKeys, issuer: 'INT', entries: [{ serial, date: BEFORE }] });
    expect(await run([crl(Uint8Array.of(0, 0x90))], high)).toBe('revoked');
    expect(await run([crl(Uint8Array.of(0, 0x91))], high)).toBe('ok');
    expect(await run([crl(Uint8Array.of(0, 7))], high)).toBe('bad-crl');
  });
  it('one list among several is enough; the other entries of the same list are irrelevant', async () => {
    const entries = [
      { serial: 3, date: BEFORE },
      { serial: 7, date: BEFORE },
      { serial: 8, date: BEFORE },
    ];
    expect(await run([rootCrl(), intCrl(entries)])).toBe('revoked');
  });
  it('a revoked twin of the intermediate does not hide a good one (and both revoked do)', async () => {
    const twin = build({ intermediate: {}, twins: [{}], crlSign: true, keys: t.keys });
    // the twin has the serial 20 and the same key and name as the intermediate (serial 2)
    const crl = (serials: number[]) =>
      buildCrl({
        key: twin.keys.ca,
        issuer: 'CA',
        entries: serials.map((serial) => ({ serial, date: BEFORE })),
      });
    expect(await run([crl([2])], twin)).toBe('ok');
    expect(await run([crl([20])], twin)).toBe('ok');
    expect(await run([crl([2, 20])], twin)).toBe('revoked');
  });
  it('the trust anchor itself is never judged (its own serial in a list changes nothing)', async () => {
    expect(await run([rootCrl([{ serial: 1, date: BEFORE, reason: 1 }])])).toBe('ok');
  });
});

describe('crls: bad-crl, a given list is never skipped silently', () => {
  it('expired, not yet valid', async () => {
    expect(await run([rootCrl([], { nextUpdate: '20251231235959Z' })])).toBe('bad-crl');
    expect(
      await run([rootCrl([], { thisUpdate: '20260101000001Z', nextUpdate: '20260301000000Z' })]),
    ).toBe('bad-crl');
    // inclusive at both ends, like certificates
    expect(await run([rootCrl([], { thisUpdate: '20260101000000Z' })])).toBe('ok');
    expect(await run([rootCrl([], { nextUpdate: '20260101000000Z' })])).toBe('ok');
  });
  it('is judged at `at`, else at `now`, else at genTime', async () => {
    const crl = rootCrl([], { thisUpdate: '20260201000000Z', nextUpdate: '20260301000000Z' });
    expect(await run([crl])).toBe('bad-crl'); // genTime is before thisUpdate
    expect(
      await run([crl], t, { now: new Date('2026-02-15T00:00:00Z'), maxSkewMs: Infinity }),
    ).toBe('ok');
    expect(
      await run([crl], t, { now: new Date('2026-04-15T00:00:00Z'), maxSkewMs: Infinity }),
    ).toBe('bad-crl');
    expect(await run([crl], t, { at: new Date('2026-02-15T00:00:00Z') })).toBe('ok');
    // at wins over now
    expect(
      await run([crl], t, {
        at: new Date('2026-02-15T00:00:00Z'),
        now: new Date('2026-04-15T00:00:00Z'),
        maxSkewMs: Infinity,
      }),
    ).toBe('ok');
  });
  it('a list issued after genTime still reports an earlier revocation (the normal case, later)', async () => {
    const crl = intCrl([{ serial: 7, date: BEFORE }], {
      thisUpdate: '20260201000000Z',
      nextUpdate: '20260301000000Z',
    });
    expect(await run([crl], t, { at: new Date('2026-02-15T00:00:00Z') })).toBe('revoked');
  });
  it('wrong signature, signed by a stranger, signature of another list', async () => {
    const stranger = build();
    expect(
      await run([rootCrl([], { mangleSig: (s) => s.map((b, i) => (i === 10 ? b ^ 1 : b)) })]),
    ).toBe('bad-crl');
    expect(await run([buildCrl({ key: stranger.keys.ca, issuer: 'CA' })])).toBe('bad-crl');
    expect(await run([buildCrl({ key: stranger.keys.ca, issuer: 'INT' })])).toBe('bad-crl');
    // a list that revokes something, signed wrongly, never revokes
    expect(
      await run([
        buildCrl({ key: stranger.keys.ca, issuer: 'INT', entries: [{ serial: 7, date: BEFORE }] }),
      ]),
    ).toBe('bad-crl');
  });
  it('an issuer that is no member of the chain', async () => {
    expect(await run([rootCrl([], { issuer: 'Elsewhere' })])).toBe('bad-crl');
  });
  it('one unusable list among good ones', async () => {
    expect(await run([rootCrl(), intCrl(), rootCrl([], { issuer: 'Elsewhere' })])).toBe('bad-crl');
  });
  it('the signer of the list must be a CA that may sign lists', async () => {
    const noCrlSign = build({ intermediate: {} }); // keyCertSign only: no cRLSign
    const crl = buildCrl({ key: noCrlSign.midKeys, issuer: 'INT' });
    expect(await run([crl], noCrlSign)).toBe('bad-crl');
    const signerAsIssuer = buildCrl({ key: t.keys.tsa, issuer: 'TSA' }); // the signer is no CA
    expect(await run([signerAsIssuer])).toBe('bad-crl');
  });
  it('a list while the signer is its own anchor has no chain member that could have signed it', async () => {
    const own = build({ selfSignedSigner: true });
    const r = await verifyTimestampToken(own.token, own.imprint, [own.tsaPem], {
      crls: [buildCrl({ key: own.keys.tsa, issuer: 'TSA' })],
    });
    expect(r).toMatchObject({ ok: false, reason: 'bad-crl' });
  });
  it('unreadable or unsupported lists', async () => {
    expect(await run([new Uint8Array()])).toBe('bad-crl');
    expect(await run([Uint8Array.of(1, 2, 3)])).toBe('bad-crl');
    expect(
      await run([rootCrl([], { exts: [ext(OID_CRL.delta, true, tlv(2, Uint8Array.of(1)))] })]),
    ).toBe('bad-crl');
    expect(await run([rootCrl([], { exts: [ext('1.2.3.4', true, tlv(5))] })])).toBe('bad-crl');
  });
  it('the order of the other checks: a token that fails earlier keeps its own reason', async () => {
    const r = await verifyTimestampToken(t.token, new Uint8Array(32), [t.caPem], {
      crls: [Uint8Array.of(1)],
    });
    expect(r).toMatchObject({ ok: false, reason: 'imprint-mismatch' });
  });
  it('the result of a good run is the same as without lists', async () => {
    const a = await verifyTimestampToken(t.token, t.imprint, [t.caPem], {});
    const b = await verifyTimestampToken(t.token, t.imprint, [t.caPem], {
      crls: [rootCrl(), intCrl()],
    });
    expect(b).toEqual(a);
    expect(b.ok && b.value.chainLength).toBe(3);
  });
});

describe('crls: bad-options', () => {
  it('wrong types and limits', async () => {
    const good = rootCrl();
    for (const v of [null, 'x', 5, {}, new Set([good]), good, new Uint8Array(3)]) {
      expect(await run(v), String(v)).toBe('bad-options');
    }
    expect(await run([null])).toBe('bad-options');
    expect(await run(['abc'])).toBe('bad-options');
    expect(await run([[1, 2, 3]])).toBe('bad-options');
    expect(await run([new Uint16Array(4)])).toBe('bad-options');
    expect(await run(Array.from({ length: 17 }, () => good))).toBe('bad-options');
    expect(await run([new Uint8Array(262145)])).toBe('bad-options');
    expect(await run(Array.from({ length: 16 }, () => good))).toBe('ok');
  });
  it('a hostile array, a hostile element and a throwing getter give a code, never a throw', async () => {
    const hostile = new Proxy([rootCrl()], {
      get() {
        throw new Error('trap');
      },
      getPrototypeOf() {
        throw new Error('trap');
      },
    });
    expect(await run(hostile)).toBe('bad-options');
    const el = new Proxy(rootCrl(), {
      get() {
        throw new Error('trap');
      },
    });
    expect(await run([el])).toBe('bad-options');
    const options = {};
    Object.defineProperty(options, 'crls', {
      enumerable: true,
      get() {
        throw new Error('getter');
      },
    });
    const r = await verifyTimestampToken(t.token, t.imprint, [t.caPem], options);
    expect(r).toMatchObject({ ok: false, reason: 'bad-options' });
  });
  it('the lists are copied: changing the buffer meanwhile changes nothing', async () => {
    const crl = intCrl([{ serial: 7, date: BEFORE }]);
    const list = [crl];
    const pending = run(list);
    crl.fill(0);
    expect(await pending).toBe('revoked');
  });
  it('a list from another realm is refused like every Uint8Array of another realm in the options', async () => {
    const { runInNewContext } = await import('node:vm');
    const foreign = runInNewContext('new Uint8Array(3)') as Uint8Array;
    expect(await run([foreign])).toBe('bad-options'); // refused like every Uint8Array of another realm
  });
});

describe('crls: limits of the signature checks', () => {
  it('many lists with the same issuer name cost bounded work and never pass a bad one', async () => {
    const stranger = build();
    const lists = Array.from({ length: 16 }, () =>
      buildCrl({ key: stranger.keys.ca, issuer: 'CA' }),
    );
    expect(await run(lists)).toBe('bad-crl');
  });
});
