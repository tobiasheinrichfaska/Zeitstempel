// `crls` against `openssl ts -verify (CRLs in the -CAfile -crl_check[_all]` (OpenSSL 3.0.13, measured; a visible skip
// without OpenSSL 3). Every row where the two differ is a row of the table in docs/grenzen.md (F21 to F30).
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyTimestampToken } from '../src/index.ts';
import type { Reason } from '../src/lib/index.ts';
import { tlv } from '../src/lib/der.ts';
import { build, ext } from './token-builder.ts';
import { OID_CRL, buildCrl, toPem, type CrlEntry, type CrlOpts } from './crl-builder.ts';

const probe = spawnSync('openssl', ['version'], { encoding: 'utf8' });
const major = Number(/^OpenSSL (\d+)/.exec(probe.stdout ?? '')?.[1] ?? 0);
const canCompare = probe.status === 0 && major >= 3;
const ATTIME = '1767225600'; // 2026-01-01T00:00:00Z, the genTime of the builder's tokens
const BEFORE = '20251210000000Z';
const AFTER = '20260301000000Z';

let tmp = '';
beforeAll(() => {
  tmp = mkdtempSync(join(tmpdir(), 'zeitstempel-crl-'));
});
afterAll(() => {
  if (tmp) rmSync(tmp, { recursive: true, force: true });
});

const t = build({ intermediate: {}, crlSign: true });
const noSign = build({ intermediate: {} }); // key usage keyCertSign only
const stranger = build();

type Make = (
  crl: (issuer: 'CA' | 'INT', entries?: CrlEntry[], o?: Partial<CrlOpts>) => Uint8Array,
) => Uint8Array[];

interface Row {
  label: string;
  /** `leaf`: -crl_check; `all`: -crl_check_all. */
  check: 'leaf' | 'all';
  lists: Make;
  tok?: ReturnType<typeof build>;
  openssl: boolean;
  ours: Reason | 'ok';
}

const e = (serial: number, date = BEFORE, more: Partial<CrlEntry> = {}): CrlEntry => ({
  serial,
  date,
  ...more,
});
const LATE = { nextUpdate: '20260401000000Z' };

const ROWS: Row[] = [
  {
    label: 'lists without the serial',
    check: 'all',
    lists: (c) => [c('CA'), c('INT')],
    openssl: true,
    ours: 'ok',
  },
  {
    label: 'signer revoked before genTime',
    check: 'leaf',
    lists: (c) => [c('INT', [e(7)])],
    openssl: false,
    ours: 'revoked',
  },
  {
    label: 'intermediate revoked before genTime (whole chain checked)',
    check: 'all',
    lists: (c) => [c('CA', [e(2)]), c('INT')],
    openssl: false,
    ours: 'revoked',
  },
  {
    label: 'certificateHold before genTime',
    check: 'leaf',
    lists: (c) => [c('INT', [e(7, BEFORE, { reason: 6 })])],
    openssl: false,
    ours: 'revoked',
  },
  {
    label: 'revoked after genTime (reason 5)',
    check: 'leaf',
    lists: (c) => [c('INT', [e(7, AFTER, { reason: 5 })], LATE)],
    openssl: false,
    ours: 'ok',
  },
  {
    label: 'revoked after genTime (keyCompromise)',
    check: 'leaf',
    lists: (c) => [c('INT', [e(7, AFTER, { reason: 1 })], LATE)],
    openssl: false,
    ours: 'revoked',
  },
  {
    label: 'earlier invalidityDate, later revocation date',
    check: 'leaf',
    lists: (c) => [c('INT', [e(7, AFTER, { reason: 4, invalidity: BEFORE })], LATE)],
    openssl: false,
    ours: 'revoked',
  },
  {
    label: 'no list for the issuer (leaf check)',
    check: 'leaf',
    lists: (c) => [c('CA')],
    openssl: false,
    ours: 'ok',
  },
  {
    label: 'no list for the intermediate (full check)',
    check: 'all',
    lists: (c) => [c('INT')],
    openssl: false,
    ours: 'ok',
  },
  {
    label: 'expired list',
    check: 'leaf',
    lists: (c) => [c('INT', [], { nextUpdate: '20251231235959Z' })],
    openssl: false,
    ours: 'bad-crl',
  },
  {
    label: 'list not yet valid',
    check: 'leaf',
    lists: (c) => [c('INT', [], { thisUpdate: '20260101000001Z', nextUpdate: '20260301000000Z' })],
    openssl: false,
    ours: 'bad-crl',
  },
  {
    label: 'signed by a stranger',
    check: 'leaf',
    lists: () => [buildCrl({ key: stranger.keys.ca, issuer: 'INT' })],
    openssl: false,
    ours: 'bad-crl',
  },
  {
    label: 'issuer is not in the chain (and the right one has none)',
    check: 'leaf',
    lists: () => [buildCrl({ key: t.keys.ca, issuer: 'Elsewhere' })],
    openssl: false,
    ours: 'bad-crl',
  },
  {
    label: 'issuer without cRLSign',
    check: 'leaf',
    tok: noSign,
    lists: () => [buildCrl({ key: noSign.midKeys, issuer: 'INT' })],
    openssl: false,
    ours: 'bad-crl',
  },
  {
    label: 'critical delta CRL indicator',
    check: 'leaf',
    lists: (c) => [c('INT', [], { exts: [ext(OID_CRL.delta, true, tlv(2, Uint8Array.of(1)))] })],
    openssl: true,
    ours: 'bad-crl',
  },
  {
    label: 'no nextUpdate',
    check: 'leaf',
    lists: (c) => [c('INT', [], { nextUpdate: null })],
    openssl: true,
    ours: 'bad-crl',
  },
  {
    label: 'unknown critical CRL extension',
    check: 'leaf',
    lists: (c) => [c('INT', [], { exts: [ext('1.2.3.4.5', true, tlv(5))] })],
    openssl: false,
    ours: 'bad-crl',
  },
  {
    label: 'a good list for the leaf and an unrelated one for a stranger',
    check: 'leaf',
    lists: (c) => [c('INT'), buildCrl({ key: stranger.keys.ca, issuer: 'Elsewhere' })],
    openssl: true,
    ours: 'bad-crl',
  },
];

function opensslVerify(tok: ReturnType<typeof build>, lists: Uint8Array[], check: 'leaf' | 'all') {
  writeFileSync(join(tmp, 'row.tok'), tok.token);
  // `ts -verify` has no -CRLfile: the CRLs travel in the PEM file of -CAfile (the store loads certificates and CRLs from it)
  writeFileSync(join(tmp, 'row.ca.pem'), tok.caPem + lists.map(toPem).join(''));
  const r = spawnSync(
    'openssl',
    [
      'ts',
      '-verify',
      '-in',
      join(tmp, 'row.tok'),
      '-token_in',
      '-digest',
      Buffer.from(tok.imprint).toString('hex'),
      '-CAfile',
      join(tmp, 'row.ca.pem'),
      '-attime',
      ATTIME,
      check === 'all' ? '-crl_check_all' : '-crl_check',
    ],
    { encoding: 'utf8' },
  );
  return { ok: r.status === 0, stderr: r.stderr ?? '' };
}

describe('crls against openssl ts -verify -crl_check', () => {
  for (const row of ROWS) {
    it(row.label, async (ctx) => {
      const tok = row.tok ?? t;
      const mid = tok.midKeys;
      const lists = row.lists((issuer, entries = [], o = {}) =>
        buildCrl({ key: issuer === 'CA' ? tok.keys.ca : mid, issuer, entries, ...o }),
      );
      const r = await verifyTimestampToken(tok.token, tok.imprint, [tok.caPem], { crls: lists });
      expect(r.ok ? 'ok' : r.reason).toBe(row.ours);
      if (!canCompare) return ctx.skip();
      const o = opensslVerify(tok, lists, row.check);
      expect(o.ok, o.stderr).toBe(row.openssl);
    });
  }
  it('is visibly skipped without OpenSSL 3', (ctx) => {
    if (canCompare) return ctx.skip();
    expect(canCompare).toBe(false);
  });
});
