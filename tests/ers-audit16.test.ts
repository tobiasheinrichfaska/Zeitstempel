// Audit 16 of the evidence record export (src/lib/ers.ts): what the export writes, the reader must read back; a
// hash renewal is named `ers-unsupported`; the size check of the export has a test.
import { exportEvidenceRecord, readEvidenceRecord, renewalImprint } from '../src/index.ts';
import { ERS_LIMITS } from '../src/lib/ers.ts';
import { HASH, makeChain, tokenAt } from './renewal-helpers.ts';
import { ALG_SHA256, ALG_SHA384, writeRecord, writeStamp } from './ers-reference.ts';
import { nestToken, padToken } from './token-pad.ts';

describe('export reads its own record back (nesting depth)', () => {
  it('a token that is readable alone but too deep inside the record is export-unsupported, not unreadable bytes', async () => {
    const made = tokenAt(HASH, '2026-01-01T00:00:00Z');
    const seen: Record<number, string> = {};
    for (const d of [4, 11, 12, 13, 14, 15]) {
      const tok = nestToken(made.token, d);
      const e = await exportEvidenceRecord({ hash: HASH, links: [{ token: tok }] });
      if (e.ok) {
        // whatever the export writes, the reader takes
        expect(readEvidenceRecord(e.value).ok).toBe(true);
        seen[d] = 'ok';
      } else {
        expect(e.reason).toBe('export-unsupported');
        expect(e.detail).toBe('depth');
        seen[d] = 'refused';
      }
    }
    expect(seen[4]).toBe('ok');
    expect(seen[15]).toBe('refused');
  });
});

describe('hash renewal is ers-unsupported, not a malformed record', () => {
  it('two algorithms and two chains (the RFC 4998 3.1 union) is ers-unsupported', async () => {
    const links = await makeChain(HASH, [
      { at: '2026-01-01T00:00:00Z' },
      { at: '2026-06-01T00:00:00Z' },
    ]);
    const st = links.map((l) => writeStamp(l.token));
    const r = readEvidenceRecord(
      writeRecord({ algorithms: [ALG_SHA256, ALG_SHA384], chains: [[st[0]!], [st[1]!]] }),
    );
    expect(r.ok ? 'ok' : r.reason).toBe('ers-unsupported');
  });
  it('two algorithms but ONE chain stays unsupported too (not an invalid shape), only sha384 is unsupported-hash', async () => {
    const links = await makeChain(HASH, [{ at: '2026-01-01T00:00:00Z' }]);
    const st = links.map((l) => writeStamp(l.token));
    const two = readEvidenceRecord(
      writeRecord({ algorithms: [ALG_SHA256, ALG_SHA384], chains: [st] }),
    );
    expect(two.ok ? 'ok' : two.reason).toBe('ers-unsupported');
    const only = readEvidenceRecord(writeRecord({ algorithms: [ALG_SHA384], chains: [st] }));
    expect(only.ok ? 'ok' : only.reason).toBe('unsupported-hash');
    const none = readEvidenceRecord(writeRecord({ algorithms: [], chains: [st] }));
    expect(none.ok ? 'ok' : none.reason).toBe('bad-evidence-record');
  });
});

describe('export size check', () => {
  it('three tokens of about 200 KB are too-large (the record would be over MAX_BYTES)', async () => {
    const links: { token: Uint8Array }[] = [];
    for (let i = 0; i < 3; i += 1) {
      const imprint =
        i === 0
          ? HASH
          : ((await renewalImprint({ hash: HASH, links })) as { value: Uint8Array }).value;
      const made = tokenAt(imprint, `2026-0${i + 1}-01T00:00:00Z`);
      links.push({ token: padToken(made.token, 200000) });
    }
    expect(links.reduce((n, l) => n + l.token.length, 0)).toBeGreaterThan(ERS_LIMITS.MAX_BYTES);
    const e = await exportEvidenceRecord({ hash: HASH, links });
    expect(e.ok ? 'ok' : e.reason).toBe('too-large');
    const one = await exportEvidenceRecord({ hash: HASH, links: links.slice(0, 1) });
    expect(one.ok).toBe(true);
  });
});
