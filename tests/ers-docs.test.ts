import { readFileSync } from 'node:fs';
import * as lib from '../src/index.ts';
import * as client from '../src/client/index.ts';
import { ERS_LIMITS } from '../src/lib/ers.ts';
import { RENEWAL_LIMITS } from '../src/lib/renewal.ts';

const read = (name: string) => readFileSync(new URL(`../${name}`, import.meta.url), 'utf8');
const model = read('docs/data-model.html');
const clientDoc = read('docs/client.md').replace(/\s+/g, ' ');
const limitsDoc = read('docs/grenzen.md').replace(/\s+/g, ' ');
const claude = read('CLAUDE.md').replace(/\s+/g, ' ');

describe('the evidence record (RFC 4998) is written down', () => {
  it('data-model.html lists the three codes, the functions and the limits with their values', () => {
    for (const code of ['bad-evidence-record', 'ers-unsupported', 'export-unsupported'])
      expect(model).toContain(`<td>${code}</td>`);
    for (const name of ['exportEvidenceRecord', 'readEvidenceRecord', 'verifyEvidenceRecord']) {
      expect(typeof (lib as Record<string, unknown>)[name], name).toBe('function');
      expect(model).toMatch(new RegExp(`<tr><td>${name}</td>`));
    }
    expect(typeof client.serializeEvidenceRecord).toBe('function');
    expect(model).toMatch(/<tr><td>serializeEvidenceRecord<\/td>/);
    for (const [name, value] of Object.entries(ERS_LIMITS)) {
      expect(model, name).toMatch(new RegExp(`<td>${name}</td><td>${value}</td>`));
    }
    expect(ERS_LIMITS.MAX_ARCHIVE_TIME_STAMPS).toBe(RENEWAL_LIMITS.MAX_LINKS);
  });
  it('the main entry has the three functions, the client entry only the one that knows evidence', () => {
    for (const name of ['exportEvidenceRecord', 'readEvidenceRecord', 'verifyEvidenceRecord'])
      expect(Object.keys(client)).not.toContain(name);
    expect(Object.keys(lib)).not.toContain('serializeEvidenceRecord');
    expect(Object.keys(lib)).not.toContain('evidenceRecordToEvidence');
    expect(Object.keys(client)).not.toContain('evidenceRecordToEvidence');
  });
  it('client.md names the scope, both decisions, the way back that is not built and the missing foreign check', () => {
    expect(clientDoc).toContain('## ERS-Export');
    for (const text of [
      '`export-unsupported`',
      '`ers-unsupported`',
      '`bad-evidence-record`',
      '`reducedHashtree`',
      'RFC 4998 Abschnitt 5.2',
      'RFC 9162',
      'Hash-Erneuerung',
      'Kein Rückweg',
      '**nicht** geprüft',
      'asn1parse',
      'Referenz-Leser',
      '`ers-tools`',
    ]) {
      expect(clientDoc, text).toContain(text);
    }
  });
  it('grenzen.md and CLAUDE.md say it, too', () => {
    const at = limitsDoc.indexOf('## Langzeitaussage');
    const evidence = limitsDoc.indexOf('Evidence Record nach RFC 4998', at);
    expect(evidence).toBeGreaterThan(at);
    expect(limitsDoc.slice(evidence, evidence + 900)).toContain('`export-unsupported`');
    expect(claude).toContain('**Evidence record (RFC 4998');
    for (const text of [
      'export-unsupported',
      'ers-unsupported',
      'src/lib/ers.ts',
      'tests/ers.test.ts',
    ])
      expect(claude, text).toContain(text);
  });
});
