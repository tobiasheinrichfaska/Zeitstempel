import { readFileSync } from 'node:fs';
import * as lib from '../src/index.ts';
import * as client from '../src/client/index.ts';
import { EVIDENCE_LIMITS } from '../src/client/evidence.ts';
import { RENEWAL_LIMITS } from '../src/lib/renewal.ts';

const read = (name: string) => readFileSync(new URL(`../${name}`, import.meta.url), 'utf8');
const model = read('docs/data-model.html');
const clientDoc = read('docs/client.md').replace(/\s+/g, ' ');
const limitsDoc = read('docs/grenzen.md').replace(/\s+/g, ' ');

describe('the renewal chain is written down', () => {
  it('data-model.html lists the new codes, the functions and the limits with their values', () => {
    for (const code of ['bad-renewal', 'renewal-too-late', 'evidence-too-large'])
      expect(model).toContain(`<td>${code}</td>`);
    for (const name of ['renewalImprint', 'verifyRenewalChain']) {
      expect(typeof (lib as Record<string, unknown>)[name], name).toBe('function');
      expect(model).toMatch(new RegExp(`<tr><td>${name}</td>`));
    }
    expect(model).toContain('<tr><td>RelayClient.renew</td>');
    for (const [name, value] of Object.entries(RENEWAL_LIMITS)) {
      expect(model, name).toMatch(new RegExp(`<td>${name}</td><td>${value}</td>`));
    }
    expect(model).toMatch(
      new RegExp(`<td>MAX_RENEWALS</td><td>${EVIDENCE_LIMITS.MAX_RENEWALS}</td>`),
    );
    expect(EVIDENCE_LIMITS.MAX_RENEWALS).toBe(RENEWAL_LIMITS.MAX_LINKS - 1);
    expect(model).toContain('<tr><td>renewals</td>');
  });
  it('the client entry has the method, the main entry does not export a client', () => {
    expect(Object.keys(client)).not.toContain('renewalImprint');
    expect(Object.keys(lib)).not.toContain('createRelayClient');
  });
  it('client.md explains the format, the order, the 30 days and the honest limits', () => {
    for (const text of [
      'RFC 4998 Abschnitt 5.2',
      '`renewals`',
      '`renew`',
      '`weakestLink`',
      '`renewal-too-late`',
      '`bad-renewal`',
      '30 Tagen',
      'so stark wie das schwächste',
      'Kein rechtlicher Wert',
      'nicht** im Browser',
      '`lastChainNotAfter`',
      '`evidence-too-large`',
      '`stamp spent`',
      'vertauschtes** Glied',
    ]) {
      expect(clientDoc, text).toContain(text);
    }
  });
  it('grenzen.md names the chain under "Langzeitaussage"', () => {
    const at = limitsDoc.indexOf('## Langzeitaussage');
    const chain = limitsDoc.indexOf('Erneuerungskette', at);
    expect(at).toBeGreaterThan(0);
    expect(chain).toBeGreaterThan(at);
    expect(limitsDoc.slice(chain, chain + 2500)).toContain('`renewal-too-late`');
  });
});
