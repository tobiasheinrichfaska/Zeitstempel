// The CRL limits, codes and the OpenSSL rows are written down and tied to the code.
import { readFileSync } from 'node:fs';
import { CRL_LIMITS } from '../src/lib/crl.ts';

const read = (name: string) => readFileSync(new URL(`../docs/${name}`, import.meta.url), 'utf8');
const model = read('data-model.html');
const limits = read('grenzen.md').replace(/\s+/g, ' ');

describe('CRL documentation', () => {
  it('data-model.html lists every CRL limit with its value', () => {
    for (const [name, value] of Object.entries(CRL_LIMITS)) {
      expect(model, name).toMatch(new RegExp(`<td>${name}</td><td>${value}</td>`));
      expect(limits, name).toContain(`\`${name}\` ${value}`);
    }
  });
  it('data-model.html names the option, the functions and both codes', () => {
    expect(model).toContain('<tr><td>crls</td>');
    expect(model).toMatch(/<tr><td>parseCrl<\/td>/);
    expect(model).toContain('<td>bad-crl</td>');
    expect(model).toContain('<td>revoked</td>');
  });
  it('grenzen.md no longer says "no revocation check" and names what is and is not supported', () => {
    expect(limits).not.toMatch(/es gibt keine Sperrprüfung/);
    for (const word of [
      'Offline-Sperrlisten',
      'kein OCSP, kein Abruf',
      'Delta-CRL',
      'Indirekt-CRL',
      '`keyCompromise`',
      'nach der `genTime` lässt das Token gültig',
    ]) {
      expect(limits, word).toContain(word);
    }
  });
  it('grenzen.md has the OpenSSL rows F21 to F30', () => {
    for (let n = 21; n <= 30; n += 1) expect(limits).toMatch(new RegExp(`\\| F${n} \\|`));
  });
});
