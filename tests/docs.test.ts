import { readFileSync } from 'node:fs';
import * as lib from '../src/index.ts';
import { DER_LIMITS } from '../src/lib/der.ts';
import { RELAY_LIMITS } from '../relay/limits.ts';

const read = (name: string) => readFileSync(new URL(`../docs/${name}`, import.meta.url), 'utf8');
const model = read('data-model.html');
const relayDoc = read('relay.md');

// Every member of the union must be listed here, or this file does not compile.
const REASONS: Record<lib.Reason, true> = {
  'bad-hash': true,
  'bad-nonce': true,
  'bad-services': true,
  'too-large': true,
  malformed: true,
  'indefinite-length': true,
  'too-deep': true,
  'trailing-bytes': true,
  'bad-structure': true,
  rejected: true,
  'no-token': true,
  'not-signed-data': true,
  'unsupported-version': true,
  'bad-content-type': true,
  'bad-tst-info': true,
  'unsupported-hash': true,
  'bad-time': true,
  'time-in-future': true,
  'imprint-mismatch': true,
  'nonce-mismatch': true,
  'one-signer-required': true,
  'unsupported-signature': true,
  'signed-attributes-missing': true,
  'message-digest-mismatch': true,
  'signing-certificate-missing': true,
  'signing-certificate-mismatch': true,
  'signature-invalid': true,
  'bad-pem': true,
  'bad-certificate': true,
  'signer-certificate-missing': true,
  'certificate-not-valid-at-time': true,
  'bad-eku': true,
  'not-a-ca': true,
  'untrusted-chain': true,
  'chain-too-long': true,
  'relay-unreachable': true,
  'relay-timeout': true,
  'relay-refused': true,
  'relay-bad-response': true,
  'relay-rate-limited': true,
  'no-trusted-service': true,
};

describe('docs against the code', () => {
  it('data-model.html lists every error code', () => {
    for (const code of Object.keys(REASONS)) expect(model).toContain(`<td>${code}</td>`);
  });
  it('data-model.html lists the library limits with their values', () => {
    for (const [name, value] of Object.entries(DER_LIMITS)) {
      expect(model).toMatch(new RegExp(`<td>${name}</td><td>${value}</td>`));
    }
  });
  it('data-model.html names the public functions that exist', () => {
    const documented = [
      'buildTimestampRequest',
      'readTimestampResponse',
      'readToken',
      'verifyTimestampToken',
      'parsePemCertificates',
      'parseCertificate',
      'nameToString',
      'readServices',
      'toBase64Url',
      'fromBase64Url',
      'toBase64',
      'fromBase64',
      'toHex',
      'equalBytes',
      'createRelayClient',
      'parseRelayAnswer',
      'parseServiceList',
    ];
    for (const name of documented) {
      expect(typeof (lib as Record<string, unknown>)[name], name).toBe('function');
      expect(model, name).toContain(name);
    }
  });
  it('relay.md lists every relay limit with its value', () => {
    for (const [name, value] of Object.entries(RELAY_LIMITS)) {
      expect(relayDoc, name).toMatch(new RegExp(String.raw`\|\s*\`${name}\`\s*\|\s*${value}\s*\|`));
    }
  });
  it('relay.md names every error code the relay sends', () => {
    const source = readFileSync(new URL('../relay/relay.ts', import.meta.url), 'utf8');
    const sent = new Set([...source.matchAll(/error: '([a-z-]+)'/g)].map((m) => m[1]!));
    sent.add('upstream-failed').add('upstream-timeout').add('upstream-too-large'); // `upstream-${kind}`
    for (const code of sent) expect(relayDoc, code).toContain(`\`${code}\``);
  });
  it('relay.md lists every client limit with its value', () => {
    for (const [name, value] of Object.entries(lib.CLIENT_LIMITS)) {
      expect(relayDoc, name).toMatch(new RegExp(String.raw`\|\s*\`${name}\`\s*\|\s*${value}\s*\|`));
    }
  });
  it('dienste.md lists every service of services.json', () => {
    const doc = read('dienste.md');
    const file = JSON.parse(readFileSync(new URL('../services.json', import.meta.url), 'utf8')) as {
      services: { id: string; url: string }[];
    };
    for (const s of file.services) expect(doc, s.id).toContain(s.url);
  });
});
