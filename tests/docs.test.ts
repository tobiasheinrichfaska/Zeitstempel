import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as lib from '../src/index.ts';
import { DER_LIMITS } from '../src/lib/der.ts';
import { VERIFY_LIMITS } from '../src/lib/verify.ts';
import { RELAY_LIMITS } from '../relay/limits.ts';

const read = (name: string) => readFileSync(new URL(`../docs/${name}`, import.meta.url), 'utf8');
const model = read('data-model.html');
const relayDoc = read('relay.md');
const limitsDoc = read('grenzen.md');

// Every member of the union must be listed here, or this file does not compile.
const REASONS: Record<lib.Reason, true> = {
  'bad-hash': true,
  'bad-nonce': true,
  'bad-options': true,
  'bad-services': true,
  'bad-key': true,
  'bad-key-id': true,
  'bad-key-file': true,
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
  it('data-model.html lists the chain search limits with their values', () => {
    for (const [name, value] of Object.entries(VERIFY_LIMITS)) {
      expect(model, name).toMatch(new RegExp(`<td>${name}</td><td>${value}</td>`));
    }
  });
  it('grenzen.md states every chain search limit with its value', () => {
    // one phrase per limit; a new limit in VERIFY_LIMITS does not compile until it has one
    const phrase: Record<keyof typeof VERIFY_LIMITS, string> = {
      MAX_CHAIN: `Tiefe ${VERIFY_LIMITS.MAX_CHAIN}`,
      MAX_CANDIDATES: `höchstens ${VERIFY_LIMITS.MAX_CANDIDATES} brauchbare Kandidaten`,
      MAX_SIGNATURE_CHECKS: `höchstens ${VERIFY_LIMITS.MAX_SIGNATURE_CHECKS}\nSignaturprüfungen`,
      MAX_REASON_CHECKS: `höchstens\n${VERIFY_LIMITS.MAX_REASON_CHECKS} zusätzlichen Signaturprüfungen`,
      MAX_TRUST_ANCHORS: `mehr als ${VERIFY_LIMITS.MAX_TRUST_ANCHORS} Einträge`,
      MAX_CERTIFICATES: `höchstens ${VERIFY_LIMITS.MAX_CERTIFICATES} Zertifikate`,
    };
    const flat = limitsDoc.replace(/\s+/g, ' ');
    for (const [name, text] of Object.entries(phrase)) {
      expect(flat, name).toContain(text.replace(/\n/g, ' '));
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
      'signRelayRequest',
      'toBase64Url',
      'fromBase64Url',
      'toBase64',
      'fromBase64',
      'toHex',
      'equalBytes',
    ];
    for (const name of documented) {
      expect(typeof (lib as Record<string, unknown>)[name], name).toBe('function');
      expect(model, name).toContain(name);
    }
  });
  it('data-model.html names every export of src/index.ts (explicit exceptions only)', () => {
    // functions that data-model.html documents by name; a new export fails here until it is listed or excepted
    const NOT_DOCUMENTED: string[] = []; // exceptions: none (ok and fail have a row of their own)
    const exported = Object.keys(lib).filter((k) => !NOT_DOCUMENTED.includes(k));
    expect(exported.length).toBeGreaterThan(10);
    for (const name of exported) {
      expect(model, name).toMatch(new RegExp(`<tr><td>(?:[^<]*, )?${name}(?:, [^<]*)?</td>`));
    }
    for (const name of NOT_DOCUMENTED) expect(Object.keys(lib), name).toContain(name);
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
  it('dienste.md lists every service of services.json', () => {
    const doc = read('dienste.md');
    const file = JSON.parse(readFileSync(new URL('../services.json', import.meta.url), 'utf8')) as {
      services: { id: string; url: string }[];
    };
    for (const s of file.services) expect(doc, s.id).toContain(s.url);
  });
});

describe('key files stay out of the repository', () => {
  const PATTERNS = ['relay-keys*.json', '*.keys.json', '*keys*.json'];
  const NAMES = [
    'relay-keys.json',
    'relay-keys.prod.json',
    'app.keys.json',
    'keys.json',
    'prod-keys-2.json',
    'my-relay-keys.local.json',
  ];
  it('.gitignore names the relay key file patterns', () => {
    const lines = readFileSync(new URL('../.gitignore', import.meta.url), 'utf8')
      .split('\n')
      .map((l) => l.trim());
    for (const pattern of PATTERNS) expect(lines, pattern).toContain(pattern);
  });
  it('git agrees: every usual key file name is ignored (checked with git where available)', () => {
    const root = fileURLToPath(new URL('../', import.meta.url));
    const probe = spawnSync('git', ['check-ignore', '-q', 'relay-keys.json'], { cwd: root });
    const inRepo = probe.error === undefined && (probe.status === 0 || probe.status === 1);
    if (!inRepo) return; // no git, or not a git checkout: the file content test above stands
    for (const name of NAMES) {
      const r = spawnSync('git', ['check-ignore', '-q', name], { cwd: root });
      expect(r.status, `${name} must be ignored`).toBe(0);
    }
    // and nothing tracked has such a name
    const tracked = spawnSync('git', ['ls-files', '*keys*.json'], { cwd: root, encoding: 'utf8' });
    expect(tracked.stdout.trim()).toBe('');
  });
  it('relay.md describes the asymmetric file: public keys, integrity, no read warning, the open Content-Type', () => {
    expect(relayDoc).toContain('kein Geheimnis');
    expect(relayDoc).toContain('Unversehrtheit');
    expect(relayDoc).toContain('nicht schreibbar');
    expect(relayDoc).toContain('v2.<kid>.<ts>.<sig>');
    expect(relayDoc).toContain('bewusst nicht');
    expect(relayDoc).not.toContain('gleichwertige Geheimnisse');
    expect(relayDoc).not.toContain('0600 setzen');
  });
  it('relay.md names the replay cache by message digest, the longest Retry-After and the uncounted 400/415', () => {
    expect(relayDoc).toContain('Digest der signierten Nachricht');
    expect(relayDoc).toContain('(r, n − s)');
    expect(relayDoc).toContain('längste');
    expect(relayDoc).toContain('Anfragen, die nicht zählen');
    expect(relayDoc).toContain('höchstens 180 Einträge');
    expect(relayDoc).toContain('Obergrenze');
    expect(relayDoc).toContain('Drei');
  });
  it('relay.md names client-aborted, the clock set back and the reverse proxy; grenzen.md the time rules', () => {
    expect(relayDoc).toContain('client-aborted');
    expect(relayDoc).toContain('Uhr zurückgestellt');
    expect(relayDoc).toContain('Reverse-Proxy');
    expect(relayDoc).toContain('Pflicht');
    expect(relayDoc).toContain('256 Verbindungen');
    expect(read('grenzen.md')).toContain('abgeschnitten');
    expect(read('grenzen.md')).toContain('ohne Nachkommastellen');
    expect(model).toContain('keine Nachkommastellen');
  });
  it('data-model.html describes signRelayRequest with a private key and no deriveVerifier', () => {
    expect(model).toContain('privateKey');
    expect(model).toContain('v2.');
    expect(model).not.toContain('deriveVerifier');
  });
});

describe('the package: what it ships can be reached', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
    files: string[];
    exports: Record<string, string | Record<string, string>>;
    scripts: Record<string, string>;
  };
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  const targets = Object.values(pkg.exports).flatMap((v) =>
    typeof v === 'string' ? [v] : Object.values(v),
  );
  it('every entry of `files` is reached through `exports` (and exports stays closed)', () => {
    expect(pkg.files.length).toBeGreaterThan(0);
    for (const entry of pkg.files) {
      expect(
        targets.some((t) => t === `./${entry}` || t.startsWith(`./${entry}/`)),
        entry,
      ).toBe(true);
    }
    // every key is a path inside the package (no bare directory export that would open everything)
    for (const key of Object.keys(pkg.exports)) expect(key, key).not.toBe('./*');
  });
  it('the services file and the anchors can be taken through exports, and the README says how', () => {
    expect(pkg.exports['./services.json']).toBe('./services.json');
    expect(pkg.exports['./anchors/*.pem']).toBe('./anchors/*.pem');
    expect(readme).toContain('zeitstempel/services.json');
    expect(readme).toContain('zeitstempel/anchors/');
  });
  it('a Git install builds: `prepare` runs the build, and the build starts from an empty dist', () => {
    expect(pkg.scripts['prepare']).toBe('npm run build');
    expect(pkg.scripts['build']).toMatch(/^node scripts\/clean-dist\.mjs && tsc /);
    expect(readme).toContain('## Installieren');
  });
});
