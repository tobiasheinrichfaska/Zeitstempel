import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as lib from '../src/index.ts';
import { DER_LIMITS } from '../src/lib/der.ts';
import { BATCH_LIMITS } from '../src/lib/batch.ts';
import { VERIFY_LIMITS } from '../src/lib/verify.ts';
import { RELAY_LIMITS } from '../relay/limits.ts';

const read = (name: string) => readFileSync(new URL(`../docs/${name}`, import.meta.url), 'utf8');
const model = read('data-model.html');
const relayDoc = read('relay.md');
const limitsDoc = read('grenzen.md');

/** True when `git` runs and the project folder is a checkout (decides whether the git tests run or are skipped). */
const inGitCheckout = (() => {
  const probe = spawnSync('git', ['check-ignore', '-q', 'relay-keys.json'], {
    cwd: fileURLToPath(new URL('../', import.meta.url)),
  });
  return probe.error === undefined && (probe.status === 0 || probe.status === 1);
})();

// Every member of the union must be listed here, or this file does not compile.
const REASONS: Record<lib.Reason, true> = {
  'bad-hash': true,
  'bad-nonce': true,
  'bad-options': true,
  'bad-services': true,
  'bad-key': true,
  'bad-key-id': true,
  'bad-key-file': true,
  'bad-batch': true,
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
  'time-too-old': true,
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
  it('data-model.html lists the batch limits with their values', () => {
    for (const [name, value] of Object.entries(BATCH_LIMITS)) {
      expect(model, name).toMatch(new RegExp(`<td>${name}</td><td>${value}</td>`));
    }
  });
  it('grenzen.md names where this library differs from openssl (E1-E4)', () => {
    expect(limitsDoc).toContain('ecdsa-with-SHA384');
    expect(limitsDoc).toContain('signature failure');
    expect(limitsDoc).toContain('keyEncipherment');
    expect(limitsDoc).toContain('Gültigkeit inklusive');
    expect(limitsDoc).toContain('3.0.13');
    expect(limitsDoc).toContain('`crls`');
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
      'verifyBatchedTimestamp',
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

describe('the audit fixes are written down where a reader looks (Befunde 1-12)', () => {
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  const services = readFileSync(new URL('../services.json', import.meta.url), 'utf8');
  const flat = (text: string) => text.replace(/\s+/g, ' ');
  it('data-model.html: minGenTime, time-too-old, signerNotAfter, the two-sided `at`, the CryptoKey', () => {
    for (const word of ['minGenTime', 'signerNotBefore', 'signerNotAfter', 'CryptoKey']) {
      expect(model, word).toContain(word);
    }
    expect(model).toContain('<td>time-too-old</td>');
    expect(flat(model)).toContain('sowohl zur <code>genTime</code> als auch zu <code>at</code>');
    expect(flat(model)).toContain('Ohne diese Option wird die Frische nicht geprüft');
    expect(model).toContain('ESSCertIDv2');
  });
  it('relay.md: the client recipe passes minGenTime, the time window and the idle timeout are in the limits', () => {
    expect(relayDoc).toContain('minGenTime: new Date(sentMs - 60_000)');
    expect(relayDoc).toContain('genTimeSlackMs');
    expect(relayDoc).toContain('upstream-too-old');
    expect(relayDoc).toContain('time-too-old');
    expect(relayDoc).not.toMatch(/\|\s*`maxSkewMs`/); // replaced by genTimeSlackMs
    expect(relayDoc).toContain('signerNotAfter');
  });
  it('relay.md: binding, proxy examples (marked as untested), trust, hash confidentiality, capacity, health, alarm', () => {
    const doc = flat(relayDoc);
    expect(doc).toContain('Ohne `RELAY_HOST` lauscht das Relay **nur auf `127.0.0.1`**');
    expect(doc).toContain('`RELAY_HOST=0.0.0.0`');
    expect(relayDoc).toContain('**nginx**');
    expect(relayDoc).toContain('**Caddy**');
    expect(doc).toContain('nicht gegen einen echten Proxy getestet');
    expect(doc).toContain('mindestens 17 s');
    expect(relayDoc).toContain('X-Zeitstempel-Auth');
    expect(doc).toContain('soweit es um die Bindung an den Hash geht');
    for (const word of ['Frische', 'Verfügbarkeit', 'Vertraulichkeit des Hashes']) {
      expect(doc, word).toContain(word);
    }
    expect(doc).toContain('gesalzenen Hash');
    expect(doc).toContain('Merkle');
    expect(doc).toContain('4 Stempel je Minute');
    expect(doc).toContain('`/health` ruft keinen Dienst auf');
    expect(doc).toContain('`upstream-invalid` ist ein Alarmzeichen');
    expect(doc).toContain('Relay- und App-Stand müssen zusammenpassen');
    for (const name of ['keepAliveProxyMs', 'keepAliveDirectMs', 'RELAY_KEEPALIVE_MS']) {
      expect(doc, name).toContain(name);
    }
    expect(doc).toContain(
      'Ein Proxy mit Leerlauf-Timeout T braucht ein Relay-keepAlive größer als T',
    );
    expect(doc).toContain('Verbindungsgrenzen je Adresse');
    expect(relayDoc).toMatch(/\|\s*`RELAY_KEEPALIVE_MS`\s*\|/); // the settings table has a row for it
  });
  it('grenzen.md: freshness is not checked without minGenTime, the long-term statement, the leap second, ESSCertIDv2', () => {
    const doc = flat(limitsDoc);
    expect(doc).toContain(
      'Ohne die Option `minGenTime` wird **nicht geprüft, wie alt das Token ist**',
    );
    expect(doc).toContain('rückdatierten');
    expect(doc).toContain('## Langzeitaussage');
    expect(doc).toContain('signerNotAfter');
    expect(doc).toContain('rechtzeitig neu stempeln');
    expect(doc).toContain('Schaltsekunde');
    expect(doc).toContain('`502 upstream-invalid`');
    expect(doc).toContain('SHA-1 und eine unbekannte Hash-OID dort werden abgelehnt');
    expect(doc).toContain('zusätzlich zu `at`');
  });
  it('README and services.json do not overstate: a certificate under the anchor, not "the service"', () => {
    expect(readme).not.toContain('„Dienst X bestätigt');
    expect(flat(readme)).toContain(
      'ein Zeitstempel-Zertifikat unter dem übergebenen Anker bestätigt',
    );
    expect(readme).toContain('minGenTime: new Date(sentMs - 60_000)');
    expect(flat(read('dienste.md'))).toContain(
      'Was ein Angreifer auf der Strecke über `http` kann',
    );
    expect(services).toContain('cannot forge the answer');
  });
});

describe('owner decisions: roots as anchors, RELAY_SERVICES required, clock skew recipe', () => {
  const flat = (text: string) => text.replace(/\s+/g, ' ');
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  it('README, dienste.md and grenzen.md say the shipped anchors are roots and how to trust narrower', () => {
    for (const doc of [flat(readme), flat(read('dienste.md')), flat(read('grenzen.md'))]) {
      expect(doc).toContain('Wurzeln');
      expect(doc).toContain('anderen');
      expect(doc).toContain('Zwischen-CA');
      expect(doc).toContain('Signierer');
      expect(doc).toContain('stärker als das');
    }
  });
  it('relay.md and README make RELAY_SERVICES required and name the config-error', () => {
    const doc = flat(relayDoc);
    expect(relayDoc).toMatch(/\| `RELAY_SERVICES`\s+\|[^|]*\*\*Pflicht\*\*[^|]*\|\s*keine\s+\|/);
    expect(doc).toContain('nicht ohne `RELAY_SERVICES`');
    expect(doc).toContain('`config-error`');
    expect(doc).toContain('nur FreeTSA erlaubt die allgemeine Nutzung ausdrücklich');
    expect(relayDoc).not.toContain('alle passenden');
    expect(flat(readme)).toContain('`RELAY_SERVICES`, Pflicht');
  });
  it('relay.md exposes Date with Retry-After and gives the one-time clock fix recipe', () => {
    const doc = flat(relayDoc);
    expect(doc).toContain('Access-Control-Expose-Headers: Retry-After, Date');
    expect(doc).toContain('Date.parse(date) - Date.now()');
    expect(doc).toContain('nowMs = Date.now() + versatz');
    expect(doc).toContain('genau einmal');
    expect(doc).toContain('liegt es am Schlüssel oder an der Kennung, nicht an der Uhr');
    expect(doc).toContain('mindestens 1 s warten');
    expect(relayDoc).toContain('stampWithClockFix');
  });
});

describe('collecting operation (Sammelbetrieb) is written down where a reader looks', () => {
  const flat = (text: string) => text.replace(/\s+/g, ' ');
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  const libSource = readFileSync(new URL('../src/lib/batch.ts', import.meta.url), 'utf8');
  const relayTree = readFileSync(new URL('../relay/batch.ts', import.meta.url), 'utf8');
  it('relay.md: the settings, the format, the tree rules and the stamped value', () => {
    const doc = flat(relayDoc);
    expect(relayDoc).toContain('## Sammelbetrieb');
    expect(relayDoc).toMatch(/\|\s*`RELAY_BATCH_MS`\s*\|/);
    expect(relayDoc).toMatch(/\|\s*`RELAY_BATCH_MAX`\s*\|/);
    expect(doc).toContain('`leaf_i = SHA-256(0x00 ‖ r_i ‖ h_i)`');
    expect(doc).toContain('`SHA-256(0x01 ‖ links ‖ rechts)`');
    expect(doc).toContain('RFC 6962');
    expect(doc).toContain('das letzte Blatt wird nie verdoppelt');
    expect(doc).toContain('`imprint = SHA-256("zeitstempel-batch-v1\\n" ‖ uint32be(n) ‖ Wurzel)`');
    expect(doc).toContain('`batch`');
    for (const field of ['`v`', '`size`', '`index`', '`salt`', '`path`'])
      expect(doc).toContain(field);
    // the tag in the documentation is the tag in both implementations
    expect(libSource).toContain("'zeitstempel-batch-v1\\n'");
    expect(relayTree).toContain("'zeitstempel-batch-v1\\n'");
  });
  it('relay.md: budgets, failures, closing, latency and the proxy timeout', () => {
    const doc = flat(relayDoc);
    expect(doc).toContain('einen Stempel je Fenster');
    expect(doc).toContain('zählen weiter jede Anfrage');
    expect(doc).toContain('**Alle** Anfragen des Fensters bekommen dieselbe Antwort');
    expect(doc).toContain('`503 shutting-down`');
    expect(doc).toContain('mindestens `RELAY_BATCH_MS` + 17 s');
    expect(doc).toContain('Fenster + 17 s');
    expect(doc).toContain('nur dem **Lesen der Anfrage**');
    expect(doc).toContain('kürzer als das Mindestintervall');
    expect(doc).toContain('`verifyBatchedTimestamp`');
    expect(doc).toContain('`imprint-mismatch`');
    expect(doc).toContain('`bad-batch`');
  });
  it('relay.md: honest about hashes, other submitters, proof value and keeping the receipt', () => {
    const doc = flat(relayDoc);
    expect(doc).toContain('sieht **nur `imprint`**');
    expect(doc).toContain('**Das Relay sieht alle Hashes**');
    expect(doc).toContain('keinen Einzelstempel auf den Hash');
    expect(doc).toContain('**nicht qualifiziert**');
    expect(doc).toContain('das GANZE body.batch');
    expect(doc).toContain('(salt, index, size, path)');
  });
  it('grenzen.md, README, dienste.md and services.json agree', () => {
    const limits = flat(limitsDoc);
    expect(limits).toContain('## Beleg im Sammelbetrieb: was er aussagt und was nicht');
    expect(limits).toContain('**Kein Einzelstempel auf den Hash.**');
    expect(limits).toContain('Nicht, wer sonst in der Menge war');
    expect(flat(readme)).toContain('**kein Einzelstempel**');
    expect(readme).toContain('verifyBatchedTimestamp');
    expect(flat(read('dienste.md'))).toContain('**5 s**');
    expect(read('dienste.md')).toContain('RELAY_BATCH_MS');
    const file = JSON.parse(readFileSync(new URL('../services.json', import.meta.url), 'utf8')) as {
      services: { id: string; minIntervalMs: number; terms: string }[];
    };
    const freetsa = file.services.find((s) => s.id === 'freetsa')!;
    expect(freetsa.minIntervalMs).toBe(5000);
    expect(freetsa.terms).toContain('RELAY_BATCH_MS');
  });
  it('data-model.html describes the structure and the function', () => {
    const doc = flat(model);
    expect(doc).toContain('BatchProof');
    expect(doc).toContain('VerifiedBatchedTimestamp');
    expect(doc).toContain('<td>bad-batch</td>');
    expect(doc).toContain('RFC 6962');
  });
});

describe('key types, solo stamps and the key file read again are written down where a reader looks', () => {
  const flat = (text: string) => text.replace(/\s+/g, ' ');
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  const source = readFileSync(new URL('../relay/relay.ts', import.meta.url), 'utf8');
  it('relay.md: settings, error codes and counters', () => {
    expect(relayDoc).toMatch(/\|\s*`RELAY_MAX_WAIT_MS`\s*\|/);
    expect(relayDoc).toContain('## Schlüsselarten und Solo-Stempel');
    for (const code of ['bad-mode', 'solo-not-allowed', 'busy']) {
      expect(relayDoc, code).toMatch(new RegExp(String.raw`\|\s*\d{3}\s*\|\s*\`${code}\``));
      expect(source, code).toContain(`error: '${code}'`);
    }
    for (const counter of ['solo', 'soloDenied', 'keyReloads', 'keyReloadFailed']) {
      expect(relayDoc, counter).toMatch(new RegExp(String.raw`\|\s*\`${counter}\`\s*\|`));
    }
  });
  it('relay.md: the rules of the planner, the wait limit, the proxy timeouts and the warning', () => {
    const doc = flat(relayDoc);
    expect(doc).toContain('Warten nur im Mangelfall');
    expect(doc).toContain('**Abwechselnd.**');
    expect(doc).toContain('mindestens **`RELAY_MAX_WAIT_MS` + Fenster + 17 s**');
    expect(doc).toContain('Wartegrenze + 17 s');
    expect(doc).toContain('**für die Nutzer dieses Browsers auslesbar**');
    expect(doc).toContain('**nur an vertraute Nutzergruppen**');
    expect(doc).toContain('**durch Entfernen aus der Datei**');
    expect(doc).toContain('keine Zahlen je Schlüssel im Betreiberlog');
    expect(doc).toContain(
      '`perMinuteTotal` (60) und `perMinutePerKey` (20) bleiben **unverändert**',
    );
  });
  it('relay.md: the key file is read again, restartAfter ends the process once, the relay never writes', () => {
    const doc = flat(relayDoc);
    expect(doc).toContain('### Schlüsseldatei laufend lesen');
    expect(doc).toContain('**Entfernter Schlüssel:** ist **sofort** ungültig');
    expect(doc).toContain('der **alte Satz bleibt aktiv**');
    expect(doc).toContain('### `restartAfter`: einmaliger sauberer Neustart');
    expect(doc).toContain('**Prozess-Überwacher**');
    expect(doc).toContain('**Das Relay schreibt nie in die Schlüsseldatei.**');
    expect(doc).toContain('**das laufende Neulesen ist deshalb der Normalweg**');
    // the relay code writes no file
    const watch = readFileSync(new URL('../relay/keywatch.ts', import.meta.url), 'utf8');
    expect(watch).not.toMatch(/writeFile|appendFile|createWriteStream|rename|unlink/);
  });
  it('README, data-model.html, grenzen.md and FEATURES_REQUIRED.md agree', () => {
    expect(flat(readme)).toContain('**Schlüsselarten und Solo-Stempel');
    expect(readme).toContain('`403 solo-not-allowed`');
    expect(readme).toContain('RELAY_MAX_WAIT_MS');
    expect(flat(model)).toContain('<td>Anfrage: <code>mode</code></td>');
    expect(model).toContain('<code>solo-not-allowed</code> (403)');
    expect(flat(read('grenzen.md'))).toContain('## Solo-Stempel (Schlüsselart 2)');
    expect(readFileSync(new URL('../FEATURES_REQUIRED.md', import.meta.url), 'utf8')).toContain(
      'Schlüsselarten und Solo-Stempel',
    );
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
  // Visibly skipped (not silently green) without git or outside a git checkout; the content test above stands.
  it.skipIf(!inGitCheckout)(
    'git agrees: every usual key file name is ignored (checked with git where available)',
    () => {
      const root = fileURLToPath(new URL('../', import.meta.url));
      for (const name of NAMES) {
        const r = spawnSync('git', ['check-ignore', '-q', name], { cwd: root });
        expect(r.status, `${name} must be ignored`).toBe(0);
      }
      // and nothing tracked has such a name
      const tracked = spawnSync('git', ['ls-files', '*keys*.json'], {
        cwd: root,
        encoding: 'utf8',
      });
      expect(tracked.stdout.trim()).toBe('');
    },
  );
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
    // the lock-out limit: the service counters are global, one valid key can lock a service for all others
    expect(relayDoc).toContain('**Aussperren:** Die Dienst-Zähler gelten **global**');
    expect(relayDoc).toContain('nie erreicht');
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
  it('a Git install builds: `prepare` builds when typescript is there, and the build starts from an empty dist', () => {
    expect(pkg.scripts['prepare']).toBe('node scripts/prepare.mjs');
    expect(pkg.scripts['build']).toMatch(/^node scripts\/clean-dist\.mjs && tsc /);
    expect(readme).toContain('## Installieren');
  });
});
