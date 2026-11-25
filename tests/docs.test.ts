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
  'tsa-mismatch': true,
  'policy-mismatch': true,
  'bad-pem': true,
  'bad-certificate': true,
  'weak-key': true,
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

describe('tsa name, TSTInfo schema, minRsaBits and the OpenSSL table are written down', () => {
  const flat = (text: string) => text.replace(/\s+/g, ' ');
  it('data-model.html and grenzen.md name the new codes, the option and the TstInfo field', () => {
    expect(model).toContain('<td>tsa-mismatch</td>');
    expect(model).toContain('<td>weak-key</td>');
    expect(model).toContain('<td>minRsaBits</td>');
    expect(model).toContain('<td>tsa</td>');
    expect(model).toContain('<td>tsa-mismatch</td>');
    const doc = flat(limitsDoc);
    for (const word of [
      '`tsa-mismatch`',
      '`weak-key`',
      '`minRsaBits`',
      '## Abgleich mit OpenSSL',
    ]) {
      expect(doc, word).toContain(word);
    }
  });
  it('grenzen.md has a row for every finding F1 to F20 of the comparison, and lists what is not built', () => {
    for (let n = 1; n <= 20; n += 1)
      expect(limitsDoc, `F${n}`).toMatch(new RegExp(`\\|\\s*F${n}\\s*\\|`));
    const doc = flat(limitsDoc);
    for (const word of ['subjectKeyIdentifier', 'pathLenConstraint', 'Brainpool', 'Ed25519']) {
      expect(doc, word).toContain(word);
    }
  });
  it('relay.md says the batch receipt is no ERS (RFC 4998 / 6283)', () => {
    const doc = flat(relayDoc);
    expect(doc).toContain('**kein Evidence Record (ERS, RFC 4998 und RFC 6283)**');
    expect(doc).toContain('**nicht möglich**');
  });
  it('the README names minRsaBits and the OpenSSL table', () => {
    const readme = flat(readFileSync(new URL('../README.md', import.meta.url), 'utf8'));
    expect(readme).toContain('`minRsaBits`');
    expect(readme).toContain('Abgleich mit OpenSSL');
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
    expect(doc).toContain('Einzelbetrieb mindestens 47 s');
    expect(doc).toContain('proxy_read_timeout 130s;');
    expect(doc).toContain('location /v1/stamp/ {');
    expect(doc).toContain('keepalive 8;');
    expect(doc).toContain('tragen keine CORS-Köpfe');
    expect(doc).toContain('response_header_timeout 130s');
    expect(doc).toContain('112 s beziehungsweise 122 s');
    expect(doc).toContain('Sammelbetrieb FreeTSA 57 s');
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
    expect(doc).toContain('mindestens `RELAY_BATCH_MS` + Kette + 17 s');
    expect(doc).toContain('`AbortSignal.timeout(maxWaitMs + batchMs + chainMs + 17_000)`');
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
    for (const counter of [
      'solo',
      'soloDenied',
      'keyReloads',
      'keyReloadFailed',
      'keyFileWritable',
    ]) {
      expect(relayDoc, counter).toMatch(new RegExp(String.raw`\|\s*\`${counter}\`\s*\|`));
    }
  });
  it('relay.md: the rules of the planner, the wait limit, the proxy timeouts and the warning', () => {
    const doc = flat(relayDoc);
    expect(doc).toContain('Warten nur im Mangelfall');
    expect(doc).toContain('**Abwechselnd.**');
    expect(doc).toContain('**`RELAY_MAX_WAIT_MS` + Fenster + Kette + 17 s**');
    expect(doc).toContain('Wartegrenze + 17 s');
    expect(doc).toContain('**für die Nutzer dieses Browsers auslesbar**');
    expect(doc).toContain('**nur an vertraute Nutzergruppen**');
    expect(doc).toContain('**durch Entfernen aus der Datei**');
    expect(doc).toContain('keine Zahlen je Schlüssel im Betreiberlog');
    expect(doc).toContain(
      '`perMinuteTotal` (60) und `perMinutePerKey` (20) bleiben **unverändert**',
    );
  });
  it('relay.md: solo exists for key type 2 only; type 1 is refused at once, before any work, without budget', () => {
    const doc = flat(relayDoc);
    expect(doc).toContain('Solo-Stempel gibt es **nur für die Schlüsselart 2**.');
    expect(doc).toContain('ist **sofort** `403 solo-not-allowed`, **vor jeder Arbeit**');
    expect(doc).toContain('kostet **kein** Gesamt-, Schlüssel- und Solo-Budget');
    expect(doc).toContain("`soloDenied` und `refused['solo-not-allowed']` zählen die Abweisung");
    expect(doc).toContain('die Schlüsselart wird **nicht** geprüft und es gibt keinen `403`');
    expect(flat(model)).toContain('sofort <code>403 solo-not-allowed</code>');
    expect(flat(readme)).toContain(
      'sofort `403 solo-not-allowed` (kein Warten, kein Platz, kein Budget verbraucht)',
    );
    // the old rule is gone from the text and from the code
    for (const old of [
      'Nur nach bestem Bemühen',
      'allein im Fenster',
      'wartet die ganze Sammelzeit ab',
      'Ein `403` nach dem Warten',
      'nie sofort',
    ]) {
      expect(doc, old).not.toContain(old);
    }
    expect(flat(limitsDoc)).not.toContain('nach bestem Bemühen');
    expect(source).not.toContain('splitWindow');
    expect(source).not.toContain('stampDirect');
    expect(source).not.toContain('alone');
    expect(source).not.toContain('function laneBusy');
  });
  it('relay.md: the minimum spacing between two calls to one service is written down and tied to the code', () => {
    const doc = flat(relayDoc);
    expect(doc).toContain('liegen **mindestens `minIntervalMs` auseinander**');
    expect(doc).toContain('gleich ob der vorige ein Fenster oder ein Solo-Stempel war');
    expect(doc).toContain('**wartet das geschlossene Fenster** bis dahin');
    expect(doc).toContain(
      'in **beiden Betriebsarten**: im Sammelbetrieb für Solo-Stempel und Fenster, im **Einzelbetrieb** für jeden Stempel',
    );
    expect(doc).not.toContain('Im **Einzelbetrieb** gibt es ihn nicht');
    expect(doc).not.toContain('nur das Mengenbudget gilt');
    expect(doc).toContain('`singleQueueMax` (16)');
    expect(source).toContain('function gateWaitMs');
    expect(source).toContain('RELAY_LIMITS.singleQueueMax');
    expect(doc).not.toContain('Kein Mindestabstand zwischen Stempeln');
    expect(doc).not.toContain('Einen **Mindestabstand** zwischen zwei Stempeln gibt es nicht');
    expect(doc).not.toContain('(kein Mindestabstand)');
    expect(flat(readme)).toContain('mindestens `minIntervalMs` des Dienstes Abstand');
    expect(source).toContain('function spacingMs');
    expect(source).toContain('function stampWindow');
  });
  it('relay.md and CLAUDE.md: the planner runs on one monotonic clock, a wall-clock step gives nothing back, tied to the code', () => {
    const doc = flat(relayDoc);
    const claude = flat(readFileSync(new URL('../CLAUDE.md', import.meta.url), 'utf8'));
    expect(doc).toContain('**Uhr des Planers:**');
    expect(doc).toContain(
      'monotonen Uhr des Prozesses (`performance.now()`, im Relay die Funktion `mono`)',
    );
    expect(doc).toContain('Ein Sprung der Wanduhr nach vorn (30 s oder 59 s');
    expect(doc).toContain('**Welche Zähler auf welcher Uhr laufen:**');
    expect(doc).not.toContain('ein Sprung der Uhr nach vorn zählt dagegen als vergangene Zeit');
    expect(doc).not.toContain('das Fenster wartet dann nie');
    expect(doc).toContain('`time-in-future` für das **ganze** Fenster');
    expect(claude).toContain('ONE monotonic clock, the function `mono`');
    expect(claude).toContain('gives back neither distance nor slots');
    expect(source).toContain('const mono = options.monotonicNow');
    expect(source).toContain('const tick = ');
    expect(source).not.toContain('lastCallMono');
    expect(source).not.toContain('monoWaitMs');
    expect(source).not.toContain('armDelayed(d, 1)');
    expect(readFileSync(new URL('./solo-clock.test.ts', import.meta.url), 'utf8')).toContain(
      'do not poll',
    );
  });
  it('relay.md: the deadline formula counts the chain of windows that wait for the distance, with its limits tied to the code', () => {
    const doc = flat(relayDoc);
    // the old statements (a window waits at most one distance; window + 17 s) are gone everywhere
    expect(doc).not.toContain('bei den mitgelieferten Diensten höchstens 15 s');
    expect(doc).not.toContain('AbortSignal.timeout(batchMs + 17_000)');
    expect(doc).not.toContain('Wer die Fristen knapp rechnet, addiert `minIntervalMs`');
    expect(doc).toContain('(k + 1) · `minIntervalMs`');
    expect(doc).toContain('höchstens 60 s');
    expect(doc).toContain('`RELAY_BATCH_MAX` > 60 (Vorgabe 128)');
    expect(doc).toContain('jedes einen Abstand nach dem vorigen');
    expect(doc).toContain('noch einmal');
    // the numbers of the text are the numbers of the code: one budget minute, the total limit, the default window size
    expect(RELAY_LIMITS.windowMs).toBe(60_000);
    expect(RELAY_LIMITS.perMinuteTotal).toBe(60);
    expect(RELAY_LIMITS.batchMaxDefault).toBe(128);
    expect(RELAY_LIMITS.upstreamTimeoutMs + 7000).toBe(17_000);
    // the examples: the window is at least minIntervalMs (the start refuses less), the chain is one distance (60 s at most)
    expect(doc).toContain('30 + 5 + 5 + 17 = **57 s**');
    expect(doc).toContain('30 + 15 + 15 + 17 = **77 s**');
    expect(doc).toContain('30 + 5 + 60 + 17 = **112 s**');
    expect(doc).toContain('30 + 15 + 60 + 17 = **122 s**');
    expect(doc).not.toContain('30 + 5 + 15 + 17');
    // the tolerance of single operation is named in the text, its value lives in relay/limits.ts (not in RELAY_LIMITS)
    expect(doc).toContain('`WAIT_TOLERANCE_MS` (50 ms');
    expect(doc).toContain('Abbruch während des Wartens');
    expect(doc).toContain('(16 Plätze je Spur, also je Dienst und Identität, nicht je Dienst)');
    expect(doc).toContain('nicht nur der gebuchte');
    expect(doc).toContain('die Mengenzähler des Einzelbetriebs auf die monotone Uhr');
    const limitsSource = readFileSync(new URL('../relay/limits.ts', import.meta.url), 'utf8');
    expect(limitsSource).toContain('export const WAIT_TOLERANCE_MS = 50;');
    expect(flat(readme)).toContain('Kette der auf den Mindestabstand wartenden Fenster');
    const project = flat(readFileSync(new URL('../CLAUDE.md', import.meta.url), 'utf8'));
    expect(project).toContain('`RELAY_MAX_WAIT_MS` + window + chain + 17 s');
    expect(project).not.toContain('timeouts at least window');
    expect(source).toContain('function armDelayed');
    expect(source).toContain('function fireDelayed');
  });
  it('relay.md: the order of the refusals of a solo request (form first) and the case without authentication', () => {
    const doc = flat(relayDoc);
    expect(doc).toContain('**nach der Prüfung der Form des Körpers**');
    expect(doc).toContain('`400 bad-upstream`) kommen vor dem `403`');
    expect(doc).toContain('Mit **`RELAY_AUTH=off`** gibt es keinen Schlüssel');
    expect(doc).not.toContain('die Zugangsdaten der Anfrage spielen keine Rolle.');
  });
  it('no document keeps a sentence of an old rule of the solo stamps or the planner', () => {
    const files: [string, string][] = [
      ['relay.md', relayDoc],
      ['recherche.md', read('recherche.md')],
      ['grenzen.md', limitsDoc],
      ['README.md', readme],
      [
        'FEATURES_REQUIRED.md',
        readFileSync(new URL('../FEATURES_REQUIRED.md', import.meta.url), 'utf8'),
      ],
    ];
    for (const [name, text] of files) {
      for (const old of [
        'volle Sammeldauer',
        '403 nach dem Warten',
        'Best-Effort',
        'Allein im Fenster',
        'feste Plätze',
        'bekommt auch Schlüsselart 1',
      ]) {
        expect(flat(text), `${name}: ${old}`).not.toContain(old);
      }
    }
  });
  it('relay.md: one relay instance per key file, and the proxy limit per address stays far below the key budget', () => {
    const doc = flat(relayDoc);
    expect(doc).toContain('**Genau eine Relay-Instanz je Schlüsseldatei.**');
    expect(doc).toContain('nicht den Host');
    expect(doc).toContain(
      '**Das Limit je Adresse muss deutlich unter dem Budget eines Schlüssels liegen.**',
    );
    expect(doc).toContain('rate=5r/m');
    expect(doc).toContain('events 5');
    expect(doc).not.toContain('rate=20r/m');
    expect(doc).not.toContain('events 20');
    // the limit in the example is below the per-key budget of the code
    expect(RELAY_LIMITS.perMinutePerKey).toBeGreaterThan(5);
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

describe('credentials of paid services (upstream, auth) are written down where a reader looks', () => {
  const flat = (text: string) => text.replace(/\s+/g, ' ');
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  const claude = readFileSync(new URL('../CLAUDE.md', import.meta.url), 'utf8');
  const features = readFileSync(new URL('../FEATURES_REQUIRED.md', import.meta.url), 'utf8');
  const source = readFileSync(new URL('../relay/relay.ts', import.meta.url), 'utf8');
  it('relay.md: the section, the kinds, the sources, the setting, the code and the limits', () => {
    const doc = flat(relayDoc);
    expect(relayDoc).toContain('## Zugangsdaten zu bezahlten Diensten');
    expect(relayDoc).toMatch(/\|\s*`RELAY_UPSTREAM_AUTH_<ID>`\s*\|/);
    expect(relayDoc).toMatch(/\|\s*400\s*\|\s*`bad-upstream`/);
    expect(source).toContain("error: 'bad-upstream'");
    for (const word of [
      '`none`',
      '`basic`',
      '`bearer`',
      '`header`',
      '`relay`',
      '`client`',
      '`either`',
    ]) {
      expect(doc, word).toContain(word);
    }
    for (const name of [
      'upstreamUserMax',
      'upstreamPasswordMax',
      'upstreamTokenMax',
      'upstreamIdentitiesMax',
    ]) {
      expect(relayDoc, name).toMatch(new RegExp(String.raw`\|\s*\`${name}\`\s*\|`));
    }
    expect(doc).toContain('`upstream` steht im signierten Körper');
    expect(doc).toContain('nur für `https`-Adressen erlaubt');
    expect(doc).toContain('je (Dienst, Identität)');
    expect(doc).toContain(
      '`perMinuteTotal` (60) und `perMinutePerKey` (20) zählen **jede** Anfrage',
    );
    expect(doc).toContain('nie ausgegeben');
    expect(doc).toContain('für die Nutzer dieses Browsers auslesbar');
    expect(doc).toContain('Cross-Site-Scripting');
    expect(doc).toContain('InfoCert Art. 7');
    expect(doc).toContain('IP-Freigabe');
    expect(doc).toContain('Privatschlüssel von Zertifikaten werden nicht übertragen');
  });
  it('the limits in the code are the ones the documentation names', () => {
    expect(RELAY_LIMITS.upstreamUserMax).toBe(64);
    expect(RELAY_LIMITS.upstreamPasswordMax).toBe(128);
    expect(RELAY_LIMITS.upstreamTokenMax).toBe(384);
    expect(RELAY_LIMITS.upstreamIdentitiesMax).toBe(64);
    const doc = flat(relayDoc);
    expect(doc).toContain(
      '`upstreamUserMax` (64), `upstreamPasswordMax` (128), `upstreamTokenMax` (384)',
    );
    expect(doc).toContain('`upstreamIdentitiesMax` (64)');
  });
  it('data-model.html: the service member auth, the body member upstream and the code', () => {
    const doc = flat(model);
    expect(doc).toContain('<tr><td>auth</td>');
    expect(doc).toContain('<tr><td>Anfrage: <code>upstream</code></td>');
    expect(doc).toContain('<code>bad-upstream</code> (400)');
    for (const name of [
      'upstreamUserMax',
      'upstreamPasswordMax',
      'upstreamTokenMax',
      'upstreamIdentitiesMax',
    ]) {
      expect(doc, name).toContain(`<code>${name}</code>`);
    }
    expect(doc).toContain(
      '<code>basic</code>, <code>bearer</code> und <code>header</code> nur mit https-Adresse',
    );
  });
  it('README, dienste.md, FEATURES_REQUIRED.md and CLAUDE.md agree', () => {
    expect(flat(readme)).toContain('**Zugangsdaten zu bezahlten Diensten');
    expect(readme).toContain('RELAY_UPSTREAM_AUTH_<ID>');
    expect(readme).toContain('`400 bad-upstream`');
    expect(flat(read('dienste.md'))).toContain(
      'Dienste mit IP-Freigabe (z. B. SK) und Dienste mit Zertifikat',
    );
    expect(features).toContain('**Zugangsdaten zu bezahlten Diensten**');
    expect(claude).toContain('**Credentials of paid services');
    expect(claude).toContain('`RELAY_UPSTREAM_AUTH_<ID>`');
  });
  it('the shipped services.json has no auth member (the four free services are unchanged)', () => {
    const file = JSON.parse(readFileSync(new URL('../services.json', import.meta.url), 'utf8')) as {
      services: Record<string, unknown>[];
    };
    expect(file.services).toHaveLength(4);
    for (const s of file.services) expect(Object.hasOwn(s, 'auth')).toBe(false);
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

describe('pathLenConstraint, the signer that is no CA, expectedPolicy and ReaderError are written down', () => {
  const flat = (text: string) => text.replace(/\s+/g, ' ');
  const readme = flat(readFileSync(new URL('../README.md', import.meta.url), 'utf8'));
  it('data-model.html: the option, the new code, the class and the wider meaning of two codes', () => {
    expect(model).toContain('<tr><td>expectedPolicy</td>');
    expect(model).toContain('<td>policy-mismatch</td>');
    expect(model).toContain('<tr><td>ReaderError</td>');
    expect(flat(model)).toContain('<code>pathLenConstraint</code>');
    expect(flat(model)).toContain('selbst ausgestellte Zwischenzertifikate zählen nicht');
  });
  it('grenzen.md: rules 13 to 15 and the table rows say what was measured', () => {
    const doc = flat(limitsDoc);
    for (const word of [
      '13. **`pathLenConstraint`**',
      '14. **Der Signierer ist keine CA:**',
      '15. **Erwartete Richtlinie (`expectedPolicy`, Option):**',
      '`policy-mismatch`',
      'path length constraint exceeded',
      '`cA` TRUE allein nimmt OpenSSL **an**',
      '**Der übergebene Anker zählt mit:**',
    ]) {
      expect(doc, word).toContain(word);
    }
    expect(limitsDoc).toMatch(/\|\s*F6\s*\|[^\n]*bad-certificate/);
    expect(limitsDoc).toMatch(/\|\s*F7\s*\|[^\n]*chain-too-long/);
    expect(limitsDoc).toMatch(/\|\s*F10\s*\|[^\n]*policy-mismatch/);
  });
  it('the README names expectedPolicy, pathLenConstraint and ReaderError', () => {
    for (const word of [
      '`expectedPolicy`',
      '`policy-mismatch`',
      '`pathLenConstraint`',
      '`ReaderError`',
    ]) {
      expect(readme, word).toContain(word);
    }
  });
});
