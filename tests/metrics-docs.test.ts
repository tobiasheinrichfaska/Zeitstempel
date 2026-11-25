import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { RELAY_LIMITS } from '../relay/limits.ts';
import { createMetrics } from '../relay/metrics.ts';

// The documents and templates that belong to GET /metrics: every series the code writes is described, the proxies block the
// path, the env template names the setting without switching it on, and the alarm criteria name real series.

const read = (path: string): string => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const relayDoc = read('docs/relay.md');
const operations = read('docs/betrieb.md');
const flat = (s: string): string => s.replace(/\s+/g, ' ');

const written = (): string[] => {
  const text = createMetrics({
    serviceIds: ['freetsa'],
    stats: () => ({ stamped: 0, refused: {} }),
    mono: () => 0,
  }).render({
    stamped: 0,
    refused: { busy: 1 },
  });
  return [...new Set([...text.matchAll(/^# TYPE (\S+) /gm)].map((m) => m[1]!))];
};

describe('docs/relay.md describes /metrics', () => {
  it('names every series the endpoint writes', () => {
    const names = written();
    expect(names.length).toBeGreaterThan(15);
    for (const name of names) expect(relayDoc, name).toContain(`\`${name}`);
  });
  it('has the setting row and says what a proxy on the same host must do', () => {
    expect(relayDoc).toMatch(/\|\s*`RELAY_METRICS`\s*\|/);
    const doc = flat(relayDoc);
    expect(doc).toContain('Der Proxy darf `/metrics` deshalb nie nach außen weitergeben');
    expect(doc).toContain('hat **jede** Anfrage über den Proxy eine Loopback-Gegenstelle');
    expect(doc).toContain('Nicht enthalten');
  });
  it('names DNS rebinding and the Host rule, the timing of single requests, and the in-flight limit', () => {
    const doc = flat(relayDoc);
    expect(doc).toContain('DNS-Rebinding');
    expect(doc).toContain('`127.0.0.1`, `localhost` oder `[::1]`');
    expect(doc).toContain('Zeitpunkt einzelner Stempel-Anfragen');
    expect(doc).toContain('`RELAY_HOST=127.0.0.2` löst die Warnung aus');
    expect(doc).toContain('`Infinity`');
    expect(doc).toContain('endet mit der Verbindung des Clients');
  });
  it('the cap of refusal codes in the table is the one in the code', () => {
    expect(relayDoc).toMatch(
      new RegExp(`\\| \`metricsMaxReasons\`\\s*\\| ${RELAY_LIMITS.metricsMaxReasons}\\s*\\|`),
    );
  });
});

describe('templates', () => {
  it('nginx blocks the path, Caddy blocks the path, both say why', () => {
    const nginx = read('deploy/nginx.conf.example');
    expect(nginx).toMatch(/location \^~ \/metrics \{\s*return 404;\s*\}/);
    const caddy = read('deploy/Caddyfile.example');
    expect(caddy).toMatch(
      /@metrics path \/metrics \/metrics\/\*\s*handle @metrics \{\s*respond 404\s*\}/,
    );
    // the blocked path comes before the one that passes everything on
    expect(nginx.indexOf('location ^~ /metrics {')).toBeLessThan(nginx.indexOf('location / {'));
    expect(caddy.indexOf('handle @metrics {')).toBeLessThan(caddy.indexOf('reverse_proxy 127'));
    for (const t of [nginx, caddy]) expect(t).toContain('Loopback-Gegenstelle');
  });
  it('the env template names RELAY_METRICS and leaves it off', () => {
    const env = read('deploy/relay.env.example');
    expect(env).toMatch(/^# RELAY_METRICS=1$/m);
    expect(env).not.toMatch(/^\s*RELAY_METRICS=/m);
  });
});

describe('docs/betrieb.md: alarm criteria', () => {
  it('name the series that exist and the thresholds asked for', () => {
    const doc = flat(operations);
    const names = new Set(written());
    for (const used of doc.matchAll(/`(zeitstempel_[a-z_]+)/g))
      expect(names.has(used[1]!), used[1]).toBe(true);
    expect(doc).toContain('zeitstempel_key_reload_failed_total');
    expect(doc).toMatch(/> 0\*\*/);
    expect(doc).toContain('**> 600** (10 Minuten ohne Erfolg)');
    expect(doc).toContain('{reason="busy"}');
    // the real rule: only more than 60 s before the request counts; no early warning, the future is another code
    expect(doc).toContain('mehr als 60 s vor der Anfrage');
    expect(doc).toContain('keine Vorwarnung');
    expect(doc).not.toContain('ab 30 s Unterschied ist Vorwarnung');
    expect(doc).toContain('`upstream-invalid` (Grund `time-in-future`)');
    // the ratio is sum() over sum(): the two sides carry different labels
    expect(doc).toContain(
      'sum(rate(zeitstempel_refused_total{reason="busy"}[5m])) / sum(rate(zeitstempel_stamp_attempts_total[5m]))',
    );
    // the alarm "service without success" rests on the attempts (what a caller without a key cannot cause)
    expect(doc).toContain('increase(zeitstempel_stamp_attempts_total{service=…}[10m]) > 0');
    expect(doc).not.toMatch(/increase\(zeitstempel_stamp_responses_total/);
    expect(doc).toContain('nie nach außen weiter');
  });
});
