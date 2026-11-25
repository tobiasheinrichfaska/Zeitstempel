import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
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
    expect(doc).toContain('ab 30 s Unterschied ist Vorwarnung');
    expect(doc).toContain('nie nach außen weiter');
  });
});
