// Static checks of the operating templates in deploy/ and docs/betrieb.md. Nothing here builds an image or starts nginx,
// Caddy or systemd: the templates are read and compared with the code (settings read by the relay, limits) and with
// docs/relay.md (time-outs). The check that they WORK is the first real run (docs/betrieb.md).
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { RELAY_LIMITS } from '../relay/limits.ts';

const root = new URL('../', import.meta.url);
const read = (path: string): string => readFileSync(new URL(path, root), 'utf8');
/** Lines that are not blank and not a comment (the `#` kinds of all templates; nginx and Caddy share it). */
const active = (text: string): string[] =>
  text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '' && !l.startsWith('#'));

const dockerfile = read('deploy/Dockerfile');
const dockerignore = read('deploy/Dockerfile.dockerignore');
const unit = read('deploy/zeitstempel-relay.service');
const envFile = read('deploy/relay.env.example');
const nginx = read('deploy/nginx.conf.example');
const caddy = read('deploy/Caddyfile.example');
const betrieb = read('docs/betrieb.md');

describe('Dockerfile', () => {
  const lines = active(dockerfile);
  it('runs as a non-root user', () => {
    const users = lines.filter((l) => /^USER\s/.test(l));
    expect(users.length).toBeGreaterThan(0);
    const last = users[users.length - 1]!.replace(/^USER\s+/, '');
    expect(last).not.toMatch(/^(root|0)(:|$)/);
  });
  it('has a health check with node (no curl), SIGTERM and exec form', () => {
    expect(lines.some((l) => /^HEALTHCHECK\s/.test(l))).toBe(true);
    expect(dockerfile).toMatch(/HEALTHCHECK[^\n]*\\\n\s*CMD \["node",/);
    expect(dockerfile).toContain('/health');
    expect(lines.join('\n')).not.toMatch(/\bcurl\b|\bwget\b/);
    expect(lines).toContain('STOPSIGNAL SIGTERM');
    const start = lines.filter((l) => /^(ENTRYPOINT|CMD)\s/.test(l));
    expect(start.length).toBeGreaterThan(0);
    for (const l of start) expect(l).toMatch(/^(ENTRYPOINT|CMD) \[/);
  });
  it('starts the relay as it runs unbuilt and copies only what it needs', () => {
    expect(lines).toContain('ENTRYPOINT ["node", "relay/container-start.ts"]');
    const copies = lines.filter((l) => /^(COPY|ADD)\s/.test(l));
    expect(copies.some((l) => /^(COPY|ADD)\s+(--\S+\s+)*\.\s/.test(l))).toBe(false);
    const sources = copies.flatMap((l) =>
      l
        .split(/\s+/)
        .slice(1, -1)
        .filter((p) => !p.startsWith('--')),
    );
    expect(new Set(sources)).toEqual(
      new Set(['package.json', 'services.json', 'anchors', 'src', 'relay']),
    );
  });
  it('listens on all addresses inside the container and pins the base tag', () => {
    expect(lines.join('\n')).toMatch(/RELAY_HOST=0\.0\.0\.0/);
    expect(dockerfile).toMatch(/^ARG NODE_IMAGE=node:24\.\d+\.\d+-\S+$/m);
    expect(dockerfile).not.toMatch(/node:\S*latest/);
  });
  it('holds no secret', () => {
    expect(dockerfile).not.toMatch(/BEGIN [A-Z ]*PRIVATE/);
    expect(lines.join('\n')).not.toMatch(/RELAY_UPSTREAM_AUTH_\w*=/);
    expect(lines.join('\n')).not.toMatch(/RELAY_PRIVATE_KEY/);
  });
  it('has an ignore list that keeps the repository noise and key files out', () => {
    const entries = new Set(active(dockerignore));
    for (const e of ['.git', 'node_modules', 'dist', 'tests', '.env', 'relay.env'])
      expect(entries.has(e), e).toBe(true);
    expect([...entries].some((e) => e.includes('keys') && e.endsWith('.json'))).toBe(true);
  });
});

/** Value of a systemd directive (the last one wins, like systemd). */
const directive = (name: string): string | undefined => {
  const hits = unit
    .split('\n')
    .filter((l) => l.startsWith(`${name}=`))
    .map((l) => l.slice(name.length + 1).trim());
  return hits[hits.length - 1];
};

describe('systemd unit', () => {
  it('waits for network and time sync, and restarts after a clean exit', () => {
    expect(directive('After')).toMatch(/network-online\.target/);
    expect(directive('After')).toMatch(/time-sync\.target/);
    expect(directive('Wants')).toMatch(/network-online\.target/);
    expect(directive('Wants')).toMatch(/time-sync\.target/);
    expect(directive('Restart')).toBe('always');
  });
  it('runs unprivileged and hardened', () => {
    expect(directive('User')).toMatch(/^[a-z][a-z0-9_-]*$/);
    expect(directive('User')).not.toBe('root');
    expect(directive('NoNewPrivileges')).toBe('true');
    expect(directive('ProtectSystem')).toBe('strict');
    expect(directive('PrivateTmp')).toBe('true');
    expect(directive('ReadOnlyPaths')).toContain('/etc/zeitstempel');
    expect(directive('EnvironmentFile')).toBe('/etc/zeitstempel/relay.env');
    expect(Number(directive('LimitNOFILE'))).toBeGreaterThan(256 + 64);
    expect(directive('ExecStart')).toMatch(/ relay\/main\.ts$/);
  });
  it('gives the relay more time to end than its own hard stop', () => {
    const stopSeconds = Number(/^(\d+)(s)?$/.exec(directive('TimeoutStopSec') ?? '')?.[1]);
    expect(stopSeconds * 1000).toBeGreaterThan(RELAY_LIMITS.shutdownHardMs);
  });
  it('holds no secret', () => {
    expect(unit).not.toMatch(/BEGIN [A-Z ]*PRIVATE/);
    expect(active(unit).join('\n')).not.toMatch(/RELAY_UPSTREAM_AUTH_\w*=/);
  });
});

/** Every `RELAY_*` setting the relay code names (main.ts reads them; the others are named in comments of the limits). */
const settingsInCode = (): Set<string> => {
  const names = new Set<string>();
  for (const f of readdirSync(new URL('relay/', root)).filter((n) => n.endsWith('.ts'))) {
    for (const m of read(`relay/${f}`).matchAll(
      /\bprocess\.env\.(RELAY_[A-Z]+(?:_[A-Z]+)*)|\benv\.(RELAY_[A-Z]+(?:_[A-Z]+)*)|`RELAY_[A-Z]+(?:_[A-Z]+)*_/g,
    )) {
      names.add((m[1] ?? m[2] ?? m[0].slice(1, -1)).replace(/_$/, ''));
    }
  }
  return names;
};

describe('env template', () => {
  const mainNames = new Set(
    [...read('relay/main.ts').matchAll(/RELAY_[A-Z]+(?:_[A-Z]+)*/g)]
      .map((m) => m[0])
      .filter((n) => n !== 'RELAY_LIMITS'),
  );
  it('mentions every RELAY_* setting that relay/main.ts names (also commented out)', () => {
    expect(mainNames.size).toBeGreaterThanOrEqual(10);
    for (const name of mainNames) expect(envFile, name).toContain(name);
    for (const name of settingsInCode()) expect(envFile, name).toContain(name);
  });
  it('mentions PORT and RELAY_UPSTREAM_AUTH_<ID>', () => {
    expect(envFile).toMatch(/^PORT=\d+$/m);
    expect(envFile).toContain('# RELAY_UPSTREAM_AUTH_<ID>=');
  });
  it('sets only the pilot values, and every active line is KEY=value without inline comment', () => {
    const lines = active(envFile);
    for (const l of lines) expect(l, l).toMatch(/^[A-Z][A-Z0-9_]*=[^\s#"']+$/);
    const set = Object.fromEntries(lines.map((l) => l.split('=') as [string, string]));
    expect(set.RELAY_SERVICES).toBe('freetsa');
    expect(set.RELAY_KEYS_FILE).toMatch(/^\/etc\/zeitstempel\//);
    expect(Object.keys(set)).not.toContain('RELAY_AUTH');
    expect(Object.keys(set)).not.toContain('RELAY_ALLOW_PLAIN_HTTP');
    expect(Object.keys(set)).not.toContain('RELAY_BATCH_MS');
    expect(Object.keys(set).filter((k) => k.startsWith('RELAY_UPSTREAM_AUTH_'))).toEqual([]);
    expect(Number(set.RELAY_MAX_WAIT_MS)).toBeGreaterThanOrEqual(RELAY_LIMITS.maxWaitMinMs);
    expect(Number(set.RELAY_MAX_WAIT_MS)).toBeLessThanOrEqual(RELAY_LIMITS.maxWaitMaxMs);
  });
  it('RELAY_KEY_SHARE is documented but not active (default 100 = off), and its example value is a valid one', () => {
    expect(
      Object.keys(Object.fromEntries(active(envFile).map((l) => l.split('=')))).includes(
        'RELAY_KEY_SHARE',
      ),
    ).toBe(false);
    const example = /^# RELAY_KEY_SHARE=(\d+)$/m.exec(envFile);
    expect(example).not.toBeNull();
    expect(Number(example![1])).toBeGreaterThanOrEqual(RELAY_LIMITS.keyShareMin);
    expect(Number(example![1])).toBeLessThanOrEqual(RELAY_LIMITS.keyShareMax);
    expect(betrieb).toContain('RELAY_KEY_SHARE=50');
  });
  it('holds no secret', () => {
    expect(envFile).not.toMatch(/BEGIN [A-Z ]*PRIVATE/);
    expect(envFile).not.toMatch(/^\s*RELAY_UPSTREAM_AUTH_\w*=[^#\s]/m);
    expect(envFile).not.toMatch(/RELAY_PRIVATE_KEY=/);
  });
});

describe('proxy templates', () => {
  const singleSeconds = (RELAY_LIMITS.maxWaitDefaultMs + 17_000) / 1000 + 3;
  it('nginx: limit_req only in the stamp location, preflight keyless, keepalive upstream', () => {
    const lines = active(nginx);
    expect(lines.filter((l) => l.startsWith('limit_req ')).length).toBe(1);
    const stamp = /location \/v1\/stamp\/ \{([\s\S]*?)\n {4}\}/.exec(nginx);
    expect(stamp, 'location /v1/stamp/').not.toBeNull();
    expect(stamp![1]).toMatch(/\blimit_req\s+zone=zs_rate\b/);
    // the one other location has no limit_req
    const rest = nginx.replace(stamp![0], '');
    expect(active(rest).filter((l) => /^limit_req\s/.test(l))).toEqual([]);
    expect(nginx).toMatch(/OPTIONS\s+"";/);
    expect(nginx).toMatch(/upstream zeitstempel_relay \{[^}]*keepalive \d+;/);
    expect(nginx).toMatch(/rate=5r\/m/);
    expect(nginx).toContain('ssl_certificate ');
    // no URI behind proxy_pass: the path stays as it is
    for (const l of lines.filter((x) => x.startsWith('proxy_pass '))) {
      expect(l).toMatch(/^proxy_pass http:\/\/zeitstempel_relay;/);
    }
    expect(active(nginx).join('\n')).not.toMatch(/\brewrite\b/);
    expect(stamp![1]).toContain('proxy_set_header X-Forwarded-For "";');
  });
  it('nginx: time-outs match docs/relay.md (single operation, 130 s upper bound named)', () => {
    expect(nginx).toMatch(new RegExp(`proxy_read_timeout\\s+${singleSeconds}s;`));
    expect(nginx).toContain('130s');
    expect(nginx).toMatch(/NICHT GEGEN EINEN ECHTEN nginx GETESTET/);
    expect(read('docs/relay.md')).toContain('130 s');
  });
  it('Caddy: names the time-outs, keeps the limit as a module sketch only, says untested', () => {
    expect(caddy).toMatch(new RegExp(`response_header_timeout\\s+${singleSeconds}s`));
    expect(caddy).toContain('130s');
    expect(caddy).toContain('@stamp path /v1/stamp/*');
    expect(caddy).toMatch(/NICHT GEGEN EIN ECHTES Caddy GETESTET/);
    expect(caddy).toMatch(/Zusatzmodul/);
    // the rate limit lines stay commented out: Caddy cannot do it without a module
    expect(active(caddy).join('\n')).not.toMatch(/rate_limit/);
    expect(active(caddy).join('\n')).toContain('header_up -X-Forwarded-For');
  });
});

describe('docs/betrieb.md', () => {
  it('names the counters and the alarm criteria', () => {
    for (const c of [
      'upstream-invalid',
      'upstream-too-old',
      'keyReloadFailed',
      'keyFileWritable',
      'unauthorized',
    ])
      expect(betrieb, c).toContain(c);
    expect(betrieb).toContain('Alarmkriterium');
  });
  it('has the checklist, rotation, emergency, restartAfter, backup, update and non-promises', () => {
    for (const h of [
      '## Pilot-Prüfliste',
      '### Erstlauf von Hand',
      '## Schlüsselrotation',
      '## Notfall: ein Schlüssel wurde ausgelesen',
      '## Neustart mit `restartAfter`',
      '## Backup',
      '## Update',
      '## Was nicht zugesagt ist',
    ])
      expect(betrieb, h).toContain(h);
    for (const w of ['npm run spike', 'npm run probe', 'Restart=always', 'Slew'])
      expect(betrieb, w).toContain(w);
    expect(betrieb).not.toContain('Wird mit der Schlüsseldatei v3 ergänzt');
    expect(betrieb).toContain('### Notfall mit Schlüsseldatei Version 3');
    expect(betrieb).toContain('Rotation mit Ablaufzeit (Schlüsseldatei Version 3)');
    expect(betrieb).toMatch(/\*\*Genau eine Instanz\*\*/);
    expect(betrieb).toContain('alle 5 s neu');
    expect(betrieb).toContain('nur statisch geprüft');
  });
  it('quotes the same stop time as the code', () => {
    expect(RELAY_LIMITS.shutdownHardMs).toBe(10_000);
    expect(betrieb).toContain('`shutdownHardMs` (10 s');
    expect(betrieb).toContain('`TimeoutStopSec=15`');
  });
});

describe('.gitignore keeps the filled-in env file out of the repository', () => {
  const lines = active(read('.gitignore'));
  it('names *.env and deploy/relay.env, and keeps the template (the exception comes last)', () => {
    expect(lines).toContain('*.env');
    expect(lines).toContain('deploy/relay.env');
    expect(lines.indexOf('!deploy/relay.env.example')).toBeGreaterThan(lines.indexOf('*.env'));
  });
  const git = spawnSync('git', ['rev-parse', '--is-inside-work-tree'], {
    cwd: new URL('./', root),
  });
  const inRepo = git.status === 0;
  it.skipIf(!inRepo)(
    'git itself ignores deploy/relay.env, any other *.env, and not the template',
    () => {
      const ignored = (path: string): boolean =>
        spawnSync('git', ['check-ignore', '-q', path], { cwd: new URL('./', root) }).status === 0;
      expect(ignored('deploy/relay.env')).toBe(true);
      expect(ignored('relay.env')).toBe(true);
      expect(ignored('deploy/other.env')).toBe(true);
      expect(ignored('deploy/relay.env.example')).toBe(false);
    },
  );
});
