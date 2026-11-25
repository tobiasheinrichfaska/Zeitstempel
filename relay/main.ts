// Starts the relay. Settings come from the environment:
//   PORT                     default 8080
//   RELAY_ORIGINS            comma-separated browser origins that may call (default: none)
//   RELAY_ALLOW_PLAIN_HTTP   "1" to use services that only answer over http (default: off)
//   RELAY_SERVICES           comma-separated service ids to offer; required (no default: the operator picks
//                            on purpose, see docs/dienste.md for the terms of use of each service)
//   RELAY_KEYS_FILE          path of the key file (ids and public keys; no secret, but only the operator may
//                            write it; never in the repo); required
//   RELAY_AUTH               "off" starts without keys (local development only); nothing else is valid
//   RELAY_HOST               address to listen on (default: 127.0.0.1, behind a reverse proxy on the same
//                            machine; a container or another machine needs RELAY_HOST=0.0.0.0 on purpose;
//                            with RELAY_AUTH=off only a loopback address is accepted)
//   RELAY_KEEPALIVE_MS       idle time of a connection between two requests, 1000 to 120000 (default: 65 s
//                            for a loopback binding, 5 s for any other; docs/relay.md)
//   RELAY_BATCH_MS           collecting operation: window in ms, 1000 to 60000 (not set, empty or 0: off, every
//                            request gets a stamp of its own; docs/relay.md, "Sammelbetrieb")
//   RELAY_BATCH_MAX          most requests in one window, 2 to 1024 (default 128)
//   RELAY_MAX_WAIT_MS        the longest a request waits, 1000 to 60000 (default 30000); then 503 busy. Both
//                            operations: the minimum distance to the previous call of the service (single
//                            operation too); collecting operation: also a free slot of the service
//   RELAY_UPSTREAM_AUTH_<ID>  credentials of a paid service that the relay holds itself (<ID>: the service id in capitals,
//                            '-' as '_'); `user:password` for basic, the token for bearer and header; mandatory for a
//                            chosen service with `auth.source` "relay", optional for "either", refused for the others
//                            (docs/relay.md, "Zugangsdaten zu bezahlten Diensten"). Never logged, never in an error text.
// Nothing about a request is logged. Once every five minutes one line of counters is printed.
import { randomBytes } from 'node:crypto';
import type { Server } from 'node:http';
import { loadServices } from './load.ts';
import type { ServiceAuth } from '../src/index.ts';
import { credentialsFromText, type UpstreamCredentials } from './credentials.ts';
import { keyFilePermissionWarning, loadKeyFile, loadKeys, type RelayKey } from './keys.ts';
import { createKeyWatcher } from './keywatch.ts';
import type { RelayOptions, RelayService } from './relay.ts';
import { RELAY_LIMITS } from './limits.ts';
import { networkUpstream } from './upstream.ts';
import { createRelayServer, LOOPBACK_HOSTS } from './server.ts';

// re-exported: the check lives with the key file reader (the watcher repeats it at every look)
export { keyFilePermissionWarning };

export function readSettings(env: NodeJS.ProcessEnv) {
  const origins = (env.RELAY_ORIGINS ?? '')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);
  if (origins.length > RELAY_LIMITS.maxOrigins) {
    throw new Error(`RELAY_ORIGINS: zu viele Herkünfte (höchstens ${RELAY_LIMITS.maxOrigins})`);
  }
  for (const o of origins) {
    let exact = false;
    try {
      const u = new URL(o);
      exact = (u.protocol === 'https:' || u.hostname === 'localhost') && u.origin === o;
    } catch {
      // not a URL at all: the same message as for an inexact origin
    }
    if (!exact) {
      throw new Error(
        `RELAY_ORIGINS: Herkunft muss genau https://host[:port] sein (oder http://localhost…): ${o}`,
      );
    }
  }
  // Decimal digits only, like the other numbers (`Number()` would take 0x50, 1e2, " 80 "); not set is 8080, an empty value
  // is invalid. 0 (a port chosen by the system) is refused on purpose: the start line, the proxy and the firewall need a
  // port that is known beforehand.
  const portRaw = env.PORT ?? '8080';
  const port = /^[0-9]{1,5}$/.test(portRaw) ? Number(portRaw) : NaN;
  if (!(port >= 1 && port <= 65535))
    throw new Error('PORT: ungültig (ganze Zahl von 1 bis 65535 erwartet, nur Dezimalziffern)');
  const only = (env.RELAY_SERVICES ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (env.RELAY_AUTH !== undefined && env.RELAY_AUTH !== '' && env.RELAY_AUTH !== 'off') {
    throw new Error('RELAY_AUTH darf nur "off" sein (oder fehlen)');
  }
  const authOff = env.RELAY_AUTH === 'off';
  if (authOff && (env.RELAY_KEYS_FILE ?? '') !== '') {
    throw new Error('RELAY_AUTH=off und RELAY_KEYS_FILE schließen sich aus');
  }
  const hostEnv = (env.RELAY_HOST ?? '').trim();
  if (authOff && hostEnv !== '' && !LOOPBACK_HOSTS.includes(hostEnv)) {
    throw new Error('RELAY_AUTH=off erlaubt nur eine Loopback-Adresse in RELAY_HOST');
  }
  // Loopback unless the operator names an address: with authentication too (a relay that is reachable from the
  // network must be made so on purpose, e.g. RELAY_HOST=0.0.0.0 in a container)
  const host: string | undefined = hostEnv || '127.0.0.1';
  const keepAliveRaw = env.RELAY_KEEPALIVE_MS ?? '';
  let keepAliveMs: number | undefined;
  if (keepAliveRaw !== '') {
    keepAliveMs = /^[0-9]{1,9}$/.test(keepAliveRaw) ? Number(keepAliveRaw) : NaN;
    if (!(
      keepAliveMs >= RELAY_LIMITS.keepAliveMinMs && keepAliveMs <= RELAY_LIMITS.keepAliveMaxMs
    )) {
      throw new Error(
        `RELAY_KEEPALIVE_MS: ungültig (ganze Zahl von ${RELAY_LIMITS.keepAliveMinMs} bis ${RELAY_LIMITS.keepAliveMaxMs} erwartet)`,
      );
    }
  }
  // Collecting operation: strictly read, an invalid value ends the start (0, empty or not set is off).
  const batchRaw = env.RELAY_BATCH_MS ?? '';
  let batchMs: number | undefined;
  if (batchRaw !== '' && batchRaw !== '0') {
    const value = /^[0-9]{1,9}$/.test(batchRaw) ? Number(batchRaw) : NaN;
    if (!(value >= RELAY_LIMITS.batchMsMin && value <= RELAY_LIMITS.batchMsMax)) {
      throw new Error(
        `RELAY_BATCH_MS: ungültig (ganze Zahl von ${RELAY_LIMITS.batchMsMin} bis ${RELAY_LIMITS.batchMsMax} erwartet; leer oder 0 schaltet den Sammelbetrieb aus)`,
      );
    }
    batchMs = value;
  }
  const batchMaxRaw = env.RELAY_BATCH_MAX ?? '';
  let batchMax: number = RELAY_LIMITS.batchMaxDefault;
  if (batchMaxRaw !== '') {
    batchMax = /^[0-9]{1,9}$/.test(batchMaxRaw) ? Number(batchMaxRaw) : NaN;
    if (!(batchMax >= RELAY_LIMITS.batchMaxMin && batchMax <= RELAY_LIMITS.batchMaxMax)) {
      throw new Error(
        `RELAY_BATCH_MAX: ungültig (ganze Zahl von ${RELAY_LIMITS.batchMaxMin} bis ${RELAY_LIMITS.batchMaxMax} erwartet)`,
      );
    }
  }
  // The longest wait for a free slot (collecting operation): strictly read, an invalid value ends the start.
  const maxWaitRaw = env.RELAY_MAX_WAIT_MS ?? '';
  let maxWaitMs: number | undefined; // not set: the relay's default (maxWaitDefaultMs)
  if (maxWaitRaw !== '') {
    maxWaitMs = /^[0-9]{1,9}$/.test(maxWaitRaw) ? Number(maxWaitRaw) : NaN;
    if (!(maxWaitMs >= RELAY_LIMITS.maxWaitMinMs && maxWaitMs <= RELAY_LIMITS.maxWaitMaxMs)) {
      throw new Error(
        `RELAY_MAX_WAIT_MS: ungültig (ganze Zahl von ${RELAY_LIMITS.maxWaitMinMs} bis ${RELAY_LIMITS.maxWaitMaxMs} erwartet)`,
      );
    }
  }
  return {
    origins,
    port,
    host,
    keepAliveMs,
    batchMs,
    batchMax,
    maxWaitMs,
    allowPlainHttp: env.RELAY_ALLOW_PLAIN_HTTP === '1',
    only,
    authOff,
    keysFile: env.RELAY_KEYS_FILE ?? '',
  };
}

/**
 * The services to offer: those the relay can use (https, or http when allowed). Throws before anything
 * listens when RELAY_SERVICES is missing or empty (the message names the possible ids), names an id that is
 * not offered, or when nothing is left to offer. The message names ids, never request data.
 */
export function chooseServices<T extends { id: string; url: string }>(
  loaded: readonly T[],
  only: readonly string[],
  allowPlainHttp: boolean,
): T[] {
  const offered = loaded.filter((s) => allowPlainHttp || new URL(s.url).protocol === 'https:');
  const unknown = only.filter((id) => !offered.some((s) => s.id === id));
  if (unknown.length > 0) {
    throw new Error(
      `RELAY_SERVICES nennt Kennung(en), die nicht angeboten werden (unbekannt oder nur http ohne RELAY_ALLOW_PLAIN_HTTP): ${unknown.join(', ')}`,
    );
  }
  if (only.length === 0 && loaded.length > 0) {
    throw new Error(
      `RELAY_SERVICES fehlt: die Dienste müssen ausdrücklich gewählt werden (mögliche Kennungen: ${loaded.map((s) => s.id).join(', ')}; Bedingungen der Dienste: docs/dienste.md, nur FreeTSA erlaubt die allgemeine Nutzung ausdrücklich)`,
    );
  }
  const chosen = offered.filter((s) => only.includes(s.id));
  if (chosen.length === 0) throw new Error('keine Dienste zum Anbieten (services.json leer?)');
  return chosen;
}

/** Prefix of the environment variables that hold the relay's own credentials for paid services. */
export const UPSTREAM_AUTH_PREFIX = 'RELAY_UPSTREAM_AUTH_';

/** The variable of a service: `RELAY_UPSTREAM_AUTH_` + id in capitals, `-` as `_` (an id has no `_`, so the names are unique). */
export const upstreamAuthVariable = (id: string): string =>
  UPSTREAM_AUTH_PREFIX + id.toUpperCase().replaceAll('-', '_');

/**
 * The credentials the relay holds itself, from the environment: for each chosen service with `auth` of source `relay`
 * (mandatory) or `either` (optional) the value of its variable. Throws before anything listens: a missing mandatory
 * value, a value that is not well formed, or a variable that belongs to no chosen service that takes credentials of the
 * relay (a typo must not pass in silence). The messages name the VARIABLE, never a value or a part of it.
 */
export function readUpstreamAuth(
  env: NodeJS.ProcessEnv,
  services: readonly { id: string; auth?: ServiceAuth }[],
): Map<string, UpstreamCredentials> {
  const out = new Map<string, UpstreamCredentials>();
  const expected = new Set<string>();
  for (const s of services) {
    const a = s.auth;
    if (a === undefined || a.kind === 'none' || a.source === 'client') continue;
    const name = upstreamAuthVariable(s.id);
    expected.add(name);
    const value = env[name];
    if (value === undefined || value === '') {
      if (a.source === 'relay') {
        throw new Error(`${name} fehlt: der Dienst ${s.id} nimmt nur Zugangsdaten des Relays`);
      }
      continue;
    }
    const creds = credentialsFromText(a, value);
    if (creds === null) {
      throw new Error(
        `${name}: ungültig (${a.kind === 'basic' ? 'Benutzer:Passwort' : 'Token'}, nur druckbares ASCII, Längen siehe docs/relay.md)`,
      );
    }
    out.set(s.id, creds);
  }
  for (const key of Object.keys(env)) {
    if (key.startsWith(UPSTREAM_AUTH_PREFIX) && !expected.has(key)) {
      throw new Error(
        `${key}: gehört zu keinem gewählten Dienst, dessen Zugangsdaten das Relay hält (Quelle "relay" oder "either")`,
      );
    }
  }
  return out;
}

/** Written at the start with an empty key list, and at a reload that leaves none. */
export const EMPTY_KEYS_WARNING =
  'Die Schlüsseldatei enthält keinen Schlüssel ("keys": []): das Relay weist jeden Aufruf mit 401 ab (kein Schlüssel = niemand darf)';

/** Settings, the services to offer and the keys (or `'off'`), or a throw that names the problem. */
export function readConfig(
  env: NodeJS.ProcessEnv,
  load: () => RelayService[] = loadServices,
  readKeys: (path: string, knownServices: ReadonlySet<string>) => RelayKey[] = (path, known) =>
    loadKeys(path, undefined, known),
  checkPermissions: (path: string) => string | null = keyFilePermissionWarning,
) {
  const settings = readSettings(env);
  const all = load();
  // every service of services.json (also the ones this relay does not offer): the ids a key's `services` may name
  const knownServices: ReadonlySet<string> = new Set(all.map((s) => s.id));
  const services = chooseServices(all, settings.only, settings.allowPlainHttp);
  // A window shorter than the interval a service asks for would call it more often than it wants.
  if (settings.batchMs !== undefined) {
    const tooShort = services.filter((s) => s.minIntervalMs > settings.batchMs!);
    if (tooShort.length > 0) {
      throw new Error(
        `RELAY_BATCH_MS (${settings.batchMs}) ist kürzer als das Mindestintervall (minIntervalMs) von: ${tooShort.map((s) => `${s.id} (${s.minIntervalMs})`).join(', ')}`,
      );
    }
  }
  const upstreamAuth = readUpstreamAuth(env, services);
  if (settings.authOff) {
    return {
      settings,
      services,
      upstreamAuth,
      keys: 'off' as const,
      knownServices,
      warnings: [`auth off, loopback only (${settings.host})`],
    };
  }
  if (settings.keysFile === '') {
    throw new Error(
      'RELAY_KEYS_FILE fehlt (ohne Schlüsseldatei startet das Relay nicht; nur für die lokale Entwicklung: RELAY_AUTH=off)',
    );
  }
  const keys = readKeys(settings.keysFile, knownServices);
  const warning = checkPermissions(settings.keysFile);
  const warnings = warning === null ? [] : [warning];
  // An expressly empty list is valid (nobody may stamp), but a start with it is almost always a mistake: say so clearly.
  if (keys.length === 0) warnings.push(EMPTY_KEYS_WARNING);
  return { settings, services, upstreamAuth, keys, knownServices, warnings };
}

/** The start line: port, services and whether requests are authenticated. No key data. */
export function startEvent(
  port: number,
  services: readonly { id: string }[],
  keys: readonly RelayKey[] | 'off',
  batchMs?: number,
) {
  return {
    event: 'start',
    port,
    services: services.map((s) => s.id),
    auth: keys === 'off' ? 'off' : 'on',
    ...(batchMs === undefined ? {} : { batchMs }),
  };
}

/** Starts listening; a host of `undefined` means all interfaces (the settings never give one: the default is 127.0.0.1). */
export function listenOn(
  server: Server,
  port: number,
  host: string | undefined,
  done: () => void,
): void {
  if (host === undefined) server.listen(port, done);
  else server.listen(port, host, done);
}

/**
 * The German line for a server that cannot listen (the error code only: no stack trace, nothing of the environment).
 * `host` is the configured binding (`undefined`: all interfaces).
 */
export function listenErrorMessage(
  code: string | undefined,
  port: number,
  host: string | undefined,
): string {
  switch (code) {
    case 'EADDRINUSE':
      return `Port ${port} ist schon belegt (EADDRINUSE); ein anderes Programm oder eine zweite Relay-Instanz nutzt ihn`;
    case 'EACCES':
      return `Keine Berechtigung für Port ${port} (EACCES); Ports unter 1024 brauchen besondere Rechte`;
    case 'EADDRNOTAVAIL':
      return `Die Adresse ${host ?? '(alle)'} ist auf diesem Rechner nicht vorhanden (EADDRNOTAVAIL, RELAY_HOST prüfen)`;
    default:
      return `Der Server konnte nicht auf Port ${port} lauschen (${code ?? 'Ursache unbekannt'})`;
  }
}

/** What the server needs from the settings: the binding (it decides the keep-alive) and an explicit keep-alive. */
export function serverLimits(settings: {
  host: string | undefined;
  keepAliveMs?: number | undefined;
}) {
  return {
    ...(settings.host === undefined ? {} : { host: settings.host }),
    ...(settings.keepAliveMs === undefined ? {} : { keepAliveMs: settings.keepAliveMs }),
  };
}

/**
 * What `createRelay` is given, from the read settings: services, origins, keys, the credentials the relay holds, the
 * collecting operation and the longest wait. The one place where the settings reach the relay (a test follows each of
 * them through here). The upstream, the random source and the clock come from the caller.
 */
export function buildRelayOptions(
  config: ReturnType<typeof readConfig>,
  deps: Pick<RelayOptions, 'upstream' | 'random' | 'now'>,
): RelayOptions {
  const { settings, services, keys, upstreamAuth } = config;
  return {
    services,
    origins: settings.origins,
    allowPlainHttp: settings.allowPlainHttp,
    upstream: deps.upstream,
    random: deps.random,
    now: deps.now,
    keys,
    upstreamAuth,
    ...(settings.batchMs === undefined
      ? {}
      : { batch: { windowMs: settings.batchMs, max: settings.batchMax } }),
    ...(settings.maxWaitMs === undefined ? {} : { maxWaitMs: settings.maxWaitMs }),
  };
}

/**
 * Ends the server for good: stops listening, closes idle connections as they become idle, closes ALL connections after
 * `shutdownGraceMs` (`server.close()` stops the server's own deadline check, so a connection with half a request would
 * otherwise never end) and calls `exit(0)` when the server is closed or, at the latest, after `shutdownHardMs`. Every timer
 * is unref'd: they never hold the process, they only end it.
 */
export function stopServer(
  server: Pick<Server, 'close' | 'closeIdleConnections' | 'closeAllConnections'>,
  exit: (code: number) => void,
  limits: { graceMs: number; hardMs: number } = {
    graceMs: RELAY_LIMITS.shutdownGraceMs,
    hardMs: RELAY_LIMITS.shutdownHardMs,
  },
): void {
  server.close(() => exit(0));
  // `close` only ends idle connections at the moment of the call: one that was busy (it just got its 503) would stay
  // open until its keep-alive ends (65 s on a loopback binding). So idle ones are closed as they become idle.
  setInterval(() => server.closeIdleConnections(), 200).unref();
  setTimeout(() => server.closeAllConnections(), limits.graceMs).unref();
  setTimeout(() => exit(0), limits.hardMs).unref();
}

function main(): void {
  let config: ReturnType<typeof readConfig>;
  try {
    config = readConfig(process.env);
  } catch (e) {
    console.error(JSON.stringify({ event: 'config-error', message: (e as Error).message }));
    process.exitCode = 1; // no server was started: the process ends by itself
    return;
  }
  const startMs = Date.now();
  const { settings, services, keys, warnings } = config;
  // The relay holds the credentials in memory now: they leave the environment (nothing inherits them).
  for (const s of services) Reflect.deleteProperty(process.env, upstreamAuthVariable(s.id));
  for (const message of warnings) console.error(JSON.stringify({ event: 'warning', message }));
  const { server, relay } = createRelayServer(
    buildRelayOptions(config, {
      upstream: networkUpstream,
      random: (n) => new Uint8Array(randomBytes(n)),
      now: () => Date.now(),
    }),
    serverLimits(settings),
  );
  // A listen error (port taken, no right) is a start error like the others: one German line, exit code 1. An error
  // of the running server (e.g. no file descriptors left for a new connection) is logged by its code and the relay
  // keeps running: without a handler Node would end the process with a stack trace and an empty replay cache.
  let listening = false;
  server.on('error', (error: NodeJS.ErrnoException) => {
    if (!listening) {
      console.error(
        JSON.stringify({
          event: 'config-error',
          message: listenErrorMessage(error.code, settings.port, settings.host),
        }),
      );
      process.exit(1);
    }
    console.error(JSON.stringify({ event: 'server-error', code: error.code ?? 'unknown' }));
  });
  listenOn(server, settings.port, settings.host, () => {
    listening = true;
    console.log(JSON.stringify(startEvent(settings.port, services, keys, settings.batchMs)));
  });
  setInterval(
    () => console.log(JSON.stringify({ event: 'counts', ...relay.stats() })),
    300_000,
  ).unref();
  let ending = false;
  const shutdown = (): void => {
    if (ending) return;
    ending = true;
    watcher?.stop();
    relay.close(); // requests that wait in a window or for a slot are answered (503), nothing hangs
    stopServer(server, process.exit);
  };
  // The key file is read again while the relay runs (new keys count, removed ones stop at once); a
  // `restartAfter` in it ends the process once cleanly, a supervisor starts it again. The relay only reads the file.
  let firstApply = true;
  const watcher =
    keys === 'off'
      ? null
      : createKeyWatcher({
          path: settings.keysFile,
          load: (path) => loadKeyFile(path, undefined, config.knownServices),
          apply: (list) => {
            relay.setKeys(list);
            // the first look only confirms what the start read (and warned about)
            if (list.length === 0 && !firstApply) {
              console.error(JSON.stringify({ event: 'warning', message: EMPTY_KEYS_WARNING }));
            }
            firstApply = false;
          },
          now: () => Date.now(),
          startMs,
          onRestart: () => {
            console.log(JSON.stringify({ event: 'restart-after' }));
            shutdown();
          },
          onReloaded: () => relay.noteKeyReload(true),
          // once per state of the file (the watcher decides): the state only, never the path, a key or a byte of the file
          onFailed: () => {
            relay.noteKeyReload(false);
            console.error(
              JSON.stringify({
                event: 'warning',
                message:
                  'Schlüsseldatei beim Neulesen ungültig oder nicht lesbar; der bisherige Schlüsselsatz bleibt aktiv',
              }),
            );
          },
          // the permission check of the start, repeated at every look: a warning once per change of state
          writableAtStart: warnings.length > 0,
          onWritable: (message) => {
            relay.noteKeyFileWritable();
            console.error(JSON.stringify({ event: 'warning', message }));
          },
        });
  watcher?.check();
  watcher?.start(RELAY_LIMITS.keyFileCheckMs);
  process.on('SIGTERM', shutdown);
}

if (import.meta.main) main();
