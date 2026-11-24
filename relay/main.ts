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
//   RELAY_MAX_WAIT_MS        collecting operation: the longest a request waits for a free slot of its service,
//                            1000 to 60000 (default 30000); then 503 busy
// Nothing about a request is logged. Once every five minutes one line of counters is printed.
import { randomBytes } from 'node:crypto';
import { statSync } from 'node:fs';
import type { Server } from 'node:http';
import { loadServices } from './load.ts';
import { loadKeys, type RelayKey } from './keys.ts';
import { createKeyWatcher } from './keywatch.ts';
import type { RelayService } from './relay.ts';
import { RELAY_LIMITS } from './limits.ts';
import { networkUpstream } from './upstream.ts';
import { createRelayServer, LOOPBACK_HOSTS } from './server.ts';

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
  const port = Number(env.PORT ?? 8080);
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    throw new Error('PORT: ungültig (ganze Zahl von 1 bis 65535 erwartet)');
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

/**
 * A warning text when the key file can be written by its group or by others (POSIX; mode & 0o022): whoever
 * can write it can enter a key of their own. Null otherwise, also under Windows (no such modes) and when
 * the file cannot be examined. The text names the path and the mode, nothing from the file. Reading is
 * no problem: the file holds public keys only.
 */
export function keyFilePermissionWarning(
  path: string,
  stat: (path: string) => { mode: number } = statSync,
  platform: string = process.platform,
): string | null {
  if (platform === 'win32') return null;
  let mode: number;
  try {
    mode = stat(path).mode;
  } catch {
    return null;
  }
  if ((mode & 0o022) === 0) return null;
  return `${path}: Die Schlüsseldatei ist für Gruppe oder Andere schreibbar (Modus ${(mode & 0o777).toString(8)}); wer sie schreiben kann, kann einen eigenen Schlüssel eintragen. Schreibrechte entziehen (chmod go-w)`;
}

/** Settings, the services to offer and the keys (or `'off'`), or a throw that names the problem. */
export function readConfig(
  env: NodeJS.ProcessEnv,
  load: () => RelayService[] = loadServices,
  readKeys: (path: string) => RelayKey[] = loadKeys,
  checkPermissions: (path: string) => string | null = keyFilePermissionWarning,
) {
  const settings = readSettings(env);
  const services = chooseServices(load(), settings.only, settings.allowPlainHttp);
  // A window shorter than the interval a service asks for would call it more often than it wants.
  if (settings.batchMs !== undefined) {
    const tooShort = services.filter((s) => s.minIntervalMs > settings.batchMs!);
    if (tooShort.length > 0) {
      throw new Error(
        `RELAY_BATCH_MS (${settings.batchMs}) ist kürzer als das Mindestintervall (minIntervalMs) von: ${tooShort.map((s) => `${s.id} (${s.minIntervalMs})`).join(', ')}`,
      );
    }
  }
  if (settings.authOff) {
    return {
      settings,
      services,
      keys: 'off' as const,
      warnings: [`auth off, loopback only (${settings.host})`],
    };
  }
  if (settings.keysFile === '') {
    throw new Error(
      'RELAY_KEYS_FILE fehlt (ohne Schlüsseldatei startet das Relay nicht; nur für die lokale Entwicklung: RELAY_AUTH=off)',
    );
  }
  const keys = readKeys(settings.keysFile);
  const warning = checkPermissions(settings.keysFile);
  return { settings, services, keys, warnings: warning === null ? [] : [warning] };
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
  for (const message of warnings) console.error(JSON.stringify({ event: 'warning', message }));
  const { server, relay } = createRelayServer(
    {
      services,
      origins: settings.origins,
      allowPlainHttp: settings.allowPlainHttp,
      upstream: networkUpstream,
      random: (n) => new Uint8Array(randomBytes(n)),
      now: () => Date.now(),
      keys,
      ...(settings.batchMs === undefined
        ? {}
        : { batch: { windowMs: settings.batchMs, max: settings.batchMax } }),
      ...(settings.maxWaitMs === undefined ? {} : { maxWaitMs: settings.maxWaitMs }),
    },
    serverLimits(settings),
  );
  listenOn(server, settings.port, settings.host, () => {
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
    server.close(() => process.exit(0));
  };
  // The key file is read again while the relay runs (new keys count, removed ones stop at once); a
  // `restartAfter` in it ends the process once cleanly, a supervisor starts it again. The relay only reads the file.
  const watcher =
    keys === 'off'
      ? null
      : createKeyWatcher({
          path: settings.keysFile,
          apply: (list) => relay.setKeys(list),
          now: () => Date.now(),
          startMs,
          onRestart: () => {
            console.log(JSON.stringify({ event: 'restart-after' }));
            shutdown();
          },
          onReloaded: () => relay.noteKeyReload(true),
          onFailed: () => relay.noteKeyReload(false),
        });
  watcher?.check();
  watcher?.start(RELAY_LIMITS.keyFileCheckMs);
  process.on('SIGTERM', shutdown);
}

if (import.meta.main) main();
