// Starts the relay. Settings come from the environment:
//   PORT                     default 8080
//   RELAY_ORIGINS            comma-separated browser origins that may call (default: none)
//   RELAY_ALLOW_PLAIN_HTTP   "1" to use services that only answer over http (default: off)
//   RELAY_SERVICES           comma-separated service ids to offer (default: all that fit)
// Nothing about a request is logged. Once every five minutes one line of counters is printed.
import { randomBytes } from 'node:crypto';
import { loadServices } from './load.ts';
import type { RelayService } from './relay.ts';
import { RELAY_LIMITS } from './limits.ts';
import { networkUpstream } from './upstream.ts';
import { createRelayServer } from './server.ts';

export function readSettings(env: NodeJS.ProcessEnv) {
  const origins = (env.RELAY_ORIGINS ?? '')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);
  if (origins.length > RELAY_LIMITS.maxOrigins) throw new Error('too many origins');
  for (const o of origins) {
    const u = new URL(o);
    if ((u.protocol !== 'https:' && u.hostname !== 'localhost') || u.origin !== o) {
      throw new Error(`origin must be exactly https://host[:port] (or http://localhost): ${o}`);
    }
  }
  const port = Number(env.PORT ?? 8080);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('bad PORT');
  const only = (env.RELAY_SERVICES ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return { origins, port, allowPlainHttp: env.RELAY_ALLOW_PLAIN_HTTP === '1', only };
}

/**
 * The services to offer: those the relay can use (https, or http when allowed). Throws before anything
 * listens when RELAY_SERVICES names an id that is not offered, or when nothing is left to offer.
 * The message names ids, never request data.
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
  const chosen = only.length > 0 ? offered.filter((s) => only.includes(s.id)) : offered;
  if (chosen.length === 0) throw new Error('keine Dienste zum Anbieten (services.json leer?)');
  return chosen;
}

/** Settings and the services to offer, or a throw that names the problem. */
export function readConfig(env: NodeJS.ProcessEnv, load: () => RelayService[] = loadServices) {
  const settings = readSettings(env);
  return {
    settings,
    services: chooseServices(load(), settings.only, settings.allowPlainHttp),
  };
}

if (import.meta.main) {
  let config: ReturnType<typeof readConfig>;
  try {
    config = readConfig(process.env);
  } catch (e) {
    console.error(JSON.stringify({ event: 'config-error', message: (e as Error).message }));
    process.exit(1);
  }
  const { settings, services } = config;
  const { server, relay } = createRelayServer({
    services,
    origins: settings.origins,
    allowPlainHttp: settings.allowPlainHttp,
    upstream: networkUpstream,
    random: (n) => new Uint8Array(randomBytes(n)),
    now: () => Date.now(),
  });
  server.listen(settings.port, () => {
    console.log(
      JSON.stringify({ event: 'start', port: settings.port, services: services.map((s) => s.id) }),
    );
  });
  setInterval(
    () => console.log(JSON.stringify({ event: 'counts', ...relay.stats() })),
    300_000,
  ).unref();
  process.on('SIGTERM', () => server.close(() => process.exit(0)));
}
