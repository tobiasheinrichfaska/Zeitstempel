// Starts the relay. Settings come from the environment:
//   PORT                     default 8080
//   RELAY_ORIGINS            comma-separated browser origins that may call (default: none)
//   RELAY_ALLOW_PLAIN_HTTP   "1" to use services that only answer over http (default: off)
//   RELAY_SERVICES           comma-separated service ids to offer (default: all that fit)
// Nothing about a request is logged. Once every five minutes one line of counters is printed.
import { randomBytes } from 'node:crypto';
import { loadServices } from './load.ts';
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

if (import.meta.main) {
  const settings = readSettings(process.env);
  const all = loadServices();
  const services = settings.only.length ? all.filter((s) => settings.only.includes(s.id)) : all;
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
