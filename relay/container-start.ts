// Start of the relay in a container service that cannot mount a file: the content of the key file (public keys only,
// no secret) comes as `RELAY_KEYS_JSON`, is written to a file of this process and read by the same strict reader as a
// mounted one. Without the variable this is `relay/main.ts` unchanged.
import { rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { main } from './main.ts';

export function keyFileFromEnv(
  env: NodeJS.ProcessEnv,
  path: string = join(tmpdir(), 'zeitstempel-relay-keys.json'),
): void {
  const text = env.RELAY_KEYS_JSON;
  if (text === undefined || text === '') return;
  rmSync(path, { force: true });
  writeFileSync(path, text, { mode: 0o600, flag: 'wx' });
  env.RELAY_KEYS_FILE = path;
  Reflect.deleteProperty(env, 'RELAY_KEYS_JSON');
}

if (import.meta.main) {
  try {
    keyFileFromEnv(process.env);
    main();
  } catch (e) {
    // the code only: nothing of the variable or the environment
    const code = (e as NodeJS.ErrnoException).code ?? 'unknown';
    console.error(
      JSON.stringify({
        event: 'config-error',
        message: `Schlüsseldatei nicht schreibbar (${code})`,
      }),
    );
    process.exitCode = 1;
  }
}
