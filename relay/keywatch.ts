import { statSync } from 'node:fs';
import { loadKeyFile, type KeyFile, type RelayKey } from './keys.ts';

export interface KeyWatcherOptions {
  path: string;
  /** Reads and checks the file (throws on any problem); default `loadKeyFile`. */
  load?: (path: string) => KeyFile;
  /** Modification signature of the file, or null when it cannot be examined; default mtime, size and inode. */
  signature?: (path: string) => string | null;
  /** Gives the relay the new key set (throws when it refuses it). */
  apply: (keys: readonly RelayKey[]) => void;
  /** Milliseconds since the epoch. */
  now: () => number;
  /** The moment this process started (ms). */
  startMs: number;
  /** Called at most once, when `startMs / 1000 < restartAfter <= now / 1000`. */
  onRestart: () => void;
  /** A reload was applied / a reload failed (counters only, nothing of the file). */
  onReloaded?: () => void;
  onFailed?: () => void;
}

export interface KeyWatcher {
  /** One look at the file: reload when it changed, then the restart rule. Never throws. */
  check: () => void;
  /** Looks every `intervalMs` (the timer does not keep the process alive). */
  start: (intervalMs: number) => void;
  stop: () => void;
}

function fileSignature(path: string): string | null {
  try {
    const s = statSync(path);
    return `${s.mtimeMs}:${s.size}:${s.ino}`;
  } catch {
    return null;
  }
}

/**
 * Keeps the relay's keys in step with the key file (docs/relay.md, "Schlüsseldatei laufend lesen"). The file is
 * only ever read, never written. A change is read strictly; an invalid file leaves the old set active and is
 * counted once per state of the file. `restartAfter` of the last good read ends the process once through
 * `onRestart` (the supervisor starts it again; the new process started after `restartAfter`, so it never repeats).
 */
export function createKeyWatcher(options: KeyWatcherOptions): KeyWatcher {
  const load = options.load ?? loadKeyFile;
  const signatureOf = options.signature ?? fileSignature;
  let applied: string | null | undefined; // signature of the state that is active (undefined: none read yet)
  let failedFor: string | null | undefined; // signature of the state that failed last (counted once)
  let restartAfter: number | undefined;
  let fired = false;
  let timer: ReturnType<typeof setInterval> | null = null;

  function fail(sig: string | null): void {
    if (failedFor !== sig) {
      failedFor = sig;
      options.onFailed?.();
    }
  }

  function check(): void {
    try {
      const sig = signatureOf(options.path);
      if (sig !== applied) {
        if (sig === null) {
          fail(sig); // the file is gone: the old set stays
        } else {
          try {
            const file = load(options.path);
            options.apply(file.keys);
            const first = applied === undefined;
            applied = sig;
            failedFor = undefined;
            restartAfter = file.restartAfter;
            if (!first) options.onReloaded?.(); // the first read only confirms what the start read
          } catch {
            fail(sig); // invalid file (or a half written one): the old set stays, the next look retries
          }
        }
      }
      const nowSec = options.now() / 1000;
      if (
        !fired &&
        restartAfter !== undefined &&
        options.startMs / 1000 < restartAfter &&
        restartAfter <= nowSec
      ) {
        fired = true;
        options.onRestart();
      }
    } catch {
      // a look at the file must never end the process
    }
  }

  return {
    check,
    start(intervalMs) {
      if (timer !== null) return;
      timer = setInterval(check, intervalMs);
      timer.unref();
    },
    stop() {
      if (timer !== null) clearInterval(timer);
      timer = null;
    },
  };
}
