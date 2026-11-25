import { createHash } from 'node:crypto';
import {
  keyFilePermissionWarning,
  loadKeyFile,
  readKeyFileBytes,
  type KeyFile,
  type RelayKey,
} from './keys.ts';

export interface KeyWatcherOptions {
  path: string;
  /** Reads and checks the file (throws on any problem); default `loadKeyFile`. */
  load?: (path: string) => KeyFile;
  /**
   * Signature of the file's state, or null when it cannot be examined (gone, not a plain file, too large); default
   * the SHA-256 of the content. Not mtime, size or inode: a change that keeps all three (written in place, the old
   * times put back) must be found, because a removed key has to stop. The file is at most `keyFileMaxBytes`, so
   * reading it at every look is cheap.
   */
  signature?: (path: string) => string | null;
  /** The permission warning for the file (null: none); default `keyFilePermissionWarning`. */
  permissionWarning?: (path: string) => string | null;
  /** Called when the file turns writable for group or others (once per change of state, path and mode only). */
  onWritable?: (message: string) => void;
  /** The file was already reported as writable at the start: not reported again by the first look. */
  writableAtStart?: boolean;
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
    return createHash('sha256').update(readKeyFileBytes(path)).digest('hex');
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
  const permissionOf = options.permissionWarning ?? keyFilePermissionWarning;
  let writable = options.writableAtStart === true; // reported as writable and not yet fixed
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

  /** The permissions are looked at every time (a `chmod` changes no content): a warning, never a refusal. */
  function checkPermissions(): void {
    try {
      const warning = permissionOf(options.path);
      if (warning === null) writable = false;
      else if (!writable) {
        writable = true;
        options.onWritable?.(warning);
      }
    } catch {
      // a warning that cannot be made must not stop the reload
    }
  }

  function check(): void {
    try {
      checkPermissions();
      const sig = signatureOf(options.path);
      if (sig === applied) {
        failedFor = undefined; // back in the state that is active: a later failure is a new one
      } else {
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
