import { spawnSync } from 'node:child_process';
import { appendFileSync, cpSync, existsSync, mkdtempSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = fileURLToPath(new URL('..', import.meta.url));

/** A copy of what `prepare` needs; `withTypescript` links this repository's node_modules into it. */
function project(withTypescript: boolean): string {
  const dir = mkdtempSync(join(tmpdir(), 'zeitstempel-prepare-'));
  for (const name of ['scripts', 'src', 'package.json', 'tsconfig.json', 'tsconfig.build.json']) {
    cpSync(join(REPO, name), join(dir, name), { recursive: true });
  }
  if (withTypescript) symlinkSync(join(REPO, 'node_modules'), join(dir, 'node_modules'), 'dir');
  return dir;
}

/** Runs the script with a PATH that has no `tsc`: TypeScript must be found by path, not through PATH. */
function prepare(dir: string) {
  return spawnSync(process.execPath, ['scripts/prepare.mjs'], {
    cwd: dir,
    encoding: 'utf8',
    env: { PATH: '/nonexistent' },
    timeout: 60_000,
  });
}

describe('scripts/prepare.mjs (the `prepare` of npm)', () => {
  it('without typescript it skips the build with one line on stderr and exit 0 (npm install --omit=dev)', () => {
    const dir = project(false);
    try {
      const r = prepare(dir);
      expect(r.status, r.stderr).toBe(0);
      expect(r.stderr.trim()).toBe('prepare: typescript not installed, skipping build');
      expect(existsSync(join(dir, 'dist'))).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
  it('with typescript it builds dist (also with no tsc on PATH) and rewrites the declarations', () => {
    const dir = project(true);
    try {
      const r = prepare(dir);
      expect(r.status, r.stderr + r.stdout).toBe(0);
      expect(existsSync(join(dir, 'dist', 'index.js'))).toBe(true);
      expect(existsSync(join(dir, 'dist', 'index.d.ts'))).toBe(true);
      expect(r.stdout).toContain('declarations rewritten');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
  it('a broken source fails loudly: exit code not 0 and the compiler error on the output (not a silent skip)', () => {
    const dir = project(true);
    try {
      appendFileSync(join(dir, 'src', 'index.ts'), "\nexport const broken: number = 'text';\n");
      const r = prepare(dir);
      expect(r.status, r.stderr + r.stdout).not.toBe(0);
      expect(r.stdout + r.stderr).toContain('error TS');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
