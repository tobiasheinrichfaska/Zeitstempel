// The browser check (scripts/browser-check.mjs) and its wiring: static facts that always hold, and one real run
// when Playwright and a built dist/ are there (else visibly skipped).
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const root = fileURLToPath(new URL('..', import.meta.url));
const script = `${root}scripts/browser-check.mjs`;
const read = (path: string): string => readFileSync(`${root}${path}`, 'utf8');

function playwrightThere(): boolean {
  try {
    createRequire(import.meta.url)('playwright');
    return true;
  } catch {
    return false;
  }
}

describe('browser check: wiring', () => {
  it('the script exists and holds no fixed absolute path', () => {
    expect(existsSync(script)).toBe(true);
    const text = read('scripts/browser-check.mjs');
    expect(text).not.toMatch(/['"`]\/(home|tmp|opt|root|Users)\//);
    expect(text).not.toMatch(/[A-Za-z]:\\/);
    expect(text).toContain('import.meta.url');
  });

  it('the script stops with exit code 2 when it cannot run, and names the browsers it may use', () => {
    const text = read('scripts/browser-check.mjs');
    expect(text).toContain('process.exit(2)');
    expect(text).toContain('npm run build');
    expect(text).toContain('BROWSERS');
    expect(text).toContain('process.exit(failed ? 1 : 0)');
  });

  it('package.json has the script and no Playwright dependency', () => {
    const pkg = JSON.parse(read('package.json')) as {
      scripts: Record<string, string>;
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    expect(pkg.scripts['browser-check']).toBe('node scripts/browser-check.mjs');
    const all = { ...pkg.dependencies, ...pkg.devDependencies };
    expect(Object.keys(all).filter((n) => n.includes('playwright'))).toEqual([]);
  });

  it('the workflow has the job `browser`: build, pinned Playwright, the script', () => {
    const wf = read('.github/workflows/tests.yml');
    expect(wf).toMatch(/^ {2}browser:/m);
    expect(wf).toContain('scripts/browser-check.mjs');
    expect(wf).toContain('npm run build');
    expect(wf).toMatch(/playwright@\d+\.\d+\.\d+ install --with-deps chromium/);
    expect(wf).not.toMatch(/playwright@(latest|\^|~)/);
    // the existing job stays
    expect(wf).toMatch(/^ {2}tests:/m);
  });

  it('dependabot.yml updates the actions and npm weekly', () => {
    const text = read('.github/dependabot.yml');
    expect(text).toMatch(/package-ecosystem: github-actions/);
    expect(text).toMatch(/package-ecosystem: npm/);
    expect(text.match(/interval: weekly/g)).toHaveLength(2);
  });
});

const canRun = playwrightThere() && existsSync(`${root}dist/index.js`);

describe('browser check: real run', () => {
  it.skipIf(!canRun)(
    'passes in Chromium (needs Playwright and a built dist/)',
    () => {
      const r = spawnSync(process.execPath, [script], {
        cwd: root,
        encoding: 'utf8',
        timeout: 240_000,
      });
      const tail = `${r.stdout}\n${r.stderr}`.split('\n').slice(-15).join('\n');
      expect(r.status, tail).toBe(0);
      expect(r.stdout).toMatch(/\d+ checks in 1 browser\(s\), 0 failed/);
    },
    300_000,
  );

  it.skipIf(existsSync(`${root}dist/index.js`))('stops with exit code 2 without dist/', () => {
    const r = spawnSync(process.execPath, [script], {
      cwd: root,
      encoding: 'utf8',
      timeout: 60_000,
    });
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('npm run build');
  });
});
