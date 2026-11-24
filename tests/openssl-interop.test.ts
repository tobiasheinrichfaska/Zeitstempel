// A sample of tokens written by `openssl ts -reply` (an independent implementation): the strict structure rules of
// the readers (no element too many in a fixed SEQUENCE) must not refuse anything valid. 40 tokens: four signer keys
// (ECDSA P-256 and P-384, RSA 2048 and 3072), signature digests SHA-256/384/512, certificate hash SHA-1/256/512 in
// the signing certificate attribute, accuracy in five forms, ordering and `tsa_name` on and off. Skipped (visibly)
// without OpenSSL 3; needs no network.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readTimestampResponse, readToken, verifyTimestampToken } from '../src/index.ts';

const probe = spawnSync('openssl', ['version'], { encoding: 'utf8' });
const major = Number(/^OpenSSL (\d+)/.exec(probe.stdout ?? '')?.[1] ?? 0);
const usable = probe.status === 0 && major >= 3;
if (!usable) it.skip('tokens written by openssl ts -reply are read (needs OpenSSL 3)', () => {});

let tmp = '';
const at = (name: string) => join(tmp, name);
function run(args: string[], what: string): string {
  const r = spawnSync('openssl', args, { encoding: 'utf8', cwd: tmp });
  if (r.status !== 0) throw new Error(`openssl ${what} failed: ${r.stderr}`);
  return r.stdout;
}

const ACCURACY = [
  '',
  'secs:1',
  'secs:1, millisecs:500, microsecs:10',
  'millisecs:5',
  'microsecs:7',
];
const ESS = ['sha1', 'sha256', 'sha512'];
const DIGEST = ['sha256', 'sha384', 'sha512'];
const SIGNERS = [
  { name: 'ec256', key: 'ec:prime256v1', root: 'rsa' },
  { name: 'rsa2048', key: 'rsa:2048', root: 'rsa' },
  { name: 'ec384', key: 'ec:secp384r1', root: 'ec' },
  { name: 'rsa3072', key: 'rsa:3072', root: 'rsa' },
] as const;

interface Sample {
  label: string;
  response: Uint8Array;
  hash: Uint8Array;
  nonce: Uint8Array;
  root: string;
  ok: boolean;
}
const samples: Sample[] = [];

function makeKey(name: string, spec: string): void {
  const [kind, param] = spec.split(':') as [string, string];
  run(
    kind === 'rsa'
      ? [
          'genpkey',
          '-algorithm',
          'RSA',
          '-pkeyopt',
          `rsa_keygen_bits:${param}`,
          '-out',
          `${name}.key`,
        ]
      : [
          'genpkey',
          '-algorithm',
          'EC',
          '-pkeyopt',
          `ec_paramgen_curve:${param}`,
          '-out',
          `${name}.key`,
        ],
    `genpkey ${name}`,
  );
}

describe.skipIf(!usable)('tokens written by openssl ts -reply are read and verified', () => {
  beforeAll(() => {
    tmp = mkdtempSync(join(tmpdir(), 'zeitstempel-interop-'));
    const roots = { rsa: 'rsa:2048', ec: 'ec:secp384r1' } as const;
    for (const [id, spec] of Object.entries(roots)) {
      makeKey(`root-${id}`, spec);
      run(
        [
          'req',
          '-x509',
          '-new',
          '-key',
          `root-${id}.key`,
          '-out',
          `root-${id}.pem`,
          '-subj',
          `/CN=Interop Root ${id}/O=Interop`,
          '-days',
          '30',
          '-sha256',
          '-addext',
          'basicConstraints=critical,CA:TRUE',
          '-addext',
          'keyUsage=critical,keyCertSign,cRLSign',
        ],
        `root ${id}`,
      );
    }
    writeFileSync(
      at('signer.ext'),
      [
        'basicConstraints=CA:FALSE',
        'keyUsage=critical,digitalSignature',
        'extendedKeyUsage=critical,timeStamping',
        'subjectKeyIdentifier=hash',
        'authorityKeyIdentifier=keyid',
        'subjectAltName=DNS:tsa.example.org,email:ts@example.org',
        '',
      ].join('\n'),
    );
    writeFileSync(at('serial'), '01\n');
    let n = 0;
    for (const signer of SIGNERS) {
      makeKey(signer.name, signer.key);
      run(
        [
          'req',
          '-new',
          '-key',
          `${signer.name}.key`,
          '-subj',
          `/CN=TSA ${signer.name}/O=Interop`,
          '-out',
          `${signer.name}.csr`,
        ],
        `csr ${signer.name}`,
      );
      run(
        [
          'x509',
          '-req',
          '-in',
          `${signer.name}.csr`,
          '-CA',
          `root-${signer.root}.pem`,
          '-CAkey',
          `root-${signer.root}.key`,
          '-CAcreateserial',
          '-out',
          `${signer.name}.pem`,
          '-days',
          '30',
          '-sha256',
          '-extfile',
          'signer.ext',
        ],
        `cert ${signer.name}`,
      );
      for (let i = 0; i < 10; i += 1) {
        const accuracy = ACCURACY[i % 5]!;
        const ordering = i % 2 === 0 ? 'no' : 'yes';
        const tsaName = Math.floor(i / 2) % 2 === 0 ? 'no' : 'yes';
        const ess = ESS[i % 3]!;
        const digest = DIGEST[(i + n) % 3]!;
        const label = `${signer.name} acc=[${accuracy}] ordering=${ordering} tsa_name=${tsaName} ess=${ess} sd=${digest}`;
        writeFileSync(
          at('ts.cnf'),
          [
            '[tsa]',
            'default_tsa = tsa_config',
            '[tsa_config]',
            `serial = ${at('serial')}`,
            `signer_cert = ${at(`${signer.name}.pem`)}`,
            `certs = ${at(`root-${signer.root}.pem`)}`,
            `signer_key = ${at(`${signer.name}.key`)}`,
            `signer_digest = ${digest}`,
            'default_policy = 1.2.3.4.5',
            'other_policies = 1.2.3.4.6',
            'digests = sha1, sha256, sha384, sha512',
            ...(accuracy ? [`accuracy = ${accuracy}`] : []),
            'clock_precision_digits = 3',
            `ordering = ${ordering}`,
            `tsa_name = ${tsaName}`,
            'ess_cert_id_chain = yes',
            `ess_cert_id_alg = ${ess}`,
            '',
          ].join('\n'),
        );
        const hashHex = Buffer.from(`interop payload ${n}`)
          .toString('hex')
          .padEnd(64, '0')
          .slice(0, 64);
        run(['ts', '-query', '-digest', hashHex, '-sha256', '-cert', '-out', 'q.tsq'], 'ts -query');
        const nonceLine = run(['ts', '-query', '-in', 'q.tsq', '-text'], 'ts -query -text')
          .split('\n')
          .find((l) => l.startsWith('Nonce:'));
        const nonceHex = (/0x([0-9A-Fa-f]+)/.exec(nonceLine ?? '')?.[1] ?? '').toLowerCase();
        run(
          [
            'ts',
            '-reply',
            '-config',
            'ts.cnf',
            '-section',
            'tsa_config',
            '-queryfile',
            'q.tsq',
            '-out',
            'r.tsr',
          ],
          'ts -reply',
        );
        const verified = spawnSync(
          'openssl',
          [
            'ts',
            '-verify',
            '-in',
            'r.tsr',
            '-queryfile',
            'q.tsq',
            '-CAfile',
            `root-${signer.root}.pem`,
          ],
          { encoding: 'utf8', cwd: tmp },
        );
        samples.push({
          label,
          response: new Uint8Array(readFileSync(at('r.tsr'))),
          hash: new Uint8Array(Buffer.from(hashHex, 'hex')),
          nonce: new Uint8Array(
            Buffer.from(nonceHex.length % 2 ? `0${nonceHex}` : nonceHex, 'hex'),
          ),
          root: readFileSync(at(`root-${signer.root}.pem`), 'utf8'),
          ok: verified.status === 0,
        });
        n += 1;
      }
    }
  }, 180_000);
  afterAll(() => {
    if (tmp) rmSync(tmp, { recursive: true, force: true });
  });

  it('forty tokens, all accepted by openssl ts -verify (the sample itself is sound)', () => {
    expect(samples.length).toBe(40);
    expect(samples.filter((s) => !s.ok).map((s) => s.label)).toEqual([]);
  });
  it('every response is read, every token is read, and every token verifies with the nonce, now and minGenTime', async () => {
    const now = new Date();
    const failures: string[] = [];
    for (const s of samples) {
      const r = readTimestampResponse(s.response);
      if (!r.ok) {
        failures.push(`${s.label}: readTimestampResponse ${r.reason}`);
        continue;
      }
      try {
        readToken(r.value.token);
      } catch (e) {
        failures.push(`${s.label}: readToken ${(e as { reason?: string }).reason}`);
        continue;
      }
      const v = await verifyTimestampToken(r.value.token, s.hash, [s.root], {
        expectedNonce: s.nonce,
        now: new Date(now.getTime() + 60_000),
        minGenTime: new Date(now.getTime() - 3_600_000),
      });
      if (!v.ok) failures.push(`${s.label}: verify ${v.reason}`);
    }
    expect(failures).toEqual([]);
  });
});
