# CLAUDE.md — Zeitstempel

> Workspace-wide conventions (language, git, build, architecture, testing, collaboration):
> [`c:\skripte\private\general stuff\CLAUDE.md`](../../private/general%20stuff/CLAUDE.md)

---

## Project overview

RFC 3161 time stamps for web apps: build a request, read the answer strictly, verify the token (hash, nonce,
signature, certificate chain to given trust anchors), a list of services as data, and a small relay that
forwards only hashes to fixed services because browsers cannot reach them (CORS). Created 2026-11-23 so that
an app can prove "this hash existed at the latest at time T".

**Platform:** library for browsers and Node (standard APIs only); the relay runs on Node 24
**Language:** TypeScript (erasable syntax only; the relay and the scripts run unbuilt through Node's type stripping)
**Architecture:** `src/lib/` is the pure library (clock and randomness are parameters, errors are codes,
the core functions never throw (`buildTimestampRequest`, `readTimestampResponse`, `verifyTimestampToken`, `readServices`, `signRelayRequest`: for no ordinary input; hostile proxies are covered and tested for `buildTimestampRequest`, `verifyTimestampToken`, `equalBytes`, `signRelayRequest`; inputs are copied by length, never iterated); the building blocks `readToken`, `parseCertificate`, `parsePemCertificates` throw `ReaderError` and the byte writers `toBase64`, `toBase64Url`, `toHex` a `TypeError` for a wrong type; strict bounded DER reader written here: no ASN.1 dependency). `relay/` is the I/O around it.
`services.json` and `anchors/` are data. Status 0.1.0: **not published to npm, not tagged, not
security-reviewed by a human; library tested under Node; in a browser only once, in headless Chromium, without the relay authentication.**

## Key rules

- **Public repo (AGPLv3 + commercial):** no private project names (also not in commit messages, branch names or
  PR texts; `tests/coupling.test.ts` fails if one appears), no credentials, no real data. Only hashes of
  short test texts are ever sent to external services.
- **The library core imports nothing from `node:`** and no `fetch`, `Buffer` or `process` (ESLint rule and
  guard test). It must run in a browser.
- **Trust is the caller's decision:** anchors are a parameter. The shipped anchors (`anchors/`) are data for
  the relay; their fingerprints are listed in `docs/dienste.md`, compared over the network with public operator pages and the system trust store (no request to the operators, no human check).
- **The relay is not an open proxy:** a client names a service id and a hash, nothing else; the relay builds the
  request, calls only the address in `services.json`, follows no redirect, and checks the answer.
- **The relay is authenticated (ECDSA P-256):** per request a signature over method, path, time and body hash,
  header `X-Zeitstempel-Auth: v2.<kid>.<ts>.<sig>`. The private key stays in the app and is never sent; the
  relay's key file holds public keys only (not a secret, but its integrity counts: start warns if group/others can
  write it). It starts only with `RELAY_KEYS_FILE` or an explicit `RELAY_AUTH=off`.
- **Never log what a request carries** (no address, hash, token, key id, signature). Counters only.
- Nothing is published to npm, tagged, rolled out or deployed without Tobias' OK. No qualified service
  contract and no credentials ever in the repo.
- Every rule keeps its test; a verification rule is checked against `openssl ts -verify` where possible.

---

## Project Directory

| File/Folder                                                                                  | Purpose                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `CLAUDE.md`                                                                                  | Project documentation and conventions                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `README.md`                                                                                  | Short description (German), use, license section                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `FEATURES_REQUIRED.md`                                                                       | Critical paths the audit validates                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `docs/data-model.html`                                                                       | Self-contained reference: structures, functions, error codes, limits (`tests/docs.test.ts` ties codes, limits and functions to the code)                                                                                                                                                                                                                                                                                                                                                                           |
| `docs/dienste.md`                                                                            | The services: measurement, anchors with fingerprints, terms of use (read from public pages, not legally checked), anchor comparison, what a stamp is worth, template for a qualified service                                                                                                                                                                                                                                                                                                                       |
| `docs/relay.md`                                                                              | Relay: settings, interface, error codes, limits (tied to the code by a test), what it sees                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `docs/grenzen.md`                                                                            | What the verification checks and what it does NOT                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `docs/recherche.md`                                                                          | Research state (2026-11-24): service limits and measurements, Bunny traffic and cost estimate, batch decision (Merkle tree), own stamps, PDF/Adobe, draft of two key types, other free services                                                                                                                                                                                                                                                                                                                    |
| `manual_tests/`                                                                              | Human-tester instructions (terminal commands that need the network)                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `src/index.ts`, `src/lib/index.ts`                                                           | Public entry                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `src/lib/der.ts`                                                                             | Strict bounded DER reader and the writers the request needs                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `src/lib/oids.ts`                                                                            | OIDs and algorithm tables as data                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `src/lib/x509.ts`                                                                            | Certificate reader, PEM bundles                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `src/lib/request.ts`                                                                         | `buildTimestampRequest`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `src/lib/token.ts`                                                                           | Token (CMS SignedData over TSTInfo) and `readTimestampResponse`                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `src/lib/verify.ts`                                                                          | `verifyTimestampToken`: imprint, nonce, signature, certificates, chain                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `src/lib/services.ts`                                                                        | `readServices`: strict reader of `services.json`                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `src/lib/auth.ts`                                                                            | `signRelayRequest`: the client side of the relay authentication (ECDSA P-256, WebCrypto only)                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `relay/keys.ts`, `relay/keywatch.ts`                                                         | Strict reader of the key file (key ids, public keys, `solo`, `restartAfter`); the watcher that reads it again and asks for the one clean restart                                                                                                                                                                                                                                                                                                                                                                   |
| `src/lib/bytes.ts`, `src/lib/result.ts`                                                      | Byte/base64 helpers; `Result`, `Reason` codes, `ReaderError`                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `services.json`, `anchors/`                                                                  | The services as data and their trust anchors (PEM)                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `relay/relay.ts`                                                                             | The relay rules (`createRelay`), no I/O of its own                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `relay/upstream.ts`                                                                          | The one way out: POST to a service (TLS, no redirect, hard deadline, size cap)                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `relay/limits.ts`                                                                            | Every relay limit in one place                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `relay/server.ts`, `relay/main.ts`, `relay/load.ts`                                          | HTTP server, start (settings from the environment), loading the data files                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `scripts/`                                                                                   | `spike.ts`, `probe.ts`, `make-request.ts`, `make-key.ts` (new key pair, stdout only), `clean-dist.mjs` (build starts from an empty dist), `prepare.mjs` (`prepare` builds only if typescript resolves, else one line on stderr and exit 0), `fix-declarations.mjs`, `browser-check.mjs` (Chromium, by hand)                                                                                                                                                                                                        |
| `tests/`                                                                                     | `der`, `verify`, `hardening` (+ `token-builder`), `token-time`, `bytes`, `copy` (+ `copy-child`), `prepare`, `no-webcrypto`, `auth` (+ `auth-helpers`), `helpers.ts` (fixtures, hashes), `relay-keys`, `services-fixtures`, `openssl`, `relay`, `solo` (key types, planner, key file reloading), `keyfile` (watcher, file kind and size, permissions), `main-wiring` (settings to relay, process: watcher, SIGTERM), `services`, `docs`, `coupling`; `fixtures/` = recorded answers of real services (public data) |
| `package.json`, `tsconfig*.json`, `eslint.config.js`, `vitest.config.ts`, `.prettierrc.json` | Toolchain                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `.github/workflows/tests.yml`                                                                | Check "Tests": typecheck, lint, format, tests, build                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `.gitattributes`, `.gitignore`                                                               | LF line endings; ignore rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `SECURITY.md`                                                                                | How to report a vulnerability, status, limits                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `LICENSE`, `LICENSE_COMMERCIAL.md`, `CONTRIBUTING.md`                                        | AGPLv3 + commercial                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

---

## Data Model

Authoritative reference: [`docs/data-model.html`](docs/data-model.html). No persisted data; shipped reference
data: `services.json` and `anchors/`. Regenerate/align the document in the same session the model changes.

## Tests

```bash
npm install
npm run typecheck
npm run lint
npm run format:check
npm test
npm run build
npm run spike   # by hand, needs the network (see manual_tests/)
```

## Known Limitations

- **Browser: checked in headless Chromium 157 only; on 2026-11-24 an audit script (not in the repo, hard-coded paths) also ran `signRelayRequest` (key bytes and non-extractable `CryptoKey`), signed cross-origin calls with preflight, batch mode with `verifyBatchedTimestamp` and a solo call against a stub relay: 47 checks, no difference to Node; the checked-in script is the older one** (2026-11-23, `node scripts/browser-check.mjs`, by
  hand, needs Playwright with Chromium, which is not a dependency; the script starts its own relay with `keys: 'off'`
  inside the script: no environment variable, no key): the four recorded tokens verify (ECDSA P-384
  and RSA-4096 signers), wrong hash / wrong anchor / changed bytes are refused, and a cross-origin call to the
  relay (preflight included) works. Firefox and Safari were not run. In an insecure context (plain http, not
  localhost) `crypto.subtle` is missing and verification answers `unsupported-signature`.
- **Strict by design (verification):** the signer must carry exactly one extended key usage,
  `id-kp-timeStamping` (critical by default). A critical extension this library does not know makes a chain
  certificate invalid (`bad-certificate`); a trust anchor is exempt (that is the caller's decision). Options are
  checked: `trust` must be an array and `options` omitted or a plain object (prototype `Object.prototype` or
  `null`; not a class instance, `Map`, array), `expectedNonce` a `Uint8Array` of 1 to 16 bytes,
  `requireCriticalEku` a boolean, `now`/`at` a real valid `Date`, `maxSkewMs` a number >= 0, `minRsaBits` a finite number >= 0, otherwise `bad-options` (never a silently skipped check; only `undefined`
  means "not given"). A `Uint8Array` of another realm (iframe, worker, `vm`) is refused (`bad-hash` / `bad-options`; a token: `malformed`; the nonce of `buildTimestampRequest`: `bad-nonce`): pass `new Uint8Array(x)`; `readTimestampResponse`, `readToken` and `parseCertificate` check no `instanceof` and accept such bytes, but only a `Uint8Array` (any other typed array such as `Uint16Array` is `malformed`). The chain search tries every signature-valid issuer candidate (bounded), so a look-alike
  certificate cannot block a valid token. A negative serial number makes a trust anchor or the signer's `sid` unreadable (`malformed`); an unreadable extra certificate inside the token is skipped (`skippedCertificates`, it can never be a candidate). A named signature OID of the signer (e.g. ecdsa-with-SHA384) must agree with the `digestAlgorithm` of the SignerInfo, else `signature-invalid` (a bare OID takes that hash). Looser than `openssl ts -verify`: extra keyUsage bits of the signer, validity inclusive (time == notAfter still valid), `crls` checked by tag only (`docs/grenzen.md`). A trust anchor without basicConstraints (X.509 v1) counts as a CA (the caller chose it); names are matched by a simplified RFC 5280 §7.1 rule to select issuer candidates only, the signature decides.
- **No revocation check, no name or path-length constraints, no policy check** (`docs/grenzen.md`). RSA-PSS and
  BER are refused; SHA-1 is accepted only as the certificate hash in the `signingCertificate` (v1) attribute, anywhere
  else it is refused.
- **The free services are not qualified** (eIDAS): limited legal weight. Terms of use read from public pages on
  2026-11-23, not legally checked, operators not asked: only FreeTSA allows general use explicitly (1 request/s per
  IP, so for the whole relay); Sectigo and DigiCert unclear; Certum probably needs a contract (`docs/dienste.md`).
- **Two of the four services answer over plain http only** (`digicert`, `certum`); the relay offers them only
  with `RELAY_ALLOW_PLAIN_HTTP=1`.
- **Anchors come from a Git for Windows certificate bundle and FreeTSA's page.** Compared on 2026-11-23 with public
  operator pages and the system trust store (network only; FreeTSA has no second source, Sectigo's download is
  http). The tests judge certificate validity at the stamped time, so the recorded answers stay valid after their
  certificates expire.
- **Relay (not rolled out, no image, no authentication towards a paid (qualified) service).** The relay knows no
  addresses: a reverse proxy with a connection and rate limit per address is mandatory for operation. Its server
  limits the open connections (256) and the time for a whole request, headers included (5 s) (`relay/limits.ts`).
  The counters are global (all services, each service) and per key id; they live in memory only. With the shipped
  services (4 requests per minute each at 15 s, 12 for FreeTSA at 5 s: 24 together) one valid key with 4 requests per
  minute locks a service for all other keys: there is no fairness per key at a service's budget. `perMinutePerKey` (20)
  can be reached by a key that uses several services (24 slots together); `perMinuteTotal` (60) is not reached with the
  shipped services (it bites only when the service limits add up to more). Counters cap
  future timestamps at `now` (a clock set back does not lock the budget). `refused` has `request-timeout` and
  `client-aborted`; the 408/431/400 answers of the server are closed hard after 1 s even if the client never reads;
  `nowMs` must be milliseconds >= 1e11 and < 1e15 (`signRelayRequest`: `ts` stays within the relay's 12 digits); key file errors name the entry index (`keys[i]`, no content).
- **Relay settings and behaviour since the final audit:** `RELAY_SERVICES` is mandatory (no default of "all services"; a
  plain-http service without `RELAY_ALLOW_PLAIN_HTTP=1` ends the start). The relay binds `127.0.0.1` unless `RELAY_HOST`
  is set (a container needs `RELAY_HOST=0.0.0.0`). Keep-alive depends on the binding: loopback 65 s (a proxy on the
  same host), any other binding 5 s; `RELAY_KEEPALIVE_MS` (1000 to 120000) overrides both; with a non-loopback binding
  the proxy owns the per-address connection limits, and a proxy on another host with an idle timeout above 5 s needs a
  larger `RELAY_KEEPALIVE_MS`. CORS exposes `Retry-After` and `Date` (clock offset recipe in `docs/relay.md`: on a 401
  read `Date`, correct once). The relay checks `genTime` within ±60 s around the request (`genTimeSlackMs`, replaces
  `maxSkewMs`).
- **Ending and PORT (audit 2):** after `server.close()` Node no longer enforces the header and request deadlines, so ending
  (`SIGTERM`, `restartAfter`) closes all connections after `shutdownGraceMs` (2 s; a request still in flight is cut then) and
  exits with 0 after `shutdownHardMs` (10 s) whatever is open (`stopServer` in `relay/main.ts`, `docs/relay.md`). `PORT` is
  read like the other numbers (decimal digits, 1 to 65535; `0x50`, `1e2`, blanks, empty and `0` end the start).
- **Freshness and long-term value (library):** freshness is checked only with `minGenTime` (`time-too-old`); without it a
  back-dated token from an expired service key passes. `at` is checked in addition to `genTime`. The result has
  `signerNotBefore`/`signerNotAfter`: the evidence weakens when the signer certificate expires or its key is
  compromised (re-stamp in time, use several services). ESSCertIDv2 refuses SHA-1 and unknown hash OIDs. A leap second
  in `genTime` stays `bad-time`. `signRelayRequest` also takes a `CryptoKey`.
- **The shipped anchors are roots:** any time stamping certificate in the hierarchy passes, also one of another
  operator; narrower trust is the caller's choice (an intermediate or the signer as anchor).
- **Batch mode (collecting operation, optional, off by default):** `RELAY_BATCH_MS` (1000 to 60000) collects the hashes of
  one window per service into a Merkle tree with blinded leaves and stamps only the root (the service never sees a
  single hash); `RELAY_BATCH_MAX` (2 to 1024, default 128) caps a window. The start refuses a window shorter than
  `minIntervalMs` of a chosen service. The app checks the answer with `verifyBatchedTimestamp` (`src/lib/batch.ts`):
  imprint = binding of version, size and root. Latency grows by the window (proxy and client timeouts at least window
  - 17 s). Not yet security-reviewed by a human.
- **Key types and solo stamps (collecting operation only):** a key file entry may carry `"solo": true` (type 2, only the
  owner hands them out); the signed JSON body may carry `"mode": "solo"` (bound by the signature; other values `bad-mode`)
  for a direct stamp without a tree (PDF document time stamps). Type 2 always (within limits), type 1 only when nobody else
  waits for the service, else `403 solo-not-allowed`. Planner per service: a solo stamp takes a whole slot, solo and
  window alternate, waiting only on a short squeeze (`RELAY_MAX_WAIT_MS`, 1000 to 60000, default 30000, then `503 busy`;
  a slot later than that is the old `429`), solo queue limited (`soloQueueMax` 6), own solo limit per key
  (`soloPerMinutePerKey` 4, memory only, no per-key numbers in the log). The key file is read again every 5 s and compared
  by the SHA-256 of its content (a change is found even when mtime, size and inode stay the same; a removed key is invalid
  from the next look on, at most 5 s after the file is saved; invalid file keeps the old set, `keyReloadFailed`). Only a
  plain file of at most 64 KiB is read (no FIFO, device, directory; a symlink is followed), and the write-permission
  warning is repeated at every look (once per change of state, `keyFileWritable`); `restartAfter` (Unix seconds) ends the relay once
  cleanly (supervisor needed; the relay never writes the file; a restart empties the replay cache). A solo key in browser
  storage is readable by that browser's users. Tested against stubs only (`tests/solo.test.ts`); `perMinuteTotal` and
  `perMinutePerKey` unchanged. Slots are the sliding-minute budget of the service (`60000 / minIntervalMs` per minute), not fixed time slots,
  and a slot is booked at the time of the STAMP (a window holds its slot from opening on, booked for opening plus window
  length, or the real time when it closes full), so the service never sees more than that many calls in any sliding
  minute, mixed window and solo operation included. There is still no minimum spacing between two stamps (open decision of the owner).
- **Credentials of paid services (optional; `auth` in `services.json`, none for the four free ones):** `kind` none, basic,
  bearer or header (header name strict, no forbidden or hop-by-hop name), `source` relay, client or either; credentials
  only for https addresses (reader, relay start and `relay/upstream.ts` each refuse http). The signed body may carry
  `upstream` (`{user,password}` or `{token}`, printable ASCII, no CR/LF, no colon in the basic user, limits in
  `relay/limits.ts`), else `400 bad-upstream`; the relay's own come from `RELAY_UPSTREAM_AUTH_<ID>` (never logged).
  Windows, slots, queues and the service budget count per (service, identity), the identity being a SHA-256 digest in
  memory only (never output, logged or counted); at most 64 identities per service, then `503 busy`; `perMinuteTotal` and
  `perMinutePerKey` count every request as before. Code: `relay/credentials.ts`. Only against stubs (`tests/upstream-auth.test.ts`,
  `tests/upstream-network.test.ts`, a TLS stub); credentials in browser storage are readable by that browser's users; no
  IP-allow-list or certificate services (`docs/relay.md`).
- **Token content rules (`tests/tstinfo.test.ts`, `tests/rsa-bits.test.ts`, `tests/batch-vectors.test.ts`):** the `tsa` field of
  the TSTInfo must name the signer (subject or an entry of the same kind in the subjectAltName, else `tsa-mismatch`;
  `dNSName` ignores ASCII case, every other kind compares bytes; the four recorded answers pass). The TSTInfo is read
  as the schema (fixed order, each field once, accuracy parts in order, millis/micros 1 to 999, no explicit `ordering`
  FALSE, non-empty extensions, else `bad-tst-info`). `minRsaBits` (default 2048, 0 = off) refuses a smaller RSA key in
  the signer and the chain, trust anchors exempt (`weak-key`). Stricter than OpenSSL there (it accepts RSA-512 and the
  odd TSTInfo shapes), looser only for `dNSName` case. Every measured difference is a row of `tests/openssl.test.ts`
  and of the table in `docs/grenzen.md`. Not built, listed there: pathLen and name
  constraints, Brainpool/Ed25519. `rootFromPath` is exported for the published RFC 6962 vectors only.
- **Signer named by `subjectKeyIdentifier` (F4, `tests/ski-signer.test.ts`, rows in `tests/openssl.test.ts`):** a SignerInfo is
  version 1 with `issuerAndSerialNumber` or version 3 with `[0]` IMPLICIT OCTET STRING (1 to 64 bytes, else
  `bad-structure`); another version or a form that does not fit the version is `unsupported-version`. The SignedData
  version stays 3 for both (the content is a TSTInfo). `readToken` gives `signer.sid` (`kind`), `Certificate` has
  `subjectKeyIdentifier` (an unreadable or doubled extension makes the certificate unreadable). A certificate without
  the extension is never found: the identifier is never computed from the key (OpenSSL does the same, measured). Several
  certificates with the same identifier: the one the `signingCertificate(V2)` hash names is taken (at most 16 hashes,
  one signature check); with issuer and serial the first match still wins (F8). `ts -verify` cannot read the form at all,
  so the comparison is `cms -verify` (it takes the first match and ignores the version). Measured only with own tokens
  and one written by `openssl cms -sign -keyid` (no signing certificate attribute, so it stops at
  `signing-certificate-missing`), not with a real service.
- **Relay authentication: not security-reviewed by a human, tested in Chromium only (audit script of 2026-11-24, not in the repo;
  the checked-in browser check of 2026-11-23 ran with `keys: 'off'`).** A private key in a web
  app is readable by that page's visitors: it keeps out other apps and scripts, not the users of the page. No key
  rotation. Anyone who can write the key file can add a key. Replay cache (digest of the signed message, at most
  180 entries by the limits) and counters live in memory only (empty after a restart; a head with `ts` from the start on, up to +60 s when the app clock runs ahead, can be replayed after a restart until its window ends, i.e. up to 120 s after the relay start: `ts` <= start + 60 s plus the 60 s window; the replay cache is empty then; no code fix); client and relay clocks
  must agree within ±60 s.
- **Reader rules after the audit of 2026-11-24 (`tests/strict-readers.test.ts`, `tests/reader-input.test.ts`, `tests/openssl-interop.test.ts`: 40 tokens
  written by `openssl ts -reply` must still be read and verified):** a SEQUENCE of fixed shape has exactly its elements
  (`EncapsulatedContentInfo`, `issuerAndSerialNumber`, an Attribute, an AttributeTypeAndValue of a name: `bad-structure`,
  in a name: unreadable). `readTimestampResponse`, `readToken` and `parseCertificate` copy their input first (by length,
  at most 262144 bytes, another realm allowed): nothing they return points into the caller's buffer. A bad `accuracy` or
  `ordering` is `bad-tst-info`; `verifyBatchedTimestamp` answers a hostile input object with `bad-options`. An empty or
  unreadable subjectAltName of the signer is read only when `tsa` needs it (decision: not rejected otherwise; the rules
  that are deliberately stricter than OpenSSL and may cost availability are listed in `docs/grenzen.md`).
- **Package and build:** the package holds `dist`, `services.json` and `anchors` (plus README, LICENSE, `package.json`);
  the relay and the tools need a clone. `prepare` builds on a Git install (an install without typescript builds no
  `dist`; a type error makes `prepare` fail loudly); `exports` has `./services.json` and `./anchors/*.pem`; the CI
  actions are pinned by tag, not by SHA. Tests with files use `mkdtemp`; git-dependent tests are skipped visibly; the
  openssl comparison uses `-attime` and needs OpenSSL 3+ (visible skip otherwise). `accuracyMs` may have fractions.
  Certificate times are read without a fraction (`bad-time`), `genTime` keeps up to 9 digits and is cut to
  milliseconds.
- Fixtures are real tokens of 2026-11-23; if a service rotates its certificates, new fixtures must be recorded:
  `scripts/make-request.ts` writes only the request (.tsq); the answer (.tsr) is fetched from the service (the old
  fixtures stay valid for the tests).
- Not on npm; consumers take it by Git tag (none yet).

_Last updated: 2026-11-24 (F4 signer by subjectKeyIdentifier; mandatory RELAY_SERVICES, Date exposed, anchors are roots; final audit findings 1-4, 7, 10-12: generation time freshness, signer validity, `at`, ESSCertIDv2, CryptoKey; run 17: named signature OID must match the digest algorithm; run 16: v1 anchors, simplified name matching, unreadable extra certificates skipped; run 7: inputs copied by length never iterated, `trust` at most 64 anchors, token in a SharedArrayBuffer verifies, start rule: `startMs` only ever falls (lowered on every request), heads from before it are refused, `signRelayRequest` never throws; round 5: honest "never throws" statement, hostile proxies, `trust` must be an array, chain search cut short by a limit always `untrusted-chain`, mutation guards, README/FEATURES aligned with the ECDSA authentication)_
