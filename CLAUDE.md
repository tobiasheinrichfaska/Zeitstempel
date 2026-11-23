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
- **Never log what a request carries** (no address, hash, token, key id, MAC). Counters only.
- Nothing is published to npm, tagged, rolled out or deployed without Tobias' OK. No qualified service
  contract and no credentials ever in the repo.
- Every rule keeps its test; a verification rule is checked against `openssl ts -verify` where possible.

---

## Project Directory

| File/Folder                                                                                  | Purpose                                                                                                                                                                                                                                                                                                              |
| -------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CLAUDE.md`                                                                                  | Project documentation and conventions                                                                                                                                                                                                                                                                                |
| `README.md`                                                                                  | Short description (German), use, license section                                                                                                                                                                                                                                                                     |
| `FEATURES_REQUIRED.md`                                                                       | Critical paths the audit validates                                                                                                                                                                                                                                                                                   |
| `docs/data-model.html`                                                                       | Self-contained reference: structures, functions, error codes, limits (`tests/docs.test.ts` ties codes, limits and functions to the code)                                                                                                                                                                             |
| `docs/dienste.md`                                                                            | The services: measurement, anchors with fingerprints, terms of use (read from public pages, not legally checked), anchor comparison, what a stamp is worth, template for a qualified service                                                                                                                         |
| `docs/relay.md`                                                                              | Relay: settings, interface, error codes, limits (tied to the code by a test), what it sees                                                                                                                                                                                                                           |
| `docs/grenzen.md`                                                                            | What the verification checks and what it does NOT                                                                                                                                                                                                                                                                    |
| `manual_tests/`                                                                              | Human-tester instructions (terminal commands that need the network)                                                                                                                                                                                                                                                  |
| `src/index.ts`, `src/lib/index.ts`                                                           | Public entry                                                                                                                                                                                                                                                                                                         |
| `src/lib/der.ts`                                                                             | Strict bounded DER reader and the writers the request needs                                                                                                                                                                                                                                                          |
| `src/lib/oids.ts`                                                                            | OIDs and algorithm tables as data                                                                                                                                                                                                                                                                                    |
| `src/lib/x509.ts`                                                                            | Certificate reader, PEM bundles                                                                                                                                                                                                                                                                                      |
| `src/lib/request.ts`                                                                         | `buildTimestampRequest`                                                                                                                                                                                                                                                                                              |
| `src/lib/token.ts`                                                                           | Token (CMS SignedData over TSTInfo) and `readTimestampResponse`                                                                                                                                                                                                                                                      |
| `src/lib/verify.ts`                                                                          | `verifyTimestampToken`: imprint, nonce, signature, certificates, chain                                                                                                                                                                                                                                               |
| `src/lib/services.ts`                                                                        | `readServices`: strict reader of `services.json`                                                                                                                                                                                                                                                                     |
| `src/lib/auth.ts`                                                                            | `signRelayRequest`: the client side of the relay authentication (ECDSA P-256, WebCrypto only)                                                                                                                                                                                                                        |
| `relay/keys.ts`                                                                              | Strict reader of the key file (key ids and public keys)                                                                                                                                                                                                                                                              |
| `src/lib/bytes.ts`, `src/lib/result.ts`                                                      | Byte/base64 helpers; `Result`, `Reason` codes, `ReaderError`                                                                                                                                                                                                                                                         |
| `services.json`, `anchors/`                                                                  | The services as data and their trust anchors (PEM)                                                                                                                                                                                                                                                                   |
| `relay/relay.ts`                                                                             | The relay rules (`createRelay`), no I/O of its own                                                                                                                                                                                                                                                                   |
| `relay/upstream.ts`                                                                          | The one way out: POST to a service (TLS, no redirect, hard deadline, size cap)                                                                                                                                                                                                                                       |
| `relay/limits.ts`                                                                            | Every relay limit in one place                                                                                                                                                                                                                                                                                       |
| `relay/server.ts`, `relay/main.ts`, `relay/load.ts`                                          | HTTP server, start (settings from the environment), loading the data files                                                                                                                                                                                                                                           |
| `scripts/`                                                                                   | `spike.ts`, `probe.ts`, `make-request.ts`, `make-key.ts` (new key pair, stdout only), `clean-dist.mjs` (build starts from an empty dist), `fix-declarations.mjs`, `browser-check.mjs` (Chromium, by hand)                                                                                                            |
| `tests/`                                                                                     | `der`, `verify`, `hardening` (+ `token-builder`), `bytes`, `copy` (+ `copy-child`), `no-webcrypto`, `auth` (+ `auth-helpers`), `helpers.ts` (fixtures, hashes), `relay-keys`, `services-fixtures`, `openssl`, `relay`, `services`, `docs`, `coupling`; `fixtures/` = recorded answers of real services (public data) |
| `package.json`, `tsconfig*.json`, `eslint.config.js`, `vitest.config.ts`, `.prettierrc.json` | Toolchain                                                                                                                                                                                                                                                                                                            |
| `.github/workflows/tests.yml`                                                                | Check "Tests": typecheck, lint, format, tests, build                                                                                                                                                                                                                                                                 |
| `.gitattributes`, `.gitignore`                                                               | LF line endings; ignore rules                                                                                                                                                                                                                                                                                        |
| `SECURITY.md`                                                                                | How to report a vulnerability, status, limits                                                                                                                                                                                                                                                                        |
| `LICENSE`, `LICENSE_COMMERCIAL.md`, `CONTRIBUTING.md`                                        | AGPLv3 + commercial                                                                                                                                                                                                                                                                                                  |

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

- **Browser: checked once, in headless Chromium 157 only, without the relay authentication (`signRelayRequest` not run in a browser)** (2026-11-23, `node scripts/browser-check.mjs`, by
  hand, needs Playwright with Chromium, which is not a dependency): the four recorded tokens verify (ECDSA P-384
  and RSA-4096 signers), wrong hash / wrong anchor / changed bytes are refused, and a cross-origin call to the
  relay (preflight included) works. Firefox and Safari were not run. In an insecure context (plain http, not
  localhost) `crypto.subtle` is missing and verification answers `unsupported-signature`.
- **Strict by design (verification):** the signer must carry exactly one extended key usage,
  `id-kp-timeStamping` (critical by default). A critical extension this library does not know makes a chain
  certificate invalid (`bad-certificate`); a trust anchor is exempt (that is the caller's decision). Options are
  checked: `trust` must be an array and `options` omitted or a plain object (prototype `Object.prototype` or
  `null`; not a class instance, `Map`, array), `expectedNonce` a `Uint8Array` of 1 to 16 bytes,
  `requireCriticalEku` a boolean, `now`/`at` a real valid `Date`, `maxSkewMs` a number >= 0, otherwise `bad-options` (never a silently skipped check; only `undefined`
  means "not given"). A `Uint8Array` of another realm (iframe, worker, `vm`) is refused (`bad-hash` / `bad-options`; a token: `malformed`; the nonce of `buildTimestampRequest`: `bad-nonce`): pass `new Uint8Array(x)`; `readTimestampResponse` and `readToken` check no `instanceof` and accept such bytes. The chain search tries every signature-valid issuer candidate (bounded), so a look-alike
  certificate cannot block a valid token. A negative serial number makes a certificate unreadable (`malformed`).
  The relay's server limits the open connections (256) and the time for a whole request, headers included
  (5 s) (`relay/limits.ts`).
- **No revocation check, no name or path-length constraints, no policy check** (`docs/grenzen.md`). RSA-PSS,
  SHA-1 and BER are refused.
- **The free services are not qualified** (eIDAS): limited legal weight. Terms of use read from public pages on
  2026-11-23, not legally checked, operators not asked: only FreeTSA allows general use explicitly (1 request/s per
  IP, so for the whole relay); Sectigo and DigiCert unclear; Certum probably needs a contract (`docs/dienste.md`).
- **Two of the four services answer over plain http only** (`digicert`, `certum`); the relay offers them only
  with `RELAY_ALLOW_PLAIN_HTTP=1`.
- **Anchors come from a Git for Windows certificate bundle and FreeTSA's page.** Compared on 2026-11-23 with public
  operator pages and the system trust store (network only; FreeTSA has no second source, Sectigo's download is
  http). The tests judge certificate validity at the stamped time, so the recorded answers stay valid after their
  certificates expire.
- **The relay's counters are global and per key id** (it knows no addresses). Not rolled out, no image, no
  authentication towards a paid (qualified) service.
- **Relay authentication: not security-reviewed by a human, not tested in a browser** (the browser check of
  2026-11-23 ran without it; `scripts/browser-check.mjs` needs a key or `RELAY_AUTH=off`). A private key in a web
  app is readable by that page's visitors: it keeps out other apps and scripts, not the users of the page. No key
  rotation. Anyone who can write the key file can add a key. The relay knows no addresses: a reverse proxy with a connection and rate limit per address is mandatory for operation. `refused` has `request-timeout` and `client-aborted`. `prepare` builds on a Git install; `exports` has `./services.json` and `./anchors/*.pem`; the CI actions are pinned by tag, not by SHA. Counters cap future timestamps at `now` (a clock set back does not lock the budget); `refused` has `client-aborted`. Certificate times are read without a fraction (`bad-time`), `genTime` keeps up to 9 digits and is cut to milliseconds. Replay cache (digest of the signed message, at most
  180 entries by the limits) and counters live in memory only (empty after a restart; a head with `ts` from the start on, up to +60 s when the app clock runs ahead, can be replayed after a restart until its window ends, i.e. up to 120 s after the relay start: `ts` <= start + 60 s plus the 60 s window; the replay cache is empty then; no code fix); client and relay clocks
  must agree within ±60 s. `perMinutePerKey` 20 of `perMinuteTotal` 60: three keys can use up the total.
- Fixtures are real tokens of 2026-11-23; if a service rotates its certificates, new fixtures must be recorded
  with `scripts/make-request.ts` (the old ones stay valid for the tests).
- Not on npm; consumers take it by Git tag (none yet).

_Last updated: 2026-11-23 (run 7: inputs copied by length never iterated, `trust` at most 64 anchors, token in a SharedArrayBuffer verifies, start rule: `startMs` only ever falls (lowered on every request), heads from before it are refused, `signRelayRequest` never throws; round 5: honest "never throws" statement, hostile proxies, `trust` must be an array, chain search cut short by a limit always `untrusted-chain`, mutation guards, README/FEATURES aligned with the ECDSA authentication)_
