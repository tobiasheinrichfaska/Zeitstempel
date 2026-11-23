# Zeitstempel

Zeitstempel nach RFC 3161 für Web-Anwendungen: Eine App will beweisen können, dass ein Hash (zum Beispiel
der einer Datei) **spätestens zu einem bestimmten Zeitpunkt** existierte. Dazu holt sie ein signiertes Token
bei einem Zeitstempel-Dienst und prüft es.

**Stand: 0.1.0, Entwurf, nicht auf npm, nicht von einem Menschen sicherheitsgeprüft.** Die Bibliothek ist unter
Node 24 getestet; im Browser **einmal in Headless-Chromium geprüft (ohne die Relay-Authentifizierung), sonst nicht getestet**.

## Bausteine

| Baustein                                      | Was er tut                                                                                                                                                                                                                                                                                                 |
| --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Bibliothek** (`src/`)                       | Anfrage bauen, Antwort strikt lesen, Token prüfen (Abdruck, Nonce, Signatur, Zertifikatskette gegen übergebene Anker). Läuft in Browser und Node, ohne Netzzugriff, ohne Abhängigkeiten.                                                                                                                   |
| **Dienstliste** (`services.json`, `anchors/`) | Vier freie Dienste als Daten, mit Vertrauensankern, Bedingungen und Messung (`docs/dienste.md`). Ein qualifizierter Dienst ist eine Vorlage ohne Zugangsdaten.                                                                                                                                             |
| **Relay** (`relay/`)                          | Kleiner Server, der nur Hashes an feste Dienste weiterreicht, weil Browser die Dienste wegen CORS nicht direkt erreichen. Jede Anfrage ist mit ECDSA P-256 signiert (Kopf `X-Zeitstempel-Auth`, in der App mit `signRelayRequest` berechnet; das Relay kennt nur öffentliche Schlüssel). Nicht ausgerollt. |
| **Werkzeuge** (`scripts/`)                    | `npm run spike` (eine Anfrage je Dienst, Prüfung doppelt), `npm run probe` (eine Anfrage über das Relay), `scripts/make-key.ts` (neues Schlüsselpaar für das Relay, nur auf dem Terminal).                                                                                                                 |

## Benutzen

```ts
import { buildTimestampRequest, readTimestampResponse, verifyTimestampToken } from 'zeitstempel';

// sha256: Uint8Array mit 32 Byte. nonce: 1 bis 16 Zufallsbytes, aufheben (für die Prüfung nötig).
const nonce = crypto.getRandomValues(new Uint8Array(8));
const request = buildTimestampRequest(sha256, nonce); // DER-Bytes für den Dienst (oder das Relay macht das)
// request per HTTP POST an die Adresse des Dienstes senden (Content-Type: application/timestamp-query);
// der Körper der Antwort ist answerBytes (ein Uint8Array). Browser erreichen die Dienste meist nicht (CORS): Relay.
const response = readTimestampResponse(answerBytes); // { ok, value: { status, token, info } }
if (!response.ok) throw new Error(response.reason);
const verified = await verifyTimestampToken(response.value.token, sha256, [anchorPem], {
  expectedNonce: nonce,
  now: new Date(), // ohne `now` wird nicht gegen die Zukunft geprüft
});
// { ok: true, value: { genTime: '2026-11-23T13:05:56.000Z', signer, chainLength, … } }
```

`verified.ok` heißt: „Dienst X bestätigt, dass dieser Hash spätestens zu `genTime` existierte“ – wenn man dem Anker
traut. Der Stempel ist **nicht qualifiziert**, es gibt **keine Sperrprüfung**, und die Anker bestimmt der
Aufrufer (`docs/grenzen.md`). Das Token muss `Uint8Array` sein: Text statt Bytes ergibt `malformed`. `genTime` ist
im Ergebnis der Prüfung (und in der Antwort des Relays) ein ISO-Text, in `response.value.info` dagegen eine Zahl
(Millisekunden seit 1970).

Über das Relay (Browser): die Anfrage wird mit dem privaten Schlüssel der App signiert; das Token prüft die App selbst.

```ts
import { fromBase64Url, signRelayRequest, toBase64Url } from 'zeitstempel';

const path = '/v1/stamp/freetsa';
const body = new TextEncoder().encode(JSON.stringify({ hash: toBase64Url(sha256) }));
const auth = await signRelayRequest({
  privateKey,
  keyId: 'app-1',
  method: 'POST',
  path,
  body,
  nowMs: Date.now(), // Millisekunden, nicht Sekunden
});
if (!auth.ok) throw new Error(auth.reason);
const res = await fetch(relayUrl + path, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'X-Zeitstempel-Auth': auth.value },
  body,
});
const token = fromBase64Url((await res.json()).token); // 200 { service, genTime, accuracyMs, serial, token }
// das Token danach mit verifyTimestampToken prüfen (ohne expectedNonce: die Nonce wählt das Relay)
```

Der private Schlüssel (PKCS#8-Bytes, mit `scripts/make-key.ts` erzeugt) gehört in die App; in einer Web-App ist er für die
Besucher der Seite lesbar. Das Relay und die Werkzeuge (`relay/`, `scripts/`) sind **nicht im Paket** (nur Bibliothek,
Dienstliste und Anker): dafür das Repository klonen. Einzelheiten und „Lokal testen“ in [`docs/relay.md`](docs/relay.md).

Die Kernfunktionen (`buildTimestampRequest`, `readTimestampResponse`, `verifyTimestampToken`, `readServices`,
`signRelayRequest`) werfen bei keiner gewöhnlichen Eingabe (gegen feindliche `Proxy`-Objekte sind `buildTimestampRequest`, `verifyTimestampToken`, `equalBytes` und `signRelayRequest` abgesichert und getestet); Fehler sind Codes (`{ ok: false, reason }`). Die Bausteine
`readToken`, `parseCertificate` und `parsePemCertificates` werfen dagegen einen `ReaderError`, und die
Byte-Helfer `toBase64`, `toBase64Url` und `toHex` einen `TypeError` bei falschem Typ (beides ist so
dokumentiert). Bytes aus einem anderen Realm (iframe, Worker) bitte als `new Uint8Array(x)` übergeben. Alles Weitere steht in
[`docs/data-model.html`](docs/data-model.html) (Funktionen, Strukturen, Fehlercodes),
[`docs/grenzen.md`](docs/grenzen.md) (was nicht geprüft wird), [`docs/dienste.md`](docs/dienste.md)
(Dienste, Messung, Bedingungen) und [`docs/relay.md`](docs/relay.md).

## Installieren

Nicht auf npm. Es gibt noch **keinen Git-Tag**; sobald einer existiert, wird die Bibliothek so eingebunden (Tag
und Adresse des Repositories sind dann einzusetzen):

```bash
npm install git+https://<adresse-des-repositories>#<tag>
```

Beim Installieren aus Git führt npm das Skript `prepare` aus (`scripts/prepare.mjs`: baut `dist/`, wenn das
mitinstallierte `typescript` da ist, und überspringt den Bau sonst mit einer Zeile auf stderr). Das Paket ist ESM-only (`import`), Node 24 oder ein Browser-Bündler.

Außer dem Einstieg (`import … from 'zeitstempel'`) liefert das Paket die Daten für die Anwendung über `exports`:

- `zeitstempel/services.json`: die Dienstliste (JSON; mit `readServices` lesen). Zum Beispiel
  `import services from 'zeitstempel/services.json' with { type: 'json' }` oder mit dem Bündler.
- `zeitstempel/anchors/<name>.pem`: die Vertrauensanker (PEM-Text, Namen in `services.json` unter `anchors`). Eine
  `.pem`-Datei ist kein JavaScript-Modul: als Text laden (Bündler: `?raw`; Node: Pfad mit
  `createRequire(import.meta.url).resolve('zeitstempel/anchors/freetsa-root.pem')` auflösen und lesen). Welchen Anker
  die App vertraut, entscheidet sie selbst (siehe `docs/dienste.md`).

## Entwickeln

```bash
npm install
npm run typecheck
npm run lint
npm test
npm run build
```

## License

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

This project is licensed under the **GNU Affero General Public License v3.0** (AGPLv3).
You are free to use, modify, and distribute this software under the terms of the AGPLv3.
If you use this software to provide a network service, you must make the full source code
of your modifications available to users of that service.

**Commercial License:** If you wish to use this software in a closed-source or proprietary
product, a commercial license is available. Contact: tobias.a.w.heinrich@gmail.com

See [LICENSE](LICENSE) for the full AGPLv3 text.
See [LICENSE_COMMERCIAL.md](LICENSE_COMMERCIAL.md) for commercial licensing terms.
