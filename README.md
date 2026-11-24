# Zeitstempel

Zeitstempel nach RFC 3161 für Web-Anwendungen: Eine App will beweisen können, dass ein Hash (zum Beispiel
der einer Datei) **spätestens zu einem bestimmten Zeitpunkt** existierte. Dazu holt sie ein signiertes Token
bei einem Zeitstempel-Dienst und prüft es.

**Stand: 0.1.0, Entwurf, nicht auf npm, nicht von einem Menschen sicherheitsgeprüft.** Die Bibliothek ist unter
Node 24 getestet, **nicht in einem Browser**.

## Bausteine

| Baustein                                      | Was er tut                                                                                                                                                                               |
| --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Bibliothek** (`src/`)                       | Anfrage bauen, Antwort strikt lesen, Token prüfen (Abdruck, Nonce, Signatur, Zertifikatskette gegen übergebene Anker). Läuft in Browser und Node, ohne Netzzugriff, ohne Abhängigkeiten. |
| **Dienstliste** (`services.json`, `anchors/`) | Vier freie Dienste als Daten, mit Vertrauensankern, Bedingungen und Messung (`docs/dienste.md`). Ein qualifizierter Dienst ist eine Vorlage ohne Zugangsdaten.                           |
| **Relay-Client** (`src/lib/client.ts`)        | `createRelayClient`: fragt das Relay (`fetch` und monotone Uhr werden übergeben), prüft das Token selbst, hält die Pause nach 429 ein. Siehe `docs/relay.md`.                            |
| **Relay** (`relay/`)                          | Kleiner Server, der nur Hashes an feste Dienste weiterreicht, weil Browser die Dienste wegen CORS nicht direkt erreichen. Nicht ausgerollt.                                              |
| **Werkzeuge** (`scripts/`)                    | `npm run spike` (eine Anfrage je Dienst, Prüfung doppelt), `npm run probe` (eine Anfrage über das Relay).                                                                                |

## Benutzen

```ts
import { buildTimestampRequest, readTimestampResponse, verifyTimestampToken } from 'zeitstempel';

const request = buildTimestampRequest(sha256, nonce); // DER-Bytes für den Dienst (oder das Relay macht das)
const response = readTimestampResponse(answerBytes); // { ok, value: { status, token, info } }
const verified = await verifyTimestampToken(token, sha256, [anchorPem], { expectedNonce: nonce });
// { ok: true, value: { genTime: '2026-11-23T13:05:56.000Z', signer, chainLength, … } }
```

Die Funktionen werfen nie; Fehler sind Codes (`{ ok: false, reason }`). Alles Weitere steht in
[`docs/data-model.html`](docs/data-model.html) (Funktionen, Strukturen, Fehlercodes),
[`docs/grenzen.md`](docs/grenzen.md) (was nicht geprüft wird), [`docs/dienste.md`](docs/dienste.md)
(Dienste, Messung, Bedingungen) und [`docs/relay.md`](docs/relay.md).

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
