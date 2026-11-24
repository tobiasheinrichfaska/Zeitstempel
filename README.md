# Zeitstempel

Zeitstempel nach RFC 3161 für Web-Anwendungen: Eine App will beweisen können, dass ein Hash (zum Beispiel
der einer Datei) **spätestens zu einem bestimmten Zeitpunkt** existierte. Dazu holt sie ein signiertes Token
bei einem Zeitstempel-Dienst und prüft es.

**Stand: 0.1.0, Entwurf, nicht auf npm, nicht von einem Menschen sicherheitsgeprüft.** Die Bibliothek ist unter
Node 24 getestet; im Browser nur in **Headless-Chromium 157** geprüft, am 2026-11-24 einschließlich Relay-Anmeldung, CORS-Preflight, Sammelbetrieb, Solo-Stempel und den vier Fixtures (47 Prüfungen ohne Unterschied zu Node; das Prüfskript liegt nicht im Repo). **Firefox und Safari nicht geprüft.**

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
const sentMs = Date.now(); // vor dem Senden merken
// ... Anfrage senden, Antwort lesen (readTimestampResponse) ...
const verified = await verifyTimestampToken(response.value.token, sha256, [anchorPem], {
  expectedNonce: nonce,
  now: new Date(), // ohne `now` wird nicht gegen die Zukunft geprüft
  minGenTime: new Date(sentMs - 60_000), // ohne `minGenTime` wird die Frische NICHT geprüft (Rückdatierung möglich)
});
// { ok: true, value: { genTime: '2026-11-23T13:05:56.000Z', signer, chainLength, … } }
```

`verified.ok` heißt: „ein Zeitstempel-Zertifikat unter dem übergebenen Anker bestätigt, dass dieser Hash spätestens zu
`genTime` existierte“ – wenn man dem Anker traut (welcher Betreiber dahinter steht, sagt die Prüfung nicht). Die Aussage
über die **Zeit** gilt nur mit `minGenTime`: ohne sie wird nicht geprüft, wie alt das Token ist, und ein Dienst mit
abgelaufenem oder gestohlenem Schlüssel könnte rückdatieren (`docs/grenzen.md`). Das Ergebnis nennt auch
`signerNotAfter`: nach diesem Zeitpunkt oder bei Kompromittierung des Dienstschlüssels verfällt die Beweiskraft
(rechtzeitig neu stempeln, mehrere Dienste; `docs/grenzen.md`, „Langzeitaussage“). Der Stempel ist **nicht qualifiziert**, es gibt **keine Sperrprüfung**, und die Anker bestimmt der
Aufrufer (`docs/grenzen.md`). **Die mitgelieferten Anker sind Wurzeln:** die Prüfung akzeptiert jedes
Zeitstempel-Zertifikat, das unter dem übergebenen Anker steht, auch das einer anderen Zeitstempel-Stelle derselben
Hierarchie. „Dienst X hat bestätigt“ ist also stärker als das Geprüfte. Wer enger vertrauen will, übergibt selbst eine
Zwischen-CA oder das Zertifikat des Signierers als Anker (für einen Anker gilt die Ausnahme in `docs/grenzen.md`).
Die Prüfung ist streng: Das Feld `tsa` des Tokens muss zum Zeitstempel-Zertifikat passen (`tsa-mismatch`), der Inhalt des
Tokens wird als Schema gelesen (`bad-tst-info`), und ein RSA-Schlüssel unter 2048 Bit im Zeitstempel-Zertifikat oder in
der Kette (`weak-key`; Anker ausgenommen) wird abgelehnt. Die Option `minRsaBits` (Zahl, Vorgabe 2048, 0 schaltet aus)
ändert die Grenze. Wo das strenger oder lockerer ist als `openssl ts -verify`: `docs/grenzen.md`, Tabelle „Abgleich
mit OpenSSL“. Der Unterzeichner darf im Token über Aussteller und Seriennummer (Version 1) oder über den
`subjectKeyIdentifier` seines Zertifikats (Version 3) genannt sein; ein Zertifikat ohne diese Erweiterung wird auf dem
zweiten Weg nie gefunden (`docs/grenzen.md`, „Unterzeichner über `subjectKeyIdentifier`“; getestet nur mit eigenen
Token und einem von OpenSSL geschriebenen, nicht mit einem echten Dienst).
Das Token muss `Uint8Array` sein: Text statt Bytes ergibt `malformed`. `genTime` ist
im Ergebnis der Prüfung (und in der Antwort des Relays) ein ISO-Text, in `response.value.info` dagegen eine Zahl
(Millisekunden seit 1970).

Über das Relay (Browser): die Anfrage wird mit dem privaten Schlüssel der App signiert; das Token prüft die App selbst.

```ts
import { fromBase64Url, signRelayRequest, toBase64Url } from 'zeitstempel';

// `scripts/make-key.ts` druckt den privaten Schlüssel als base64url-TEXT; `signRelayRequest` will die Bytes.
// `privateKeyText` ist Zeile 1 der Ausgabe von make-key, ohne Zeilenumbruch (daher `.trim()`).
const privateKey = fromBase64Url(privateKeyText.trim()); // null bei ungültigem Text
if (!privateKey) throw new Error('privateKeyText is not base64url');
const path = '/v1/stamp/freetsa';
const sentMs = Date.now(); // merken: für `minGenTime` der Prüfung unten
const body = new TextEncoder().encode(JSON.stringify({ hash: toBase64Url(sha256) }));
const auth = await signRelayRequest({
  privateKey,
  keyId: 'app-1',
  method: 'POST',
  path,
  body,
  nowMs: sentMs, // Millisekunden, nicht Sekunden
});
if (!auth.ok) throw new Error(auth.reason);
const res = await fetch(relayUrl + path, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'X-Zeitstempel-Auth': auth.value },
  body,
});
const token = fromBase64Url((await res.json()).token); // 200 { service, genTime, accuracyMs, serial, token }
// das Token danach mit verifyTimestampToken prüfen (ohne expectedNonce: die Nonce wählt das Relay), und zwar mit
// { now: new Date(), minGenTime: new Date(sentMs - 60_000) }, sonst ist die Frische nicht geprüft
```

Der private Schlüssel (PKCS#8-Bytes, mit `scripts/make-key.ts` erzeugt, oder ein nicht extrahierbarer `CryptoKey`) gehört in die App. `make-key` druckt ihn als
base64url-Text auf das Terminal (im Beispiel oben macht `fromBase64Url` daraus die Bytes). In einer Web-App ist er für die
Besucher der Seite lesbar. Das Relay und die Werkzeuge (`relay/`, `scripts/`) sind **nicht im Paket** (nur Bibliothek,
Dienstliste und Anker): dafür das Repository klonen. Einzelheiten und „Lokal testen“ in [`docs/relay.md`](docs/relay.md).

**Sammelbetrieb (Betriebsart des Relays, Vorgabe aus):** Mit `RELAY_BATCH_MS` sammelt das Relay die Hashes eines Fensters in
einem Merkle-Baum und lässt den Dienst **einen** Stempel für alle geben (hält die Grenzen der Dienste ein, die Antwort
kommt nach dem Fenster). Die Antwort trägt dann zusätzlich `batch` (`salt`, `index`, `size`, `path`); die App prüft sie mit
`verifyBatchedTimestamp({ token, hash, batch }, [ankerPem], { now, minGenTime })` und bewahrt Token und Beleg mit dem Hash
auf. Das ist **kein Einzelstempel** auf den Hash, und das Relay sieht alle Hashes; Einzelheiten in
[`docs/relay.md`](docs/relay.md) („Sammelbetrieb“) und [`docs/grenzen.md`](docs/grenzen.md).

**Schlüsselarten und Solo-Stempel (nur im Sammelbetrieb):** Ein Schlüssel der Art 2 (`"solo": true` in der Schlüsseldatei,
nur vom Eigentümer vergeben) darf `{"hash": "…", "mode": "solo"}` senden und bekommt einen **direkten** Stempel des Hashes
ohne Baum (nötig für PDF-Dokumentzeitstempel; die Antwort hat kein `batch`). Art 1 wartet die volle Sammeldauer im
Fenster und bekommt den direkten Stempel nur, wenn es dort allein ist (sonst `403 solo-not-allowed`, das Budget ist dann
verbraucht). Ist kein Platz beim Dienst frei, wartet die Anfrage höchstens
`RELAY_MAX_WAIT_MS` (Vorgabe 30 s), danach `503 busy`. Die Schlüsseldatei wird laufend neu gelesen (Sperren = Eintrag
entfernen); `restartAfter` beendet das Relay einmal sauber (Prozess-Überwacher nötig). Einzelheiten in
[`docs/relay.md`](docs/relay.md) („Schlüsselarten und Solo-Stempel“); Solo-Schlüssel im Browserspeicher sind für die
Nutzer dieses Browsers auslesbar.

**Zugangsdaten zu bezahlten Diensten (optional, nur für Dienste mit `auth` in `services.json`; die vier freien Dienste
brauchen nichts):** Die App darf die Zugangsdaten (`basic`: Benutzer und Passwort, `bearer` oder ein Namenskopf: ein Token)
selbst im signierten Körper mitliefern (`{"hash": "…", "upstream": {…}}`), oder das Relay hält sie
(`RELAY_UPSTREAM_AUTH_<ID>`); je Dienst legt `auth.source` (`relay`, `client`, `either`) fest, wer liefert. Streng geprüft
(`400 bad-upstream`), nur nach `https`, nie in Protokoll, Zählern oder Fehlern. Im Sammelbetrieb gelten Fenster, Plätze und
Dienstbudget je (Dienst, Zugangsdaten-Identität), nie gemischt; höchstens 64 Identitäten je Dienst (`503 busy`). Zugangsdaten
im Browserspeicher sind für die Nutzer dieses Browsers auslesbar. Nicht für Dienste mit IP-Freigabe oder Zertifikat.
Einzelheiten in [`docs/relay.md`](docs/relay.md) („Zugangsdaten zu bezahlten Diensten“); nur gegen Stubs getestet.

Betriebshinweise (Einzelheiten im Abschnitt „Betrieb hinter einem Reverse-Proxy“ von `docs/relay.md`): Das Relay und der Dienst
sehen den **Hash**; bei ratbarem Inhalt einen gesalzenen Hash oder eine Merkle-Wurzel stempeln (oder den Sammelbetrieb nutzen). Jeder Dienst erlaubt nur
wenige Stempel je Minute für alle zusammen (mitgeliefert: 4 je Dienst, FreeTSA 12), auch ein Fehlschlag kostet davon; `/health` prüft
keinen Dienst; ein Anstieg von `upstream-invalid` in den Zählern ist ein Alarmzeichen. Die Dienste wählt der Betreiber ausdrücklich
(`RELAY_SERVICES`, Pflicht: ohne Angabe startet das Relay nicht; Bedingungen in `docs/dienste.md`). Das Relay lauscht ohne `RELAY_HOST`
nur auf `127.0.0.1` (ein Container braucht `RELAY_HOST=0.0.0.0`) und gehört hinter einen Reverse-Proxy.

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
mitinstallierte `typescript` da ist, und überspringt den Bau sonst mit einer Zeile auf stderr). **Ohne TypeScript** (z. B. `npm install --omit=dev`)
entsteht also kein `dist/`, und ein Import scheitert dann mit „Cannot find module …/dist/index.js“: Git-Installs brauchen
die devDependencies. Ein Fehler beim Bauen selbst (Typfehler) lässt `prepare` und damit die Installation laut scheitern. Das Paket ist ESM-only (`import`), Node 24 oder ein Browser-Bündler.

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
