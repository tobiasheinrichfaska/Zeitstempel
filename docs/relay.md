# Relay

Ein kleiner Server, der **nur** Hashes an feste Zeitstempel-Dienste weiterreicht, weil Browser die Dienste
wegen CORS nicht direkt erreichen. Er läuft mit Node 24 und nur mit `node:`-Modulen; es gibt keine
Abhängigkeit zur Laufzeit. **Nicht ausgerollt:** es gibt kein Image und keine Einrichtung; das entscheidet
der Betreiber.

## Start

```bash
RELAY_ORIGINS=https://app.example npm run relay
```

| Einstellung              | Bedeutung                                                                                       | Vorgabe        |
| ------------------------ | ----------------------------------------------------------------------------------------------- | -------------- |
| `PORT`                   | Port                                                                                            | 8080           |
| `RELAY_ORIGINS`          | Browser-Herkünfte, durch Komma getrennt, genau `https://host[:port]` (oder `http://localhost…`) | keine          |
| `RELAY_ALLOW_PLAIN_HTTP` | `1` erlaubt Dienste, die nur über `http` antworten                                              | aus            |
| `RELAY_SERVICES`         | Kennungen der angebotenen Dienste, durch Komma getrennt                                         | alle passenden |

## Schnittstelle

| Anfrage                                                                                                                    | Antwort                                                                                       |
| -------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `POST /v1/stamp/<dienst>` mit `{"hash": "<base64url>"}` (`application/json`) oder 32 Rohbytes (`application/octet-stream`) | 200 `{service, genTime, accuracyMs, serial, token}`; `token` ist das Token (DER) in base64url |
| `GET /v1/services`                                                                                                         | Liste der angebotenen Dienste (Kennung, Name, `qualified`, Verwendungszweck)                  |
| `GET /health`                                                                                                              | `{ok: true, services: [...]}`                                                                 |
| `OPTIONS …`                                                                                                                | Vorabfrage (CORS) für die konfigurierten Herkünfte                                            |

### Formate

- **`hash`** ist der SHA-256 (32 Byte) als **base64url ohne Auffüllzeichen** (`=`), also 43 Zeichen. Der JSON-Körper
  hat genau ein Feld; Rohbytes gehen nur mit `Content-Type: application/octet-stream` (genau 32 Byte).
  Ein `charset`-Zusatz im `Content-Type` wird ignoriert. Mehr als 512 Byte Körper werden abgelehnt.
- **200:** `service` (Kennung), `genTime` (ISO 8601, UTC, mit Millisekunden, z. B. `2026-11-23T13:05:56.000Z`;
  die Zeit des Dienstes, sekundengenau), `accuracyMs` (ganze Zahl oder `null`), `serial` (Kleinbuchstaben-Hex),
  `token` (base64url ohne Auffüllzeichen, das Token als DER, so wie es `readToken`/`verifyTimestampToken` der
  Bibliothek erwarten).
- **`GET /v1/services`:** `{"services": [{"id", "name", "qualified", "intendedUse"}]}`. Die Reihenfolge ist die der Datei
  `services.json`; es gibt keine Vorgabe, die App wählt eine Kennung (eine Einstellung der App, nicht des Relays).
- **`GET /health`:** `{"ok": true, "services": ["<id>", …]}`.
- Alle Antworten sind JSON (`application/json; charset=utf-8`), auch Fehler. Das Relay benutzt keine Cookies
  und verlangt keine Anmeldung.

### Browser (CORS)

- Die App-Herkunft muss in `RELAY_ORIGINS` stehen, **genau** wie der Browser sie sendet (`https://app.example`,
  ohne Pfad, ohne Schrägstrich am Ende).
- Ein `POST` mit `Content-Type: application/json` (oder `application/octet-stream`) löst im Browser eine
  **Vorabfrage** aus. Antwort darauf: `204` mit `Access-Control-Allow-Origin: <die Herkunft>`,
  `Access-Control-Allow-Methods: GET, POST`, `Access-Control-Allow-Headers: Content-Type`,
  `Access-Control-Max-Age: 600`, `Vary: Origin`.
- Jede Antwort an eine erlaubte Herkunft (auch Fehler) trägt `Access-Control-Allow-Origin: <die Herkunft>`
  und `Access-Control-Expose-Headers: Retry-After` (sonst kann das Skript der Seite `Retry-After` nicht lesen).
  Es gibt keinen Platzhalter `*` und keine Anmeldedaten (`credentials`) im Browseraufruf.
- Eine **nicht erlaubte Herkunft** bekommt `403 origin-not-allowed` **ohne** `Access-Control-Allow-Origin`; der
  Browser zeigt der Seite dann nur einen Netzwerkfehler (`TypeError`), nicht den Code. Ebenso sieht die Seite bei
  `413` (Verbindung wird geschlossen) unter Umständen nur einen Netzwerkfehler. Aufrufer ohne `Origin`-Kopf
  (Skripte, `curl`) werden nicht eingeschränkt.
- Eine Seite über **`http`** (nicht `localhost`) hat in Browsern kein WebCrypto; die Prüfung liefert dann
  `unsupported-signature`. Die App sollte über `https` laufen.

### Die App als Client

1. Hash der Daten bilden (SHA-256, 32 Byte), `fetch(relay + '/v1/stamp/' + id, {method: 'POST', headers:
{'Content-Type': 'application/json'}, body: JSON.stringify({hash: toBase64Url(hash)})})`. Keine Anmeldedaten,
   kein `mode`-Zusatz nötig. Die Frist der App sollte **länger als 12 s** sein (das Relay wartet bis zu 10 s auf
   den Dienst).
2. Bei `200`: `fromBase64Url(body.token)` und `verifyTimestampToken(token, hash, [ankerPem…], {now})`
   **ohne** `expectedNonce` (die Nonce wählt das Relay, die App kennt sie nicht; die Bindung an den Hash
   prüft `imprint-mismatch`). Die Anker (`anchors/*.pem` des Dienstes aus `services.json`) liefert die App
   selbst mit; wem sie traut, entscheidet sie. `genTime` des Relays ist nur eine Anzeige: maßgeblich ist
   `value.genTime` der eigenen Prüfung.
3. Bei `429`: `Retry-After` (Sekunden) lesen und erst dann wieder fragen. Bei `502`/`504`/Netzwerkfehler: später
   noch einmal versuchen oder einen anderen Dienst nehmen; ein Fehlschlag ist kein Beweis für etwas.
4. Das Token (base64url-Text) zusammen mit Kennung des Dienstes und Hash aufbewahren; geprüft wird später
   mit denselben Mitteln, ohne das Relay.

Fehler sind `{"error": "<code>"}`; bei 502 mit `reason` aus der Prüfung:

| Status | Code                                                                            | Bedeutung                                                                      |
| ------ | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| 400    | `bad-hash`                                                                      | Hash nicht 32 Byte, ungültiges base64url, zusätzliche Felder, kein JSON-Objekt |
| 400    | `no-query`                                                                      | Abfragezeichenfolge (`?…`) ist nicht erlaubt                                   |
| 400    | `bad-request`                                                                   | Pfad ist keine gültige Adresse (z. B. `//`, `//[`)                             |
| 403    | `origin-not-allowed`                                                            | Aufruf aus einem Browser von einer nicht konfigurierten Herkunft               |
| 404    | `unknown-service`, `not-found`                                                  | Dienst oder Pfad nicht vorhanden                                               |
| 405    | `method-not-allowed`                                                            | `/v1/stamp/…` nur mit POST                                                     |
| 413    | `too-large`                                                                     | Körper über dem Limit (Verbindung wird geschlossen)                            |
| 415    | `unsupported-media-type`                                                        | weder JSON noch `application/octet-stream`                                     |
| 429    | `rate-limited`                                                                  | Limit erreicht; `Retry-After` in Sekunden                                      |
| 500    | `internal`                                                                      | Unerwarteter Fehler im Relay (ohne Einzelheiten nach außen)                    |
| 502    | `upstream-failed`, `upstream-too-large`, `upstream-refused`, `upstream-invalid` | Dienst nicht erreichbar, zu große oder unpassende Antwort, ungültiges Token    |
| 504    | `upstream-timeout`                                                              | Dienst antwortete nicht rechtzeitig                                            |

## Was das Relay prüft

- **Kein offener Proxy:** Der Aufrufer nennt nur die Kennung eines Dienstes aus `services.json`. Adresse,
  Anfrage und Nonce baut das Relay selbst. Der Aufrufer kann nichts in die Anfrage einschleusen, außer dem
  Hash.
- **Die Antwort wird geprüft**, bevor sie weitergegeben wird: Hash, Nonce, Signatur, Kette zu den Ankern des
  Dienstes, Zeit nicht in der Zukunft. Die App kann (und soll) das Token mit der Bibliothek selbst noch
  einmal prüfen; sie muss dem Relay nicht vertrauen.
- Keine Weiterleitungen, TLS-Zertifikate nach Node-Vorgabe, harte Frist für den ganzen Aufruf, Größenlimit.
- `Cache-Control: no-store`, `Vary: Origin`, `X-Content-Type-Options: nosniff`.

## Was das Relay sieht

Zeitpunkt und Netzadresse des Aufrufers (wie jeder Server) und den **Hash**, nie Inhalte. Es schreibt
**nichts** über Anfragen ins Protokoll: keine Adresse, keinen Hash, kein Token. Alle fünf Minuten steht eine
Zeile mit Zählern im Protokoll (Anzahl gestempelter Anfragen und Zahl der Ablehnungen je Art). Die
Netzadresse sieht allerdings die Infrastruktur davor (Hoster, Lastverteiler); das ist Sache des Betreibers.

## Grenzen (`relay/limits.ts`)

| Name                | Wert   | Bedeutung                                                     |
| ------------------- | ------ | ------------------------------------------------------------- |
| `bodyBytes`         | 512    | Größter Körper einer Anfrage                                  |
| `upstreamBytes`     | 65536  | Größte Antwort eines Dienstes                                 |
| `upstreamTimeoutMs` | 10000  | Frist für den ganzen Aufruf beim Dienst                       |
| `requestTimeoutMs`  | 10000  | Frist für die ganze eingehende Anfrage                        |
| `perMinuteTotal`    | 60     | Anfragen je Minute über alle Dienste                          |
| `windowMs`          | 60000  | Zeitfenster der Zähler                                        |
| `maxSkewMs`         | 300000 | Erlaubter Unterschied zwischen Token-Zeit und Uhr des Relays  |
| `maxOrigins`        | 16     | Zahl der einstellbaren Herkünfte                              |
| `maxConnections`    | 256    | Gleichzeitig offene Verbindungen; weitere lehnt der Server ab |

Je Dienst gilt zusätzlich `60000 / minIntervalMs` Anfragen je Minute (bei 15 s: 4). `perMinuteTotal` und
`minIntervalMs` sind ein **Mengenbudget je Minute**, kein Mindestabstand: Das Relay verteilt die Anfragen nicht
zeitlich, sondern lässt in einem Fenster von einer Minute höchstens so viele durch; danach kommen Anfragen mit
`429` und `Retry-After`.

**Grenze der Zähler:** Sie gelten für alle Aufrufer zusammen, nicht je Aufrufer (das Relay kennt keine
Adressen). Ein einzelner Aufrufer kann das Limit für alle ausschöpfen. Schutz vor Überlast durch viele
Aufrufer ist Aufgabe der Infrastruktur davor.
