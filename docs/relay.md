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

Fehler sind `{"error": "<code>"}`; bei 502 mit `reason` aus der Prüfung:

| Status | Code                                                                            | Bedeutung                                                                      |
| ------ | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| 400    | `bad-hash`                                                                      | Hash nicht 32 Byte, ungültiges base64url, zusätzliche Felder, kein JSON-Objekt |
| 400    | `no-query`                                                                      | Abfragezeichenfolge (`?…`) ist nicht erlaubt                                   |
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

| Name                | Wert   | Bedeutung                                                    |
| ------------------- | ------ | ------------------------------------------------------------ |
| `bodyBytes`         | 512    | Größter Körper einer Anfrage                                 |
| `upstreamBytes`     | 65536  | Größte Antwort eines Dienstes                                |
| `upstreamTimeoutMs` | 10000  | Frist für den ganzen Aufruf beim Dienst                      |
| `requestTimeoutMs`  | 10000  | Frist für die ganze eingehende Anfrage                       |
| `perMinuteTotal`    | 60     | Anfragen je Minute über alle Dienste                         |
| `windowMs`          | 60000  | Zeitfenster der Zähler                                       |
| `maxSkewMs`         | 300000 | Erlaubter Unterschied zwischen Token-Zeit und Uhr des Relays |
| `maxOrigins`        | 16     | Zahl der einstellbaren Herkünfte                             |

Je Dienst gilt zusätzlich `60000 / minIntervalMs` Anfragen je Minute (bei 15 s: 4).

**Grenze der Zähler:** Sie gelten für alle Aufrufer zusammen, nicht je Aufrufer (das Relay kennt keine
Adressen). Ein einzelner Aufrufer kann das Limit für alle ausschöpfen. Schutz vor Überlast durch viele
Aufrufer ist Aufgabe der Infrastruktur davor.
