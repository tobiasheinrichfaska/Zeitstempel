# Relay

Ein kleiner Server, der **nur** Hashes an feste Zeitstempel-Dienste weiterreicht, weil Browser die Dienste
wegen CORS nicht direkt erreichen. Er läuft mit Node 24 und nur mit `node:`-Modulen; es gibt keine
Abhängigkeit zur Laufzeit. **Nicht ausgerollt:** es gibt kein Image und keine Einrichtung; das entscheidet
der Betreiber.

## Start

```bash
RELAY_ORIGINS=https://app.example RELAY_KEYS_FILE=/etc/zeitstempel/relay-keys.json npm run relay
```

Ohne Schlüsseldatei startet das Relay **nicht** (Zeile `config-error` auf stderr, Exit-Code 1).

| Einstellung              | Bedeutung                                                                                       | Vorgabe        |
| ------------------------ | ----------------------------------------------------------------------------------------------- | -------------- |
| `PORT`                   | Port                                                                                            | 8080           |
| `RELAY_ORIGINS`          | Browser-Herkünfte, durch Komma getrennt, genau `https://host[:port]` (oder `http://localhost…`) | keine          |
| `RELAY_ALLOW_PLAIN_HTTP` | `1` erlaubt Dienste, die nur über `http` antworten                                              | aus            |
| `RELAY_SERVICES`         | Kennungen der angebotenen Dienste, durch Komma getrennt                                         | alle passenden |
| `RELAY_KEYS_FILE`        | Pfad der Schlüsseldatei (siehe „Zugangsschlüssel“); Pflicht, außer mit `RELAY_AUTH=off`         | keine          |
| `RELAY_AUTH`             | nur `off` ist gültig: Start ohne Schlüssel, **nur für die lokale Entwicklung**                  | aus            |
| `RELAY_HOST`             | Adresse, auf der das Relay lauscht; mit `RELAY_AUTH=off` nur eine Loopback-Adresse erlaubt      | alle (auth an) |

`RELAY_AUTH=off` lauscht **nur auf `127.0.0.1`** (Vorgabe, auch ohne `RELAY_HOST`; eine andere Adresse als
`127.0.0.1`, `::1` oder `localhost` wird abgelehnt) und schreibt beim Start `{"event":"warning","message":"auth off,
loopback only (…)"}` auf stderr. Ein Relay ohne Anmeldung ist so nicht von außen erreichbar. Mit Schlüsseldatei
gilt die Vorgabe „alle Adressen“, außer `RELAY_HOST` ist gesetzt.

`RELAY_AUTH=off` und `RELAY_KEYS_FILE` zusammen werden abgelehnt. Die Startzeile im Protokoll meldet
`"auth":"on"` oder `"auth":"off"`.

## Schnittstelle

| Anfrage                                                                                                                                                      | Antwort                                                                                       |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| `POST /v1/stamp/<dienst>` mit `{"hash": "<base64url>"}` (`application/json`) oder 32 Rohbytes (`application/octet-stream`) und dem Kopf `X-Zeitstempel-Auth` | 200 `{service, genTime, accuracyMs, serial, token}`; `token` ist das Token (DER) in base64url |
| `GET /v1/services` (ohne Anmeldung)                                                                                                                          | Liste der angebotenen Dienste (Kennung, Name, `qualified`, Verwendungszweck)                  |
| `GET /health` (ohne Anmeldung)                                                                                                                               | `{ok: true, services: [...]}`                                                                 |
| `OPTIONS …`                                                                                                                                                  | Vorabfrage (CORS) für die konfigurierten Herkünfte                                            |

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
- Alle Antworten sind JSON (`application/json; charset=utf-8`), auch Fehler. Das Relay benutzt keine Cookies.
  Einen Stempel gibt es nur mit gültigem Kopf `X-Zeitstempel-Auth` (nächster Abschnitt); `GET /health`,
  `GET /v1/services` und die Vorabfrage `OPTIONS` brauchen ihn nicht.

### Zugangsschlüssel

Nur Apps mit einem Zugangsschlüssel dürfen stempeln. Das Verfahren ist **asymmetrisch** (ECDSA über P-256 mit
SHA-256): Die App hält den **privaten Schlüssel** (PKCS#8); er bleibt in der App und wird **nie übertragen**. Das
Relay kennt nur den **öffentlichen Schlüssel** und eine Schlüsselkennung `kid` (`[a-z][a-z0-9-]{0,31}`). Gesendet
wird pro Anfrage nur eine Signatur. Die Schlüsseldatei des Relays enthält deshalb **kein Geheimnis**; es zählt ihre
**Unversehrtheit**: wer sie schreiben kann, kann einen eigenen Schlüssel eintragen und damit stempeln.

**Kopf:** `X-Zeitstempel-Auth: v2.<kid>.<ts>.<sig>`

- `ts`: Unix-Sekunden, dezimal, ohne führende Nullen.
- `sig` = base64url (ohne `=`, 86 Zeichen) der 64 Byte `r || s` (IEEE P1363, so wie WebCrypto ECDSA/SHA-256 sie
  ausgibt) über die Nachricht `"zeitstempel-auth-v2\n" + METHODE + "\n" + PFAD + "\n" + ts + "\n" +
hex(SHA-256(Körper))`. `PFAD` ist der Pfad ohne Abfrage (`/v1/stamp/freetsa`), `Körper` sind die rohen Bytes, wie
  gesendet. Die Kennung ist nicht Teil der Nachricht; sie wählt den Schlüssel, gegen den geprüft wird. Die
  Bibliothek rechnet das: `signRelayRequest` (siehe unten). Köpfe der früheren Fassung (`v1.…`, HMAC) werden mit
  `401` abgelehnt.

**Was das Relay prüft** (jeder Fehler der Anmeldung ist ein einheitliches `401 {"error":"unauthorized"}`; die
Antwort verrät nicht, ob Kennung, Zeit oder Signatur falsch war. Die Reihenfolge der Prüfungen: `403`
(Herkunft), `400` (Anfrageziel, Abfragezeichenfolge), `405` (Methode), `404` (Dienst), dann `401` (Anmeldung),
`413` beim Lesen des Körpers, und erst nach der Anmeldung `415`/`400` (Hash) und `429`. Alles vor der
Anmeldung verrät nur Öffentliches (welche Dienste es gibt, das Größenlimit, die Form des Ziels) und ist kein
Orakel für Kennung oder Signatur. Ohne Kopf gibt es für einen bekannten Dienst mit erlaubter Herkunft, Methode
POST und kanonischem Ziel nie etwas anderes als `401`):

1. Form des Kopfes und `ts` innerhalb von ±`authWindowSeconds` (60 s) der Uhr des Relays, **vor** dem Lesen des
   Körpers; zusätzlich darf `ts` nicht vor dem Start des Prozesses liegen (`ts` · 1000 ≥ min(Startzeit, jetzt) − 1000 ms;
   gerechnet wird bei jeder Prüfung mit dem kleineren von Startzeit und aktueller Uhr, damit eine beim Start
   vorgehende Uhr, die später korrigiert wird, das Relay nicht bis zum Einholen der echten Zeit stilllegt). Der
   Wiederholungsspeicher liegt nur im Speicher und ist nach einem Neustart leer; ohne diese Regel ließe sich ein
   mitgeschnittener Kopf aus der Zeit davor innerhalb seines Fensters noch einmal abspielen. Folge: **nach einem
   Neustart sind Köpfe aus der Zeit davor ungültig** (die App signiert ohnehin jeden Versuch neu). **Widerruf
   eines Schlüssels** = Eintrag aus der Schlüsseldatei entfernen und das Relay neu starten. **Grenze:** geht die Uhr des Relays beim Start **nach**, ist die Startzeit zu früh und der Schutz vor dem Abspielen alter Köpfe nach einem Neustart bis zur Korrektur der Uhr geschwächt (Köpfe aus der Zeit zwischen echtem und gemessenem Start werden angenommen); die Uhr beim Start prüfen (NTP vor dem Relay). Die Uhr der App muss also auf etwa eine halbe Minute genau gehen. Das Fenster wird **nach** dem Lesen
   des Körpers noch einmal geprüft (ein langsamer Körper rettet keinen veralteten Kopf).
2. Nach dem Lesen des Körpers die Signatur (ECDSA P-256, SHA-256). Das Relay führt **für jeden wohlgeformten
   Kopf genau eine** Prüfung aus, auch bei unbekannter Kennung (gegen einen je Prozess zufällig erzeugten
   Schein-Schlüssel; gleiche Arbeit, gleiche Antwort, kein Orakel); erst danach entscheidet die Kennung, und eine
   unbekannte Kennung wird in jedem Fall abgelehnt (ein Test zählt die Prüfungen). Diese Prüfung läuft also für
   jeden wohlgeformten Kopf mit frischer Zeit; begrenzt wird die Arbeit durch höchstens 256 Verbindungen, die
   Frist von 10 s je Anfrage und das Zeitfenster. Es wird kein Geheimnis verglichen,
   ein Zeitangriff gibt also nichts preis.
3. Eine Nachricht, die schon angenommen wurde, wird abgelehnt (Wiederholung): nach `200` und nach `502`/`504` (die Anfrage wurde
   angenommen) braucht jeder weitere Versuch einen frischen Kopf. Nach `429` (nichts wurde eingetragen) darf
   **derselbe** Kopf innerhalb des Zeitfensters wiederholt werden. **Gemerkt wird der Digest der signierten Nachricht (mit der
   Kennung), nicht die Signatur:** ECDSA ist formbar, zu einer gültigen Signatur `(r, s)` ist auch `(r, n − s)`
   für dieselbe Nachricht gültig, und ein Speicher über Signaturen ließe die Zwillingssignatur als neu durch (ein
   Test belegt beides). Eine Wiederholung stirbt mit `401` **vor** dem `Content-Type`, vor der Prüfung des Hashes
   und vor dem Budget: sie verbraucht weder Budget noch Eintrag. Der Speicher wird nur **gelesen**, solange die Anfrage
   nicht bis zum Budget durchgekommen ist; eingetragen wird erst, wenn Hash und Form des Körpers stimmen und
   Budget **und** Speicher die Anfrage zulassen. Abgewiesene Versuche (`400`, `415`, `429`) füllen den Speicher
   also nicht und verbrauchen kein Budget.
   Der Speicher ist auf `authReplayEntries` Einträge begrenzt, davon darf eine Kennung höchstens den Anteil
   `authReplayKeyShare` halten (eine Kennung kann die anderen nicht aussperren). Ein Eintrag bleibt bis
   `ts + authWindowSeconds + requestTimeoutMs`, also höchstens 130 s. Weil nur zugelassene Anfragen eingetragen
   werden und höchstens `perMinuteTotal` je Minute zugelassen werden, gibt es **höchstens 180 Einträge zugleich**
   (60 × ⌈130 / 60⌉), gleich wie viele Schlüssel es gibt; `authReplayEntries` (512) ist eine **Obergrenze** mit
   Spielraum, die im Betrieb nicht erreicht wird, kein Wert, den man erwartet. Wäre er doch voll (oder der Anteil
   der Kennung), antwortet das Relay `429` mit `Retry-After` (kein Eintrag wird verdrängt, das ließe eine
   Wiederholung zu), und auch diese Antwort kostet kein Budget.
4. Das Budget zählt zusätzlich zu den globalen und den Dienst-Grenzen `perMinutePerKey` je Schlüsselkennung
   (nur im Speicher, nie im Protokoll). Bei `429` nennt `Retry-After` die **längste** Wartezeit aller zutreffenden
   Grenzen (Kennung, Dienst, Gesamt, Speicher): wer so lange wartet, wird von keiner anderen Grenze mehr
   abgewiesen.

Der `Content-Type` ist **bewusst nicht** Teil der Signatur; gebunden sind Methode, Pfad, Zeit und die Bytes des
Körpers. Der Typ bestimmt nur, wie die bereits geprüften Bytes gelesen werden (JSON oder 32 Rohbytes).

**Anfragen, die nicht zählen:** Eine Anfrage mit gültigem Kopf, aber falschem `Content-Type` (`415`) oder
ungültigem Hash (`400`) zählt **nicht** gegen das Budget und wird **nicht** gemerkt; dieselbe signierte Anfrage lässt
sich also innerhalb des Zeitfensters wiederholen und liefert wieder `400`/`415`. Das öffnet nichts: einen gültigen
Kopf hat nur, wer den privaten Schlüssel hat (oder eine mitgeschnittene Anfrage), die Arbeit je Anfrage ist klein
(eine Signaturprüfung, höchstens 512 Byte Körper) und ihre Zahl ist begrenzt durch die Frist von 10 s je Anfrage,
höchstens 256 gleichzeitige Verbindungen und das Zeitfenster von 60 s. Kein Dienst wird dadurch aufgerufen.

**Kein Relay in der Nachricht:** Die signierte Nachricht enthält nichts, was ein einzelnes Relay bezeichnet. Wird
**derselbe Schlüssel bei zwei Relays** eingetragen, kann ein Kopf, der bei dem einen angenommen wurde, innerhalb von
höchstens 60 s bei dem anderen noch einmal angenommen werden (Querwiederholung). **Schlüssel nicht auf mehrere
Relays teilen**; je Relay einen eigenen eintragen.

**Anfrageziel:** Das rohe Ziel der Anfrage muss gleich dem kanonischen Pfad sein (kein `./`, `..`, Rückwärtsstrich,
keine Absolutform `http://…`, kein leeres `?`); sonst `400 bad-request`. So bindet die Signatur den Pfad wörtlich:
was signiert wurde, ist das, was geroutet wird.

Das Relay schreibt weder Kennung noch Zeit noch Signatur ins Protokoll; die Zähler kennen nur `unauthorized`.

**Schlüsseldatei** (Pfad aus `RELAY_KEYS_FILE`): `{"version": 2, "keys": [{"id": "app-1", "publicKey": "<base64url>"}]}`.
`publicKey` ist der **unkomprimierte Punkt** (65 Byte: `04 || X || Y`) als base64url ohne `=`. Streng gelesen: genau
diese Felder, 1 bis 64 Schlüssel, `id` nach dem Muster, der Punkt muss **auf der Kurve P-256 liegen** (sonst
`public-key-point`), keine doppelte `id`, kein doppelter Schlüssel. Die Datei enthält **keine Geheimnisse**, gehört
aber **nicht ins Repository** (`.gitignore` kennt `relay-keys*.json`, `*.keys.json` und `*keys*.json`): sie ist
Konfiguration des Betreibers, und ein privater Schlüssel soll nie neben ihr liegen. Sie wird vom Betreiber verwaltet
und darf für Gruppe und Andere **nicht schreibbar** sein (z. B. Modus 0644 oder 0600). Beim Start gibt das Relay eine
Warnung (`{"event":"warning",…}` auf stderr, nur Pfad und Modus, kein Inhalt) aus, wenn Gruppe oder Andere die Datei
schreiben können (Modus & 0o022; POSIX, unter Windows entfällt die Prüfung); das Relay startet trotzdem. Lesbarkeit
ist unbedenklich. Ein Fehler beim Lesen nennt Pfad und Regelname, nie Inhalt. **Grenze der Warnung:** sie prüft nur die Datei selbst,
nicht das Verzeichnis, in dem sie liegt, und nicht den Eigentümer; wer das Verzeichnis schreiben kann, kann die
Datei ersetzen. Verzeichnis und Eigentümer sind Sache des Betreibers. Doppelte `id`s in den Schlüsseln, die dem Relay
übergeben werden, sind ein Startfehler.

**Schlüssel erzeugen:** `node scripts/make-key.ts <kennung>` schreibt in zwei Zeilen auf die Konsole (und in keine
Datei) den **privaten** Schlüssel (PKCS#8, base64url; gehört nur der App, geheim halten) und den Eintrag
`{id, publicKey}` für die Schlüsseldatei. `npm run probe` liest `RELAY_PRIVATE_KEY` (der private Schlüssel,
base64url) und `RELAY_KEY_ID` aus der Umgebung und signiert damit.

**Grenze:** Der private Schlüssel liegt in der App. Eine Web-App, die ihn im Browser hält, kann ihn nicht vor ihren
eigenen Besuchern verbergen; der Schlüssel schützt das Relay vor fremden Apps und Skripten, nicht vor den Nutzern
einer Seite, die ihn ausliefert. Er lässt sich pro App widerrufen (Eintrag aus der Datei, Relay neu starten).
**Aussperren:** Das Budget je Kennung (`perMinutePerKey` = 20) liegt bei einem Drittel des gemeinsamen Budgets
(`perMinuteTotal` = 60). **Drei** Kennungen (oder drei gestohlene Schlüssel) können das gemeinsame Budget also
ausschöpfen und damit alle übrigen Kennungen für den Rest des Zeitfensters aussperren; eine oder zwei können es
nicht. Mehr als 20 Anfragen je Minute braucht eine einzelne App nicht: die Dienstgrenzen der vier mitgelieferten
Dienste ergeben zusammen 16 (4 je Dienst bei 15 s).

### Browser (CORS)

- Die App-Herkunft muss in `RELAY_ORIGINS` stehen, **genau** wie der Browser sie sendet (`https://app.example`,
  ohne Pfad, ohne Schrägstrich am Ende).
- Ein `POST` mit `Content-Type: application/json` (oder `application/octet-stream`) und dem Kopf
  `X-Zeitstempel-Auth` löst im Browser eine
  **Vorabfrage** aus. Antwort darauf: `204` mit `Access-Control-Allow-Origin: <die Herkunft>`,
  `Access-Control-Allow-Methods: GET, POST`, `Access-Control-Allow-Headers: Content-Type, X-Zeitstempel-Auth`,
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

1. Hash der Daten bilden (SHA-256, 32 Byte). Körper als Text bilden und einmal in Bytes umsetzen, dann den
   Kopf **für genau diese Bytes** signieren und senden:

   ```ts
   const path = '/v1/stamp/' + id;
   const text = JSON.stringify({ hash: toBase64Url(hash) });
   const signed = await signRelayRequest({
     privateKey, // PKCS#8-Bytes: aus dem Speicher der App, nie aus dem Quelltext der Seite, wenn es sich vermeiden lässt
     keyId: 'app-1',
     method: 'POST',
     path,
     body: new TextEncoder().encode(text),
     nowMs: Date.now(),
   });
   if (!signed.ok) throw new Error(signed.reason);
   const res = await fetch(relay + path, {
     method: 'POST',
     headers: { 'Content-Type': 'application/json', 'X-Zeitstempel-Auth': signed.value },
     body: text,
   });
   ```

   `signRelayRequest` wirft nie und weist nie ab: auch für feindliche Proxys als Eingabe, als `privateKey` oder als
   `body` (werfendes `getPrototypeOf`/`get`) gibt es einen Code (`bad-options`/`bad-key`). Jede Eingabe wird einmal
   gelesen und kopiert, nie über einen Iterator; `privateKey` darf höchstens 256 Byte, `body` höchstens 512 Byte
   haben (sonst `bad-key`/`bad-options`). **Realm:** ein `Uint8Array` aus einem anderen Realm (iframe, Worker, `vm`)
   wird abgewiesen; `privateKey` und `body` als `new Uint8Array(x)` übergeben.

   Keine Cookies, kein `mode`-Zusatz nötig. Für jeden Versuch (auch nach `429`/`401`) neu signieren. Die Frist der App sollte **länger als 12 s** sein (das Relay wartet bis zu 10 s auf
   den Dienst).

2. Bei `200`: `fromBase64Url(body.token)` und `verifyTimestampToken(token, hash, [ankerPem…], {now})`
   **ohne** `expectedNonce` (die Nonce wählt das Relay, die App kennt sie nicht; die Bindung an den Hash
   prüft `imprint-mismatch`). Die Anker (`anchors/*.pem` des Dienstes aus `services.json`) liefert die App
   selbst mit; wem sie traut, entscheidet sie. `genTime` des Relays ist nur eine Anzeige: maßgeblich ist
   `value.genTime` der eigenen Prüfung.
3. Bei `401`: Schlüssel, Kennung und die Uhr der App prüfen (±60 s); ein Wiederholungsversuch mit demselben
   Kopf wird ebenfalls mit `401` abgelehnt. Bei `429`: `Retry-After` (Sekunden) lesen und erst dann wieder
   fragen. Bei `502`/`504`/Netzwerkfehler: später
   noch einmal versuchen oder einen anderen Dienst nehmen; ein Fehlschlag ist kein Beweis für etwas.
4. Das Token (base64url-Text) zusammen mit Kennung des Dienstes und Hash aufbewahren; geprüft wird später
   mit denselben Mitteln, ohne das Relay.

Fehler sind `{"error": "<code>"}`; bei 502 mit `reason` aus der Prüfung:

| Status | Code                                                                            | Bedeutung                                                                                                                 |
| ------ | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| 400    | `bad-hash`                                                                      | Hash nicht 32 Byte, ungültiges base64url, zusätzliche Felder, kein JSON-Objekt                                            |
| 400    | `no-query`                                                                      | Abfragezeichenfolge (`?…`) ist nicht erlaubt                                                                              |
| 400    | `bad-request`                                                                   | Anfrageziel ist keine gültige Adresse (z. B. `//`, `//[`) oder nicht gleich dem kanonischen Pfad (`./`, `\`, Absolutform) |
| 401    | `unauthorized`                                                                  | Auth-Fehler: Kopf `X-Zeitstempel-Auth` fehlt oder ist ungültig (Form, Zeit, Kennung, Signatur, Wiederholung); einheitlich |
| 403    | `origin-not-allowed`                                                            | Aufruf aus einem Browser von einer nicht konfigurierten Herkunft                                                          |
| 404    | `unknown-service`, `not-found`                                                  | Dienst oder Pfad nicht vorhanden                                                                                          |
| 405    | `method-not-allowed`                                                            | `/v1/stamp/…` nur mit POST                                                                                                |
| 413    | `too-large`                                                                     | Körper über dem Limit (Verbindung wird geschlossen); kommt vor der Signaturprüfung, nennt nur das öffentliche Limit       |
| 415    | `unsupported-media-type`                                                        | weder JSON noch `application/octet-stream`                                                                                |
| 429    | `rate-limited`                                                                  | Limit erreicht (auch je Schlüssel, auch Speicher gegen Wiederholung voll); `Retry-After` in Sekunden                      |
| 500    | `internal`                                                                      | Unerwarteter Fehler im Relay (ohne Einzelheiten nach außen)                                                               |
| 502    | `upstream-failed`, `upstream-too-large`, `upstream-refused`, `upstream-invalid` | Dienst nicht erreichbar, zu große oder unpassende Antwort, ungültiges Token                                               |
| 504    | `upstream-timeout`                                                              | Dienst antwortete nicht rechtzeitig                                                                                       |

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

Zeitpunkt und Netzadresse des Aufrufers (wie jeder Server), den **Hash** und den Kopf `X-Zeitstempel-Auth`
(Kennung, Zeit, Signatur), nie Inhalte und nie den privaten Schlüssel. Es schreibt **nichts** über Anfragen ins Protokoll:
keine Adresse, keinen Hash, kein Token, keine Kennung, keine Signatur. Alle fünf Minuten steht eine
Zeile mit Zählern im Protokoll (Anzahl gestempelter Anfragen und Zahl der Ablehnungen je Art). Die
Netzadresse sieht allerdings die Infrastruktur davor (Hoster, Lastverteiler); das ist Sache des Betreibers.

## Grenzen (`relay/limits.ts`)

| Name                 | Wert   | Bedeutung                                                          |
| -------------------- | ------ | ------------------------------------------------------------------ |
| `bodyBytes`          | 512    | Größter Körper einer Anfrage                                       |
| `upstreamBytes`      | 65536  | Größte Antwort eines Dienstes                                      |
| `upstreamTimeoutMs`  | 10000  | Frist für den ganzen Aufruf beim Dienst                            |
| `requestTimeoutMs`   | 10000  | Frist für die ganze eingehende Anfrage                             |
| `perMinuteTotal`     | 60     | Anfragen je Minute über alle Dienste                               |
| `windowMs`           | 60000  | Zeitfenster der Zähler                                             |
| `perMinutePerKey`    | 20     | Anfragen je Minute für eine Schlüsselkennung (ein Drittel)         |
| `authWindowSeconds`  | 60     | Erlaubter Zeitunterschied (Sekunden) der Anfrage zur Relay-Uhr     |
| `authReplayEntries`  | 512    | Obergrenze gemerkter Nachrichten (real höchstens 180); voll: `429` |
| `authReplayKeyShare` | 0.5    | Anteil des Speichers, den eine Kennung höchstens hält              |
| `maxSkewMs`          | 300000 | Erlaubter Unterschied zwischen Token-Zeit und Uhr des Relays       |
| `maxOrigins`         | 16     | Zahl der einstellbaren Herkünfte                                   |
| `maxConnections`     | 256    | Gleichzeitig offene Verbindungen; weitere lehnt der Server ab      |

Je Schlüsselkennung gilt zusätzlich `perMinutePerKey`. Je Dienst gilt zusätzlich `60000 / minIntervalMs` Anfragen je Minute (bei 15 s: 4). `perMinuteTotal` und
`minIntervalMs` sind ein **Mengenbudget je Minute**, kein Mindestabstand: Das Relay verteilt die Anfragen nicht
zeitlich, sondern lässt in einem Fenster von einer Minute höchstens so viele durch; danach kommen Anfragen mit
`429` und `Retry-After`.

**Grenze der Zähler:** Die globalen und die Dienst-Zähler gelten für alle Aufrufer zusammen, nicht je
Netzadresse (das Relay kennt keine Adressen); je Aufrufer zählt nur die Schlüsselkennung. Wer einen gültigen
Schlüssel hat, kann sein Budget und das gemeinsame Limit für alle ausschöpfen. Schutz vor Überlast durch viele
Aufrufer ist Aufgabe der Infrastruktur davor.
