# Relay

Ein kleiner Server, der **nur** Hashes an feste Zeitstempel-Dienste weiterreicht, weil Browser die Dienste
wegen CORS nicht direkt erreichen. Er läuft mit Node 24 und nur mit `node:`-Modulen; es gibt keine
Abhängigkeit zur Laufzeit. **Nicht ausgerollt:** es gibt kein Image und keine Einrichtung; das entscheidet
der Betreiber.

**Nicht im Paket:** Das Paket (`npm install git+…`) enthält nur die Bibliothek, `services.json` und `anchors/`
(Feld `files` der `package.json`). Das Relay (`relay/`) und die Werkzeuge (`scripts/`: `make-key.ts`, `probe.ts`,
`spike.ts`) gehören nur zum Repository: Wer das Relay betreibt oder einen Schlüssel erzeugt, klont das Repository
und führt die Befehle dort aus (`npm install`, dann `npm run relay`).

## Start

```bash
RELAY_ORIGINS=https://app.example RELAY_SERVICES=freetsa RELAY_KEYS_FILE=/etc/zeitstempel/relay-keys.json npm run relay
```

Ohne Schlüsseldatei startet das Relay **nicht** (Zeile `config-error` auf stderr, Exit-Code 1). Ebenso **nicht ohne
`RELAY_SERVICES`**: Die Dienste werden ausdrücklich gewählt, es gibt keine Vorgabe „alle“ (Zeile `config-error`,
Exit-Code 1, die Meldung nennt die möglichen Kennungen aus `services.json`). Wer wählt, liest vorher die
Nutzungsbedingungen in `docs/dienste.md`: nur FreeTSA erlaubt die allgemeine Nutzung ausdrücklich.

| Einstellung              | Bedeutung                                                                                       | Vorgabe     |
| ------------------------ | ----------------------------------------------------------------------------------------------- | ----------- |
| `PORT`                   | Port                                                                                            | 8080        |
| `RELAY_ORIGINS`          | Browser-Herkünfte, durch Komma getrennt, genau `https://host[:port]` (oder `http://localhost…`) | keine       |
| `RELAY_ALLOW_PLAIN_HTTP` | `1` erlaubt Dienste, die nur über `http` antworten                                              | aus         |
| `RELAY_SERVICES`         | Kennungen der angebotenen Dienste, durch Komma getrennt; **Pflicht** (Start bricht sonst ab)    | keine       |
| `RELAY_KEYS_FILE`        | Pfad der Schlüsseldatei (siehe „Zugangsschlüssel“); Pflicht, außer mit `RELAY_AUTH=off`         | keine       |
| `RELAY_AUTH`             | nur `off` ist gültig: Start ohne Schlüssel, **nur für die lokale Entwicklung**                  | aus         |
| `RELAY_HOST`             | Adresse, auf der das Relay lauscht; mit `RELAY_AUTH=off` nur eine Loopback-Adresse erlaubt      | `127.0.0.1` |

**Bindung (geändert):** Ohne `RELAY_HOST` lauscht das Relay **nur auf `127.0.0.1`**, mit Schlüsseldatei ebenso wie mit
`RELAY_AUTH=off`. Früher lauschte es mit Schlüsseldatei auf allen Adressen. Der Normalfall ist der Reverse-Proxy auf
demselben Rechner (siehe „Betrieb hinter einem Reverse-Proxy“). **Ein Container oder ein Proxy auf einem anderen
Rechner braucht `RELAY_HOST=0.0.0.0`** (oder die eigene Adresse); das ist dann eine bewusste Entscheidung des
Betreibers. Wer ein Relay von früher ohne `RELAY_HOST` startet und es von außen erreichen will, muss den Wert jetzt
setzen (sonst ist es nur lokal erreichbar: der sichere Fehler).

`RELAY_AUTH=off` lauscht ebenfalls auf `127.0.0.1` (eine andere Adresse als `127.0.0.1`, `::1` oder `localhost` wird
abgelehnt) und schreibt beim Start `{"event":"warning","message":"auth off, loopback only (…)"}` auf stderr. Ein Relay
ohne Anmeldung ist so nicht von außen erreichbar.

`RELAY_AUTH=off` und `RELAY_KEYS_FILE` zusammen werden abgelehnt. Die Startzeile im Protokoll meldet
`"auth":"on"` oder `"auth":"off"`.

## Schnittstelle

| Anfrage                                                                                                                                                      | Antwort                                                                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| `POST /v1/stamp/<dienst>` mit `{"hash": "<base64url>"}` (`application/json`) oder 32 Rohbytes (`application/octet-stream`) und dem Kopf `X-Zeitstempel-Auth` | 200 `{service, genTime, accuracyMs, serial, token}`; `token` ist das Token (DER) in base64url    |
| `GET /v1/services` (ohne Anmeldung)                                                                                                                          | Liste der angebotenen Dienste (Kennung, Name, `qualified`, Verwendungszweck)                     |
| `GET /health` (ohne Anmeldung)                                                                                                                               | `{ok: true, services: [...]}` (der Prozess läuft; **kein Dienst wird geprüft**, siehe „Betrieb“) |
| `OPTIONS …`                                                                                                                                                  | Vorabfrage (CORS) für die konfigurierten Herkünfte                                               |

### Formate

- **`hash`** ist der SHA-256 (32 Byte) als **base64url ohne Auffüllzeichen** (`=`), also 43 Zeichen. Der JSON-Körper
  hat genau ein Feld; Rohbytes gehen nur mit `Content-Type: application/octet-stream` (genau 32 Byte).
  Ein `charset`-Zusatz im `Content-Type` wird ignoriert. Mehr als 512 Byte Körper werden abgelehnt.
- **200:** `service` (Kennung), `genTime` (ISO 8601, UTC, mit Millisekunden, z. B. `2026-11-23T13:05:56.000Z`;
  die Zeit des Dienstes, sekundengenau), `accuracyMs` (Zahl, kann Bruchteile haben, z. B. `0.5`, oder `null`), `serial` (Kleinbuchstaben-Hex),
  `token` (base64url ohne Auffüllzeichen, das Token als DER, so wie es `readToken`/`verifyTimestampToken` der
  Bibliothek erwarten).
- **`GET /v1/services`:** `{"services": [{"id", "name", "qualified", "intendedUse"}]}`. Die Reihenfolge ist die der Datei
  `services.json`; es gibt keine Vorgabe, die App wählt eine Kennung (eine Einstellung der App, nicht des Relays).
- **`GET /health`:** `{"ok": true, "services": ["<id>", …]}`. Das heißt nur: der Prozess läuft und diese Dienste sind
  eingerichtet. **`/health` ruft keinen Dienst auf** und sagt nichts darüber, ob ein Dienst erreichbar ist oder gültige
  Token liefert (ein Aufruf wäre ein Stempel und kostete Budget).
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
   Körpers; zusätzlich darf `ts` nicht vor dem Start des Prozesses liegen (`ts` · 1000 ≥ Startzeit − 1000 ms). Die
   Startzeit wird nie neu berechnet, sondern bei jeder Anfrage an einen Dienst nur **gesenkt** (`Startzeit =
min(Startzeit, jetzt)`), auch bei einem Rücksprung der Uhr, nie erhöht. Ging die Uhr beim Start vor und wird später
   korrigiert, sinkt die Startzeit einmal auf den ersten beobachteten korrigierten Zeitpunkt; danach gilt für Köpfe ab
   dort wieder das volle ±60-s-Fenster. Der Wiederholungsspeicher liegt nur im Speicher und ist nach einem Neustart leer; ohne diese Regel ließe sich ein
   mitgeschnittener Kopf aus der Zeit davor innerhalb seines Fensters noch einmal abspielen. Folge: **nach einem
   Neustart sind Köpfe aus der Zeit davor ungültig** (die App signiert ohnehin jeden Versuch neu). **Widerruf
   eines Schlüssels** = Eintrag aus der Schlüsseldatei entfernen und das Relay neu starten. **Grenzen:** (a) Geht die Uhr des Relays beim Start **nach**, ist die Startzeit zu früh und der Schutz vor dem Abspielen alter Köpfe nach einem Neustart bis zur ersten Anfrage nach der Korrektur geschwächt (Köpfe aus der Zeit zwischen echtem und gemessenem Start werden angenommen); die Uhr beim Start prüfen (NTP vor dem Relay). (b) Geht sie beim Start **vor**, werden Köpfe von vor der ersten Anfrage nach der Korrektur abgelehnt (die App signiert ohnehin jeden Versuch neu); Köpfe von vor dem echten Neustart bleiben abgelehnt, weil der echte Start nie nach dem ersten korrigierten Zeitpunkt liegt. (c) Die Startzeit sinkt nur bei Anfragen an einen Dienst; setzt jemand die Uhr nach dem Start zurück, gelten Köpfe bis zum niedrigsten dabei beobachteten Zeitpunkt, nie weiter zurück. Die Uhr der App muss also auf etwa eine Minute genau gehen (±60 s). (d) Ein Kopf mit `ts` ab dem Start (bis +60 s; geht die Uhr der App vor, ist das möglich) bleibt nach einem Neustart bis zum Ende seines Fensters wiederholbar, also bis zu 120 s nach dem Start des Relays (`ts` ≤ Start + 60 s, dazu das Fenster von 60 s), weil der Wiederholungsspeicher dann leer ist; gegen einen Mitschnitt dieser Art schützt das Relay nicht (kein Codefix). (e) Eine Uhrablesung, die nicht endlich ist (`NaN`, `±Infinity`), wird bei Anfragen ignoriert und senkt die Startzeit nicht; ist die Uhr schon beim Start nicht endlich, **bricht der Start ab** (Fehler `relay clock is not finite at start`, kein Inhalt). Das Fenster wird **nach** dem Lesen
   des Körpers noch einmal geprüft (ein langsamer Körper rettet keinen veralteten Kopf).
2. Nach dem Lesen des Körpers die Signatur (ECDSA P-256, SHA-256). Das Relay führt **für jeden wohlgeformten
   Kopf genau eine** Prüfung aus, auch bei unbekannter Kennung (gegen einen je Prozess zufällig erzeugten
   Schein-Schlüssel; gleiche Arbeit, gleiche Antwort, kein Orakel); erst danach entscheidet die Kennung, und eine
   unbekannte Kennung wird in jedem Fall abgelehnt (ein Test zählt die Prüfungen). Diese Prüfung läuft also für
   jeden wohlgeformten Kopf mit frischer Zeit; begrenzt wird die Arbeit durch höchstens 256 Verbindungen, die
   Frist von 5 s je Anfrage und das Zeitfenster. Es wird kein Geheimnis verglichen,
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
   `ts + authWindowSeconds + requestTimeoutMs`, also höchstens 125 s (bei richtiger Uhr). Weil nur zugelassene Anfragen eingetragen
   werden und höchstens `perMinuteTotal` je Minute zugelassen werden, gibt es **höchstens 180 Einträge zugleich**
   (60 × ⌈125 / 60⌉), gleich wie viele Schlüssel es gibt; `authReplayEntries` (512) ist eine **Obergrenze** mit
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
(eine Signaturprüfung, höchstens 512 Byte Körper) und ihre Zahl ist begrenzt durch die Frist von 5 s je Anfrage,
höchstens 256 gleichzeitige Verbindungen und das Zeitfenster von 60 s. Kein Dienst wird dadurch aufgerufen.

**Kein Relay in der Nachricht:** Die signierte Nachricht enthält nichts, was ein einzelnes Relay bezeichnet. Wird
**derselbe Schlüssel bei zwei Relays** eingetragen, kann ein Kopf, der bei dem einen angenommen wurde, innerhalb von
höchstens 60 s bei dem anderen noch einmal angenommen werden (Querwiederholung). **Schlüssel nicht auf mehrere
Relays teilen**; je Relay einen eigenen eintragen.

**Anfrageziel:** Das rohe Ziel der Anfrage muss gleich dem kanonischen Pfad sein (kein `./`, `..`, Rückwärtsstrich,
keine Absolutform `http://…`, kein leeres `?`); sonst `400 bad-request`. So bindet die Signatur den Pfad wörtlich:
was signiert wurde, ist das, was geroutet wird.

Das Relay schreibt weder Kennung noch Zeit noch Signatur ins Protokoll; die Zähler kennen nur `unauthorized`.

**Abgebrochene Anfragen:** Bricht der Client die Verbindung ab, während der Körper noch kommt (`ECONNRESET`,
`aborted`), wird das **nicht beantwortet** (die Verbindung ist weg) und nicht als `internal` gezählt, sondern in
`refused` unter `client-aborted`. `internal` zählt nur echte Ausnahmen im Relay.

**Zu langsame Anfragen:** Kommt eine Anfrage nicht innerhalb von `requestTimeoutMs` vollständig an (Kopfzeilen oder
Körper tröpfeln), beendet **der Server** die Verbindung und antwortet `408`. Das zählt unter `refused` als
`request-timeout` (einmal je Verbindung), **nicht** als `client-aborted`: dieses zählt nur Clients, die von sich aus
abbrechen. Die Zähler `unauthorized`, `rate-limited` usw. bleiben davon unberührt.

**Pipelining mit Müll:** Wer mehrere Anfragen hintereinander schickt (pipelined) und danach Müll nachschickt, bekommt nur die `400` und verliert die Antwort der laufenden Anfrage (wie bei Node).

**Schlüsseldatei** (Pfad aus `RELAY_KEYS_FILE`): `{"version": 2, "keys": [{"id": "app-1", "publicKey": "<base64url>"}]}`.
`publicKey` ist der **unkomprimierte Punkt** (65 Byte: `04 || X || Y`) als base64url ohne `=`. Streng gelesen: genau
diese Felder, 1 bis 64 Schlüssel, `id` nach dem Muster, der Punkt muss **auf der Kurve P-256 liegen** (sonst
`public-key-point`), keine doppelte `id`, kein doppelter Schlüssel. Die Datei enthält **keine Geheimnisse**, gehört
aber **nicht ins Repository** (`.gitignore` kennt `relay-keys*.json`, `*.keys.json` und `*keys*.json`): sie ist
Konfiguration des Betreibers, und ein privater Schlüssel soll nie neben ihr liegen. Sie wird vom Betreiber verwaltet
und darf für Gruppe und Andere **nicht schreibbar** sein (z. B. Modus 0644 oder 0600). Beim Start gibt das Relay eine
Warnung (`{"event":"warning",…}` auf stderr, nur Pfad und Modus, kein Inhalt) aus, wenn Gruppe oder Andere die Datei
schreiben können (Modus & 0o022; POSIX, unter Windows entfällt die Prüfung); das Relay startet trotzdem. Lesbarkeit
ist unbedenklich. Ein Fehler beim Lesen nennt Pfad und Regelname und, wenn ein Eintrag fehlerhaft ist, dessen Index in `keys` (`id in keys[2]`), nie Inhalt. **Grenze der Warnung:** sie prüft nur die Datei selbst,
nicht das Verzeichnis, in dem sie liegt, und nicht den Eigentümer; wer das Verzeichnis schreiben kann, kann die
Datei ersetzen. Verzeichnis und Eigentümer sind Sache des Betreibers. Doppelte `id`s in den Schlüsseln, die dem Relay
übergeben werden, sind ein Startfehler.

**Schlüssel erzeugen** (im geklonten Repository): `node scripts/make-key.ts <kennung>` (gleichwertig:
`npm run -s make-key -- <kennung>`) schreibt in zwei Zeilen auf die Konsole (und in keine Datei) den **privaten**
Schlüssel (PKCS#8, base64url; gehört nur der App, geheim halten) und den Eintrag `{id, publicKey}` für die
Schlüsseldatei; ein Hinweis dazu geht auf stderr. Beispiel (gekürzt):

```text
$ node scripts/make-key.ts app-1
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg…        <- Zeile 1: privater Schlüssel, nur für die App
{"id":"app-1","publicKey":"BAsY3mTq0…"}                  <- Zeile 2: Eintrag für die Schlüsseldatei
```

Zeile 2 kommt in `keys` der Schlüsseldatei: `{"version": 2, "keys": [<Zeile 2>]}`. `npm run probe` liest `RELAY_PRIVATE_KEY` (der private Schlüssel,
base64url) und `RELAY_KEY_ID` aus der Umgebung und signiert damit.

**Grenze:** Der private Schlüssel liegt in der App. Eine Web-App, die ihn im Browser hält, kann ihn nicht vor ihren
eigenen Besuchern verbergen; der Schlüssel schützt das Relay vor fremden Apps und Skripten, nicht vor den Nutzern
einer Seite, die ihn ausliefert. Er lässt sich pro App widerrufen (Eintrag aus der Datei, Relay neu starten).
**Aussperren:** Die Dienst-Zähler gelten **global**, nicht je Kennung. Mit den mitgelieferten Diensten (je 4
Anfragen je Minute bei 15 s) sperrt ein einziger gültiger Schlüssel mit 4 Anfragen in einer Minute einen Dienst für
alle anderen Kennungen bis zum Ende des Zeitfensters. `perMinutePerKey` (20) und `perMinuteTotal` (60) werden mit
den mitgelieferten Diensten nie erreicht (die vier Dienstgrenzen ergeben zusammen nur 16 je Minute); sie greifen
erst, wenn die Dienstgrenzen zusammen mehr ergeben. Das Relay verteilt das Budget eines Dienstes nicht fair auf die
Kennungen: Wer einen gültigen Schlüssel hat (auch einen gestohlenen), kann einen Dienst für alle übrigen
aussperren. Das ist eine bekannte Grenze; ein Schlüssel lässt sich widerrufen (Eintrag entfernen, Relay neu starten).

### Browser (CORS)

- Die App-Herkunft muss in `RELAY_ORIGINS` stehen, **genau** wie der Browser sie sendet (`https://app.example`,
  ohne Pfad, ohne Schrägstrich am Ende).
- Ein `POST` mit `Content-Type: application/json` (oder `application/octet-stream`) und dem Kopf
  `X-Zeitstempel-Auth` löst im Browser eine
  **Vorabfrage** aus. Antwort darauf: `204` mit `Access-Control-Allow-Origin: <die Herkunft>`,
  `Access-Control-Allow-Methods: GET, POST`, `Access-Control-Allow-Headers: Content-Type, X-Zeitstempel-Auth`,
  `Access-Control-Max-Age: 600`, `Vary: Origin`.
- Jede Antwort an eine erlaubte Herkunft (auch Fehler) trägt `Access-Control-Allow-Origin: <die Herkunft>`
  und `Access-Control-Expose-Headers: Retry-After, Date` (sonst kann das Skript der Seite `Retry-After` und `Date`
  nicht lesen; `Date` ist die Uhr des Relays, siehe „Die App als Client“, Schritt 3). Dasselbe gilt für die Antwort
  auf die Vorabfrage.
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
   const sentMs = Date.now();
   const signed = await signRelayRequest({
     privateKey, // PKCS#8-Bytes: aus dem Speicher der App, nie aus dem Quelltext der Seite, wenn es sich vermeiden lässt
     keyId: 'app-1',
     method: 'POST',
     path,
     body: new TextEncoder().encode(text),
     nowMs: sentMs, // Millisekunden, nicht Sekunden
   });
   if (!signed.ok) throw new Error(signed.reason);
   const res = await fetch(relay + path, {
     method: 'POST',
     headers: { 'Content-Type': 'application/json', 'X-Zeitstempel-Auth': signed.value },
     body: text,
   });
   ```

   `sentMs` (der Zeitpunkt des Sendens) wird für die Frische des Tokens in Schritt 2 gebraucht: **merken**.

   `privateKey` darf auch ein `CryptoKey` sein (privat, ECDSA auf P-256, **auch nicht
   extrahierbar**): Die App muss die Schlüsselbytes dann nie halten, zum Beispiel `await crypto.subtle.importKey('pkcs8',
bytes, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])` einmal beim Start und danach nur den `CryptoKey`
   weitergeben. Er wird unverändert benutzt (kein Export, kein neuer Import). Ein `CryptoKey` aus einem anderen Realm, ein
   öffentlicher, ein anderer Algorithmus oder eine andere Kurve ergeben `bad-key`. (Auch dann gilt: wer den
   Code der Seite ausführen kann, kann den Schlüssel **benutzen**, nur nicht auslesen.)

   **`nowMs` ist die Zeit in Millisekunden seit 1970 (`Date.now()`), nicht in Sekunden.** Die Bibliothek verlangt eine
   endliche Zahl ab 1e11 (Bruchteile sind erlaubt); ein kleinerer Wert, etwa Sekunden, ergibt `bad-options`, damit
   nicht stillschweigend eine Zeit im Jahr 1970 signiert wird.

   `signRelayRequest` wirft nie und weist nie ab: auch für feindliche Proxys als Eingabe, als `privateKey` oder als
   `body` (werfendes `getPrototypeOf`/`get`) gibt es einen Code (`bad-options`/`bad-key`). Jede Eingabe wird einmal
   gelesen und kopiert, nie über einen Iterator; `privateKey` darf höchstens 256 Byte, `body` höchstens 512 Byte
   haben (sonst `bad-key`/`bad-options`). **Realm:** ein `Uint8Array` aus einem anderen Realm (iframe, Worker, `vm`)
   wird abgewiesen; `privateKey` und `body` als `new Uint8Array(x)` übergeben.

   Keine Cookies, kein `mode`-Zusatz nötig. Für jeden Versuch (auch nach `429`/`401`) neu signieren. Die Frist der App sollte **rund 17 s ab Sendebeginn** betragen: bis zu 5 bis 6 s für den Körper
   (`requestTimeoutMs`), bis zu 10 s für den Dienst (`upstreamTimeoutMs`) und die Prüfung des Tokens.

2. Bei `200`: `fromBase64Url(body.token)` und
   `verifyTimestampToken(token, hash, [ankerPem…], { now: new Date(), minGenTime: new Date(sentMs - 60_000) })`
   **ohne** `expectedNonce` (die Nonce wählt das Relay, die App kennt sie nicht; die Bindung an den Hash
   prüft `imprint-mismatch`). Die Anker (`anchors/*.pem` des Dienstes aus `services.json`) liefern die App
   selbst mit; wem sie traut, entscheidet sie. `genTime` des Relays ist nur eine Anzeige: maßgeblich ist
   `value.genTime` der eigenen Prüfung. **`minGenTime` nicht weglassen:** ohne sie prüft die App **nicht, wie alt
   das Token ist** (ein Dienst oder ein Relay mit Zugriff auf einen abgelaufenen oder gestohlenen Dienstschlüssel
   könnte ein rückdatiertes Token liefern, das besteht; `docs/grenzen.md`). Mit `minGenTime` und `now` gilt das
   Fenster [Senden − 60 s, jetzt + 5 min] (die Obergrenze lässt sich mit `maxSkewMs` enger fassen); die 60 s
   entsprechen `genTimeSlackMs` des Relays und decken die Uhrabweichung zwischen Dienst und App.
3. Bei `401`: Schlüssel, Kennung und die Uhr der App prüfen (±60 s); ein Wiederholungsversuch mit demselben
   Kopf wird ebenfalls mit `401` abgelehnt. **Uhrversatz beheben (genau einmal):** Das Relay gibt `Date` frei
   (`Access-Control-Expose-Headers`, auch bei `401`). Die App liest den Kopf, bildet
   `versatz = Date.parse(date) - Date.now()` und signiert **genau einmal** neu mit `nowMs = Date.now() + versatz`;
   `now` und `minGenTime` der Prüfung bildet sie dann ebenfalls mit der korrigierten Uhr. Schlägt auch dieser
   Versuch mit `401` fehl, liegt es am Schlüssel oder an der Kennung, nicht an der Uhr: nicht weiter versuchen.

   ```ts
   import { signRelayRequest } from 'zeitstempel';

   /** Sends once; after a 401 corrects the clock by the relay's `Date` and signs and sends exactly once more. */
   export async function stampWithClockFix(
     relay: string,
     id: string,
     privateKey: Uint8Array,
     keyId: string,
     hash: string, // base64url
   ): Promise<{ res: Response; offsetMs: number; sentMs: number }> {
     const path = '/v1/stamp/' + id;
     const body = new TextEncoder().encode(JSON.stringify({ hash }));
     const attempt = async (offsetMs: number) => {
       const sentMs = Date.now() + offsetMs; // die Uhr des Relays, soweit bekannt
       const signed = await signRelayRequest({
         privateKey,
         keyId,
         method: 'POST',
         path,
         body,
         nowMs: sentMs,
       });
       if (!signed.ok) throw new Error(signed.reason);
       const res = await fetch(relay + path, {
         method: 'POST',
         headers: { 'Content-Type': 'application/json', 'X-Zeitstempel-Auth': signed.value },
         body,
       });
       return { res, offsetMs, sentMs };
     };
     const first = await attempt(0);
     const relayMs = Date.parse(first.res.headers.get('Date') ?? '');
     if (first.res.status !== 401 || Number.isNaN(relayMs)) return first;
     return attempt(relayMs - Date.now()); // genau einmal; danach `now: new Date(Date.now() + offsetMs)`, `minGenTime: new Date(sentMs - 60_000)`
   }
   ```

   `Date` hat nur ganze Sekunden: der Versatz ist auf etwa 1 s genau, das Fenster von ±60 s ist weit genug. Nach der
   Korrektur ist `ts` ein anderer, die Nachricht also keine Wiederholung. Ein erneutes Signieren **innerhalb
   derselben Sekunde** mit unveränderter Uhr ergäbe dieselbe Nachricht (Wiederholung, `401`): bei `502`/`504` daher
   **mindestens 1 s warten** (siehe unten). **Eine weitere Ursache:** Der Kopf trägt die Zeit nur in ganzen
   Sekunden; zwei Anfragen mit demselben Pfad und demselben Körper in derselben Sekunde ergeben dieselbe
   Nachricht und die zweite wird als Wiederholung abgelehnt (`401`). Nach `502`/`504` (die Anfrage wurde
   angenommen) deshalb **mindestens 1 s warten**, bevor man erneut signiert und sendet. Bei `429`: `Retry-After` (Sekunden) lesen und erst dann wieder
   fragen. Bei `502`/`504`/Netzwerkfehler: später
   noch einmal versuchen oder einen anderen Dienst nehmen; ein Fehlschlag ist kein Beweis für etwas.

4. Das Token (base64url-Text) zusammen mit Kennung des Dienstes, Hash und dem Ergebnis der Prüfung
   (`signerNotAfter`!) aufbewahren; die **Rechnung** (Hash, Signatur, Kette zur `genTime`) lässt sich später mit denselben
   Mitteln ohne das Relay wiederholen, die **Aussage** wird aber schwächer: nach `signerNotAfter` des
   Zeitstempel-Zertifikats oder wenn dessen Schlüssel kompromittiert wird, verfällt die Beweiskraft (es gibt keine
   Sperrprüfung, die Frische lässt sich später nicht mehr prüfen; `docs/grenzen.md`, „Langzeitaussage“). Für Nachweise
   über längere Zeit: **rechtzeitig neu stempeln** (vor `signerNotAfter`) und **mehrere Dienste** stempeln.

Fehler sind `{"error": "<code>"}`; bei 502 mit `reason` aus der Prüfung:

| Status | Code                                                                            | Bedeutung                                                                                                                    |
| ------ | ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| 400    | `bad-hash`                                                                      | Hash nicht 32 Byte, ungültiges base64url, zusätzliche Felder, kein JSON-Objekt                                               |
| 400    | `no-query`                                                                      | Abfragezeichenfolge (`?…`) ist nicht erlaubt                                                                                 |
| 400    | `bad-request`                                                                   | Anfrageziel ist keine gültige Adresse (z. B. `//`, `//[`) oder nicht gleich dem kanonischen Pfad (`./`, `\`, Absolutform)    |
| 401    | `unauthorized`                                                                  | Auth-Fehler: Kopf `X-Zeitstempel-Auth` fehlt oder ist ungültig (Form, Zeit, Kennung, Signatur, Wiederholung); einheitlich    |
| 403    | `origin-not-allowed`                                                            | Aufruf aus einem Browser von einer nicht konfigurierten Herkunft                                                             |
| 404    | `unknown-service`, `not-found`                                                  | Dienst oder Pfad nicht vorhanden                                                                                             |
| 405    | `method-not-allowed`                                                            | `/v1/stamp/…` nur mit POST                                                                                                   |
| 413    | `too-large`                                                                     | Körper über dem Limit (Verbindung wird geschlossen); kommt vor der Signaturprüfung, nennt nur das öffentliche Limit          |
| 415    | `unsupported-media-type`                                                        | weder JSON noch `application/octet-stream`                                                                                   |
| 429    | `rate-limited`                                                                  | Limit erreicht (auch je Schlüssel, auch Speicher gegen Wiederholung voll); `Retry-After` in Sekunden                         |
| 500    | `internal`                                                                      | Unerwarteter Fehler im Relay (ohne Einzelheiten nach außen)                                                                  |
| 502    | `upstream-failed`, `upstream-too-large`, `upstream-refused`, `upstream-invalid` | Dienst nicht erreichbar, zu große oder unpassende Antwort, ungültiges Token (`reason`; auch `time-too-old`/`time-in-future`) |
| 504    | `upstream-timeout`                                                              | Dienst antwortete nicht rechtzeitig                                                                                          |

## Lokal testen

Ohne Netz und ohne echten Dienst, im geklonten Repository (am besten in einer eigenen Kopie, damit die
mitgelieferte `services.json` unverändert bleibt):

1. Einen **Stub-Dienst** bauen, der auf `127.0.0.1` lauscht, die Anfrage (`application/timestamp-query`) liest und
   ein **gültig signiertes** Token zurückgibt, z. B. mit `openssl ts -reply -queryfile … -signer … -inkey …
-chain …` (eigene Wurzel, Zeitstempel-Zertifikat mit der erweiterten Schlüsselverwendung `timeStamping`, kritisch).
   Die aufgezeichneten Antworten unter `tests/fixtures/` taugen dafür **nicht**: das Relay wählt die Nonce selbst
   und verlangt sie in der Antwort zurück, eine aufgezeichnete Antwort trägt eine andere.
2. In der Kopie von `services.json` die Adresse eines Dienstes auf den Stub setzen (`http://127.0.0.1:<port>/`)
   und unter `anchors` die PEM-Datei der eigenen Wurzel eintragen; diese Datei liegt in `anchors/`.
3. Das Relay mit `RELAY_ALLOW_PLAIN_HTTP=1` starten (der Stub spricht http), mit `RELAY_AUTH=off` (nur Loopback)
   oder mit einer Schlüsseldatei wie oben und mit `RELAY_SERVICES` (Pflicht, auch hier); dazu keine neuen Einstellungen: es sind dieselben wie im Betrieb.

Der Test-Harness `tests/relay.test.ts` ist ein Beispiel für den Aufbau im selben Prozess: er ersetzt den Dienst
durch eine Funktion (`upstream`) und legt die Nonce fest (`random`), damit die aufgezeichnete Antwort passt; für
einen Stub über http gilt die Anleitung oben.

## Was das Relay prüft

- **Kein offener Proxy:** Der Aufrufer nennt nur die Kennung eines Dienstes aus `services.json`. Adresse,
  Anfrage und Nonce baut das Relay selbst. Der Aufrufer kann nichts in die Anfrage einschleusen, außer dem
  Hash.
- **Die Antwort wird geprüft**, bevor sie weitergegeben wird: Hash, Nonce, Signatur, Kette zu den Ankern des
  Dienstes und die **Zeit**: `genTime` muss in [Zeitpunkt der Anfrage an den Dienst − `genTimeSlackMs`, Uhr des
  Relays nach der Antwort + `genTimeSlackMs`] liegen (je 60 s; früher galt nur eine Obergrenze von 5 Minuten, nach unten
  war nichts begrenzt, ein rückdatiertes Token mit abgelaufenem oder gestohlenem Dienstschlüssel wäre durchgegangen).
  Eine Abweichung ergibt `502 upstream-invalid` mit `reason` `time-too-old` bzw. `time-in-future`; ein zu altes Token
  wird zusätzlich unter `upstream-too-old` gezählt. Das Budget des Dienstes ist dann verbraucht (die Anfrage ging
  hinaus). Eine Grenze nach 60 s lässt eine Uhrabweichung zwischen Dienst und Relay von bis zu einer Minute zu; ein
  Dienst, dessen Uhr mehr abweicht, wird abgelehnt.
- **Die App muss dem Relay nicht vertrauen, soweit es um die Bindung an den Hash geht:** Die App prüft das Token
  mit der Bibliothek selbst (Abdruck, Signatur, Kette zu ihren eigenen Ankern); ein Relay kann ihr keinen Stempel für
  einen anderen Hash oder einen unbekannten Aussteller unterschieben. **Nicht** gilt das für: die **Frische** (die App
  prüft sie nur, wenn sie `minGenTime` übergibt; Schritt 2), die **Verfügbarkeit** (das Relay kann Stempel verweigern,
  verzögern oder verlieren), die **Vertraulichkeit des Hashes** (das Relay und der Dienst sehen ihn, bei einem Dienst nur
  über `http` auch jeder auf der Strecke dorthin) und die Wahl des Dienstes (das Relay entscheidet, welche Dienste es
  anbietet).
- Keine Weiterleitungen, TLS-Zertifikate nach Node-Vorgabe, harte Frist für den ganzen Aufruf, Größenlimit.
- `Cache-Control: no-store`, `Vary: Origin`, `X-Content-Type-Options: nosniff`.

## Was das Relay sieht

Zeitpunkt und Netzadresse des Aufrufers (wie jeder Server), den **Hash** und den Kopf `X-Zeitstempel-Auth`
(Kennung, Zeit, Signatur), nie Inhalte und nie den privaten Schlüssel. Es schreibt **nichts** über Anfragen ins Protokoll:
keine Adresse, keinen Hash, kein Token, keine Kennung, keine Signatur. Alle fünf Minuten steht eine
Zeile mit Zählern im Protokoll (Anzahl gestempelter Anfragen und Zahl der Ablehnungen je Art). Die
Netzadresse sieht allerdings die Infrastruktur davor (Hoster, Lastverteiler); das ist Sache des Betreibers.

## Grenzen (`relay/limits.ts`)

| Name                 | Wert  | Bedeutung                                                                                                                       |
| -------------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------- |
| `bodyBytes`          | 512   | Größter Körper einer Anfrage                                                                                                    |
| `upstreamBytes`      | 65536 | Größte Antwort eines Dienstes                                                                                                   |
| `upstreamTimeoutMs`  | 10000 | Frist für den ganzen Aufruf beim Dienst                                                                                         |
| `requestTimeoutMs`   | 5000  | Frist für die ganze eingehende Anfrage (auch die Kopfzeilen)                                                                    |
| `perMinuteTotal`     | 60    | Anfragen je Minute über alle Dienste                                                                                            |
| `windowMs`           | 60000 | Zeitfenster der Zähler                                                                                                          |
| `perMinutePerKey`    | 20    | Anfragen je Minute für eine Schlüsselkennung (ein Drittel)                                                                      |
| `authWindowSeconds`  | 60    | Erlaubter Zeitunterschied (Sekunden) der Anfrage zur Relay-Uhr                                                                  |
| `authReplayEntries`  | 512   | Obergrenze gemerkter Nachrichten (real höchstens 180); voll: `429`                                                              |
| `authReplayKeyShare` | 0.5   | Anteil des Speichers, den eine Kennung höchstens hält                                                                           |
| `genTimeSlackMs`     | 60000 | Token-Zeit: höchstens so weit vor dem Zeitpunkt der Anfrage und so weit hinter der Relay-Uhr (`time-too-old`, `time-in-future`) |
| `maxOrigins`         | 16    | Zahl der einstellbaren Herkünfte                                                                                                |
| `maxConnections`     | 256   | Gleichzeitig offene Verbindungen; weitere lehnt der Server ab                                                                   |
| `keepAliveTimeoutMs` | 65000 | Leerlauf einer offenen Verbindung zwischen zwei Anfragen (länger als der Leerlauf-Timeout üblicher Proxys, 60 s)                |

Je Schlüsselkennung gilt zusätzlich `perMinutePerKey`. Je Dienst gilt zusätzlich `60000 / minIntervalMs` Anfragen je Minute (bei 15 s: 4). `perMinuteTotal` und
`minIntervalMs` sind ein **Mengenbudget je Minute**, kein Mindestabstand: Das Relay verteilt die Anfragen nicht
zeitlich, sondern lässt in einem Fenster von einer Minute höchstens so viele durch; danach kommen Anfragen mit
`429` und `Retry-After`.

**Grenze der Zähler:** Die globalen und die Dienst-Zähler gelten für alle Aufrufer zusammen, nicht je
Netzadresse (das Relay kennt keine Adressen); je Aufrufer zählt nur die Schlüsselkennung. Wer einen gültigen
Schlüssel hat, kann sein Budget und das gemeinsame Limit für alle ausschöpfen. Schutz vor Überlast durch viele
Aufrufer ist Aufgabe der Infrastruktur davor.

**Uhr zurückgestellt:** Die Zähler der Fenster (gesamt, je Dienst, je Kennung) und die Restzeit der Einträge des
Wiederholungsspeichers rechnen Zeitpunkte in der Zukunft beim Lesen als „jetzt“. Ein Rückwärtssprung der Uhr sperrt
das Budget also nicht für die Länge des Sprungs: nach höchstens einem Fenster (60 s) ist es wieder frei, und
`Retry-After` nennt nie mehr als ein Fenster (beim Wiederholungsspeicher nie mehr als die Lebensdauer eines Eintrags). Die Zusage „höchstens 125 s“ gilt für den
genannten `Retry-After`-Wert, nicht für den Speicher selbst: seine Einträge bleiben nach einem Rücksprung bis zu
ihrem **echten** Ablauf erhalten (der Wiederholungsschutz bleibt also bestehen); nur die Wartezeit, die das Relay
nennt, wird begrenzt.

**Leerlauf-Verbindungen (`keepAliveTimeoutMs`):** Der Leerlauf einer Verbindung zwischen zwei Anfragen beträgt 65 s
(früher 5 s). Ein Reverse-Proxy hält Verbindungen zum Relay meist offen und schließt sie nach 60 s Leerlauf selbst; läge
der Wert des Relays darunter, träfe eine Anfrage eine Verbindung, die das Relay gerade schließt (Fehler `502` am
Proxy). **Wechselwirkung:** Eine Leerlauf-Verbindung belegt einen der `maxConnections` (256) Plätze bis zu 65 s statt
5 s. Das ändert das Bild gegenüber einem bösartigen Client wenig (er konnte schon bisher 256 Verbindungen mit einer
halben Anfrage jeweils 5 s halten und sofort neu öffnen, also dauerhaft), schwächt aber nichts ab: die Frist für eine
**Anfrage** (`requestTimeoutMs`, 5 s, auch für die Kopfzeilen) gilt unverändert auch auf einer Verbindung, die schon
benutzt wurde (ein Test belegt es: eine halbe zweite Anfrage endet mit `408`), und `maxConnections` ist unverändert 256.
Mit einem Reverse-Proxy sieht das Relay nur dessen wenige Verbindungen; der Schutz vor vielen Verbindungen eines Clients
ist Sache des Proxys (Verbindungs- und Ratenlimit je Adresse).

**Verbindungen und Betrieb:** Das Relay kennt keine Adressen und führt keinen Zähler je Adresse (es protokolliert
auch keine). Ein einzelner Client kann daher bis zu 256 Verbindungen (`maxConnections`) für etwa 5 bis 6 s belegen
(`requestTimeoutMs`, die Frist gilt auch für die Kopfzeilen; der Server prüft sie einmal je Sekunde) und damit andere
Aufrufer aussperren. Ein **Reverse-Proxy mit Verbindungs- und Ratenlimit je Adresse vor dem Relay ist für den Betrieb
Pflicht**; das Relay allein schützt davor nicht.

## Betrieb hinter einem Reverse-Proxy

Das Relay ist **nicht** für das offene Netz gedacht. Es lauscht auf `127.0.0.1`; davor steht ein Reverse-Proxy mit TLS
und einem Verbindungs- und Ratenlimit je Adresse. Die Beispiele unten sind **Beispiele**: sie wurden gelesen und gegen
die Regeln des Relays abgeglichen, aber **nicht gegen einen echten Proxy getestet** (kein nginx und kein Caddy im Test).
Anpassen und selbst prüfen (`nginx -t`, `caddy validate`).

Was jede Einrichtung leisten muss:

- Den **Pfad unverändert** weitergeben (das Relay verlangt das rohe Ziel gleich dem kanonischen Pfad, die Signatur
  bindet ihn): keine Umschreibung, kein Präfix, keine Normalisierung, kein Anhängen einer Abfrage.
- Die Köpfe **`Origin`** und **`X-Zeitstempel-Auth`** unverändert durchreichen (und `Content-Type`); `Origin` nicht
  entfernen, sonst gilt der Aufruf als Aufruf ohne Browser. Die Antworten (auch `Access-Control-*`, `Retry-After`)
  unverändert zurückgeben.
- Eine **Lese-Frist von mindestens 17 s** (besser 20 s): bis zu 5 bis 6 s für den Körper, bis zu 10 s für den Dienst,
  dazu die Prüfung. Kürzere Fristen des Proxys brechen Stempel ab, die das Relay noch zählt.
- **Ratenlimit und Verbindungslimit je Adresse.** Das Relay selbst kennt keine Adressen. Der Rahmen ist klein: die vier
  mitgelieferten Dienste erlauben zusammen 16 Anfragen je Minute (4 je Dienst).
- Körper höchstens 512 Byte (das Relay lehnt mehr ab); der Proxy darf früher abweisen.
- `GET /health` ist für Überwachung gedacht; es prüft keinen Dienst.

**nginx** (Beispiel, nicht getestet):

```nginx
limit_req_zone  $binary_remote_addr zone=zs_rate:10m rate=20r/m;
limit_conn_zone $binary_remote_addr zone=zs_conn:10m;

server {
    listen 443 ssl;
    server_name relay.example;
    # ssl_certificate / ssl_certificate_key: eigene Einrichtung

    client_max_body_size   1k;
    client_header_timeout  6s;
    client_body_timeout    6s;

    location / {
        limit_req  zone=zs_rate burst=5 nodelay;
        limit_conn zs_conn 10;
        limit_req_status  429;
        limit_conn_status 429;

        proxy_pass http://127.0.0.1:8080;   # ohne Pfad hinter der Adresse: der Pfad bleibt unverändert
        proxy_http_version 1.1;
        proxy_set_header Connection "";     # Verbindungen zum Relay offen halten
        proxy_set_header Host $host;
        proxy_connect_timeout 5s;
        proxy_send_timeout    20s;
        proxy_read_timeout    20s;          # mindestens 17 s
        proxy_redirect off;
        # Origin und X-Zeitstempel-Auth gibt nginx von sich aus weiter: nicht mit proxy_set_header leeren.
    }
}
```

**Caddy** (Beispiel, nicht getestet). Caddy kann ohne Zusatzmodul **kein** Ratenlimit je Adresse; das Modul (zum Beispiel
`caddy-ratelimit`) muss hinzugebaut werden, sonst fehlt der wichtigste Teil. Die Zeilen dazu hängen von dessen Fassung
ab und stehen deshalb hier nur als Gerüst:

```caddyfile
relay.example {
    # rate_limit { zone je_adresse { key {remote_host}  events 20  window 1m } }   # Zusatzmodul nötig
    reverse_proxy 127.0.0.1:8080 {
        transport http {
            dial_timeout            5s
            response_header_timeout 20s    # mindestens 17 s
        }
    }
}
```

`reverse_proxy` gibt Pfad und Köpfe (`Origin`, `X-Zeitstempel-Auth`) von sich aus unverändert weiter.

**Hinweise für den Betrieb:**

- **Vertraulichkeit des Hashes.** Das Relay und der Dienst sehen den Hash; bei einem Dienst, der nur über `http`
  antwortet (`digicert`, `certum`), liest ihn auch jeder auf der Strecke mit. Ist der Inhalt **ratbar** (kurzer Text,
  bekannte Datei, Werte aus einer kleinen Menge), lässt sich der Hash durch Raten bestätigen. Dann nicht den Hash des Inhalts
  stempeln, sondern einen **gesalzenen Hash** (SHA-256 über Inhalt plus zufälliges Salz, das die App aufbewahrt) oder die
  **Wurzel eines Merkle-Baums** über mehrere Hashes (ein Stempel für viele Inhalte).
- **Kapazität.** Jeder Dienst erlaubt `60000 / minIntervalMs` Anfragen je Minute für **alle** Nutzer des Relays zusammen
  (bei 15 s: **4 Stempel je Minute**). Mit FreeTSA allein (dem einzigen Dienst mit ausdrücklich erlaubter allgemeiner
  Nutzung, `docs/dienste.md`) sind das 4 Stempel je Minute für alle. Das Budget wird **auch bei einem Fehler des Dienstes
  oder einem ungültigen Token verbraucht** (die Anfrage ging hinaus). Wer mehr braucht, bündelt (Merkle-Wurzel) oder
  braucht einen Vertragsdienst.
- **`/health` prüft keinen Dienst** (s. o.); eine Überwachung, die nur `/health` ruft, meldet „gesund“, auch wenn alle
  Dienste ausfallen.
- **`upstream-invalid` ist ein Alarmzeichen.** In der Zeile der Zähler (alle fünf Minuten) steht unter `refused`
  `upstream-invalid` (und `upstream-too-old` für rückdatierte Token). Normalerweise bleibt der Wert bei 0. Ein Anstieg
  heißt: ein Dienst liefert Token, die das Relay nicht annimmt (neue Zertifikatskette, veraltete Anker in `anchors/`,
  Uhr, ein Dienst oder jemand auf der Strecke betrügt) oder ein Token mit Schaltsekunde (`docs/grenzen.md`). Das
  verdient eine Warnung, nicht nur eine Zahl im Protokoll; die Einzelheiten (`reason`) stehen nur in der Antwort an den
  Aufrufer, nicht im Protokoll.
- **Relay- und App-Stand müssen zusammenpassen.** Die Kopfform (`v2`), die Kennungen der Dienste (`services.json`), die
  Anker und die Regeln der Prüfung (hier: die Zeitgrenzen) gehören zu einem Stand. Wird das Relay oder `services.json`
  aktualisiert, die App gleich mitnehmen (und umgekehrt): eine App mit alten Ankern meldet `untrusted-chain`, ein Relay
  mit alten Ankern `upstream-invalid`; eine App ohne `minGenTime` prüft die Frische nicht, auch wenn das Relay es tut.
