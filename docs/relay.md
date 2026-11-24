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

| Einstellung                | Bedeutung                                                                                                                                                                                                                                                                                               | Vorgabe                                      |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| `PORT`                     | Port                                                                                                                                                                                                                                                                                                    | 8080                                         |
| `RELAY_ORIGINS`            | Browser-Herkünfte, durch Komma getrennt, genau `https://host[:port]` (oder `http://localhost…`)                                                                                                                                                                                                         | keine                                        |
| `RELAY_ALLOW_PLAIN_HTTP`   | `1` erlaubt Dienste, die nur über `http` antworten                                                                                                                                                                                                                                                      | aus                                          |
| `RELAY_SERVICES`           | Kennungen der angebotenen Dienste, durch Komma getrennt; **Pflicht** (Start bricht sonst ab)                                                                                                                                                                                                            | keine                                        |
| `RELAY_KEYS_FILE`          | Pfad der Schlüsseldatei (siehe „Zugangsschlüssel“); Pflicht, außer mit `RELAY_AUTH=off`                                                                                                                                                                                                                 | keine                                        |
| `RELAY_AUTH`               | nur `off` ist gültig: Start ohne Schlüssel, **nur für die lokale Entwicklung**                                                                                                                                                                                                                          | aus                                          |
| `RELAY_HOST`               | Adresse, auf der das Relay lauscht; mit `RELAY_AUTH=off` nur eine Loopback-Adresse erlaubt                                                                                                                                                                                                              | `127.0.0.1`                                  |
| `RELAY_KEEPALIVE_MS`       | Leerlauf einer Verbindung zwischen zwei Anfragen in ms, ganze Zahl 1000 bis 120000 (übersteuert beide Werte, siehe „Leerlauf-Verbindungen“)                                                                                                                                                             | nach Bindung: 65000 bei Loopback, sonst 5000 |
| `RELAY_BATCH_MS`           | Sammelbetrieb: Fenster in ms, ganze Zahl 1000 bis 60000; leer oder `0` = aus (jede Anfrage bekommt einen eigenen Stempel); siehe „Sammelbetrieb“                                                                                                                                                        | aus                                          |
| `RELAY_BATCH_MAX`          | Sammelbetrieb: höchstens so viele Anfragen in einem Fenster, ganze Zahl 2 bis 1024; ein volles Fenster schließt sofort                                                                                                                                                                                  | 128                                          |
| `RELAY_UPSTREAM_AUTH_<ID>` | Zugangsdaten eines bezahlten Dienstes, die das Relay selbst hält (`<ID>`: Kennung in Großbuchstaben, `-` als `_`); `Benutzer:Passwort` bei `basic`, sonst das Token; **Pflicht** für einen gewählten Dienst mit Quelle `relay`, **freiwillig** bei `either`; siehe „Zugangsdaten zu bezahlten Diensten“ | keine                                        |
| `RELAY_MAX_WAIT_MS`        | Sammelbetrieb: längste Wartezeit einer Anfrage auf einen freien Platz beim Dienst in ms, ganze Zahl 1000 bis 60000; danach `503 busy`; siehe „Schlüsselarten und Solo-Stempel“                                                                                                                          | 30000                                        |

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

| Anfrage                                                                                                                                                                                                                                                                                                    | Antwort                                                                                                                            |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `POST /v1/stamp/<dienst>` mit `{"hash": "<base64url>"}` oder `{"hash": "<base64url>", "mode": "solo"}` (`application/json`; bei einem bezahlten Dienst dazu `"upstream": {…}`, siehe „Zugangsdaten zu bezahlten Diensten“) oder 32 Rohbytes (`application/octet-stream`) und dem Kopf `X-Zeitstempel-Auth` | 200 `{service, genTime, accuracyMs, serial, token}`; `token` ist das Token (DER) in base64url; im Sammelbetrieb zusätzlich `batch` |
| `GET /v1/services` (ohne Anmeldung)                                                                                                                                                                                                                                                                        | Liste der angebotenen Dienste (Kennung, Name, `qualified`, Verwendungszweck; bei bezahlten Diensten `auth`)                        |
| `GET /health` (ohne Anmeldung)                                                                                                                                                                                                                                                                             | `{ok: true, services: [...]}` (der Prozess läuft; **kein Dienst wird geprüft**, siehe „Betrieb“)                                   |
| `OPTIONS …`                                                                                                                                                                                                                                                                                                | Vorabfrage (CORS) für die konfigurierten Herkünfte                                                                                 |

### Formate

- **`hash`** ist der SHA-256 (32 Byte) als **base64url ohne Auffüllzeichen** (`=`), also 43 Zeichen. Der JSON-Körper
  hat genau ein Feld, im Sammelbetrieb darf ein zweites Feld `mode` dazukommen (nur der Wert `"solo"`, siehe „Schlüsselarten und Solo-Stempel“; jeder andere Wert ist `400 bad-mode`), bei einem bezahlten Dienst darf `upstream` dazukommen (siehe „Zugangsdaten zu bezahlten Diensten“; `400 bad-upstream`); Rohbytes gehen nur mit `Content-Type: application/octet-stream` (genau 32 Byte).
  Ein `charset`-Zusatz im `Content-Type` wird ignoriert. Mehr als 512 Byte Körper werden abgelehnt.
- **200:** `service` (Kennung), `genTime` (ISO 8601, UTC, mit Millisekunden, z. B. `2026-11-23T13:05:56.000Z`;
  die Zeit des Dienstes, sekundengenau), `accuracyMs` (Zahl, kann Bruchteile haben, z. B. `0.5`, oder `null`), `serial` (Kleinbuchstaben-Hex),
  `token` (base64url ohne Auffüllzeichen, das Token als DER, so wie es `readToken`/`verifyTimestampToken` der
  Bibliothek erwarten).
- **`GET /v1/services`:** `{"services": [{"id", "name", "qualified", "intendedUse"}]}`; ein Dienst mit Zugangsdaten hat zusätzlich `auth` (`{"kind", "source"}`, bei `header` auch `"header"`: was die App senden muss, nie ein Wert, nie ob das Relay selbst Zugangsdaten hält). Die Reihenfolge ist die der Datei
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
   eines Schlüssels** = Eintrag aus der Schlüsseldatei entfernen; das Relay liest die Datei laufend neu und lässt den Schlüssel danach sofort nicht mehr zu (siehe „Schlüsseldatei laufend lesen“, kein Neustart nötig). **Grenzen:** (a) Geht die Uhr des Relays beim Start **nach**, ist die Startzeit zu früh und der Schutz vor dem Abspielen alter Köpfe nach einem Neustart bis zur ersten Anfrage nach der Korrektur geschwächt (Köpfe aus der Zeit zwischen echtem und gemessenem Start werden angenommen); die Uhr beim Start prüfen (NTP vor dem Relay). (b) Geht sie beim Start **vor**, werden Köpfe von vor der ersten Anfrage nach der Korrektur abgelehnt (die App signiert ohnehin jeden Versuch neu); Köpfe von vor dem echten Neustart bleiben abgelehnt, weil der echte Start nie nach dem ersten korrigierten Zeitpunkt liegt. (c) Die Startzeit sinkt nur bei Anfragen an einen Dienst; setzt jemand die Uhr nach dem Start zurück, gelten Köpfe bis zum niedrigsten dabei beobachteten Zeitpunkt, nie weiter zurück. Die Uhr der App muss also auf etwa eine Minute genau gehen (±60 s). (d) Ein Kopf mit `ts` ab dem Start (bis +60 s; geht die Uhr der App vor, ist das möglich) bleibt nach einem Neustart bis zum Ende seines Fensters wiederholbar, also bis zu 120 s nach dem Start des Relays (`ts` ≤ Start + 60 s, dazu das Fenster von 60 s), weil der Wiederholungsspeicher dann leer ist; gegen einen Mitschnitt dieser Art schützt das Relay nicht (kein Codefix). (e) Eine Uhrablesung, die nicht endlich ist (`NaN`, `±Infinity`), wird bei Anfragen ignoriert und senkt die Startzeit nicht; ist die Uhr schon beim Start nicht endlich, **bricht der Start ab** (Fehler `relay clock is not finite at start`, kein Inhalt). Das Fenster wird **nach** dem Lesen
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
alle anderen Kennungen bis zum Ende des Zeitfensters (bei FreeTSA mit 5 s: 12 Anfragen). `perMinuteTotal` (60) wird mit
den mitgelieferten Diensten nie erreicht (die vier Dienstgrenzen ergeben zusammen nur 24 je Minute); `perMinutePerKey`
(20) kann ein Schlüssel erreichen, der mehrere Dienste zugleich nutzt. Beide greifen im Sammelbetrieb früher
(siehe dort: sie zählen jede Anfrage). Das Relay verteilt das Budget eines Dienstes nicht fair auf die
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

| Status | Code                                                                            | Bedeutung                                                                                                                                                                                                                                                        |
| ------ | ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 400    | `bad-hash`                                                                      | Hash nicht 32 Byte, ungültiges base64url, zusätzliche Felder, kein JSON-Objekt                                                                                                                                                                                   |
| 400    | `no-query`                                                                      | Abfragezeichenfolge (`?…`) ist nicht erlaubt                                                                                                                                                                                                                     |
| 400    | `bad-request`                                                                   | Anfrageziel ist keine gültige Adresse (z. B. `//`, `//[`) oder nicht gleich dem kanonischen Pfad (`./`, `\`, Absolutform)                                                                                                                                        |
| 400    | `bad-mode`                                                                      | `mode` im JSON-Körper hat einen anderen Wert als `"solo"` (nur nach bestandener Anmeldung)                                                                                                                                                                       |
| 400    | `bad-upstream`                                                                  | `upstream` passt nicht zum Dienst: vorhanden, wo der Dienst keines nimmt (Quelle `relay`, keine `auth`), fehlend, wo die App eines liefern muss, falsche Form, Zeichen oder Länge (nur nach bestandener Anmeldung)                                               |
| 401    | `unauthorized`                                                                  | Auth-Fehler: Kopf `X-Zeitstempel-Auth` fehlt oder ist ungültig (Form, Zeit, Kennung, Signatur, Wiederholung); einheitlich                                                                                                                                        |
| 403    | `origin-not-allowed`                                                            | Aufruf aus einem Browser von einer nicht konfigurierten Herkunft                                                                                                                                                                                                 |
| 403    | `solo-not-allowed`                                                              | Schlüsselart 1 verlangte `mode: "solo"`, während für den Dienst andere Anfragen warten (nur im Sammelbetrieb)                                                                                                                                                    |
| 404    | `unknown-service`, `not-found`                                                  | Dienst oder Pfad nicht vorhanden                                                                                                                                                                                                                                 |
| 405    | `method-not-allowed`                                                            | `/v1/stamp/…` nur mit POST                                                                                                                                                                                                                                       |
| 413    | `too-large`                                                                     | Körper über dem Limit (Verbindung wird geschlossen); kommt vor der Signaturprüfung, nennt nur das öffentliche Limit                                                                                                                                              |
| 415    | `unsupported-media-type`                                                        | weder JSON noch `application/octet-stream`                                                                                                                                                                                                                       |
| 429    | `rate-limited`                                                                  | Limit erreicht (auch je Schlüssel, auch Speicher gegen Wiederholung voll); `Retry-After` in Sekunden                                                                                                                                                             |
| 500    | `internal`                                                                      | Unerwarteter Fehler im Relay (ohne Einzelheiten nach außen)                                                                                                                                                                                                      |
| 502    | `upstream-failed`, `upstream-too-large`, `upstream-refused`, `upstream-invalid` | Dienst nicht erreichbar, zu große oder unpassende Antwort, ungültiges Token (`reason`; auch `time-too-old`/`time-in-future`)                                                                                                                                     |
| 503    | `shutting-down`                                                                 | Nur im Sammelbetrieb: das Relay wird beendet; die Anfrage war nicht (mehr) in einem Fenster, die App versucht es später neu                                                                                                                                      |
| 503    | `busy`                                                                          | Im Sammelbetrieb: kein freier Platz beim Dienst innerhalb von `RELAY_MAX_WAIT_MS`, oder die Solo-Warteschlange des Dienstes ist voll; immer: die Tabelle der Zugangsdaten-Identitäten des Dienstes ist voll (`upstreamIdentitiesMax`); `Retry-After` in Sekunden |
| 504    | `upstream-timeout`                                                              | Dienst antwortete nicht rechtzeitig                                                                                                                                                                                                                              |

## Sammelbetrieb

**Betriebsart des Relays, standardmäßig aus.** Ohne `RELAY_BATCH_MS` bekommt jede Anfrage einen eigenen Stempel (so
war und ist es der Normalfall). Mit `RELAY_BATCH_MS` sammelt das Relay die Hashes mehrerer Anfragen für einen Dienst
in einem **Fenster** und lässt den Dienst **einen einzigen Wert** stempeln, der alle Hashes des Fensters bindet. Das
hält den Takt des Dienstes (`minIntervalMs`) ein, gleich wie viele Nutzer es gibt (bei FreeTSA zählt das Limit von 1
Anfrage je Sekunde für das ganze Relay), und es kostet je Nutzer nur wenige hundert Byte mehr.

### Funktionsweise

1. Die erste angenommene Anfrage für einen Dienst (nach Anmeldung, Prüfung des Hashes und den Budgets je Schlüssel
   und gesamt) **öffnet das Fenster**. Weitere angenommene Anfragen für denselben Dienst kommen in dasselbe Fenster.
   Das Fenster schließt nach `RELAY_BATCH_MS` oder sobald `RELAY_BATCH_MAX` Anfragen darin warten (dann öffnet die
   nächste Anfrage ein neues). Je Dienst gibt es ein eigenes Fenster.
2. Beim Schließen zieht das Relay für jede Anfrage ein **Salz** `r_i` (32 Zufallsbytes) und bildet das **Blatt**
   `leaf_i = SHA-256(0x00 ‖ r_i ‖ h_i)` (`h_i` ist der Hash des Einreichers). Die Blätter werden **gemischt**
   (Fisher-Yates mit der Zufallsquelle des Relays; die Reihenfolge verrät nichts über die Ankunft) und zu einem
   Merkle-Baum nach **RFC 6962** zusammengesetzt: innerer Knoten `SHA-256(0x01 ‖ links ‖ rechts)`; bei `n` Blättern
   wird bei der größten Zweierpotenz unter `n` geteilt, **das letzte Blatt wird nie verdoppelt**. Die Präfixe `0x00`
   und `0x01` trennen Blätter von inneren Knoten (kein innerer Knoten lässt sich als Blatt ausgeben und umgekehrt).
3. Gestempelt wird `imprint = SHA-256("zeitstempel-batch-v1\n" ‖ uint32be(n) ‖ Wurzel)`: der Wert bindet die
   Fassung und die Blattzahl. Das Relay verfährt damit wie mit jedem Hash: eigene Nonce, Prüfung des Tokens gegen
   `imprint` (Signatur, Kette, Nonce), Frische (`genTimeSlackMs`). Die Prüfung der Antwort ist dieselbe wie im
   Einzelbetrieb.
4. Jede wartende Anfrage bekommt **dasselbe Token** und ihren **Beleg** `batch`.

Beispiel für `n = 5` (Teilung bei 4); der Beleg für `L2` ist `index 2`, `size 5`, `path [L3, B, L4]`:

```text
                   Wurzel = H(01 ‖ A ‖ L4)
                  /                       \
        A = H(01 ‖ B ‖ C)                  L4
         /              \
 B = H(01 ‖ L0 ‖ L1)   C = H(01 ‖ L2 ‖ L3)
    /      \              /      \
   L0      L1            L2      L3        Li = SHA-256(00 ‖ Salz_i ‖ Hash_i)

 gestempelt: SHA-256("zeitstempel-batch-v1\n" ‖ uint32be(5) ‖ Wurzel)
```

### Antwort

Wie im Einzelbetrieb (`service`, `genTime`, `accuracyMs`, `serial`, `token`), dazu das Feld `batch`:

```json
{
  "service": "freetsa",
  "genTime": "2026-11-23T13:05:56.000Z",
  "accuracyMs": null,
  "serial": "…",
  "token": "<base64url, dasselbe Token für alle im Fenster>",
  "batch": {
    "v": 1,
    "size": 5,
    "index": 2,
    "salt": "<base64url, 32 Byte>",
    "path": ["<base64url, 32 Byte>", "<…>", "<…>"]
  }
}
```

`v` ist die Fassung (1), `size` die Zahl der Blätter, `index` die Stelle des Blattes im gemischten Baum, `salt` das Salz
`r_i`, `path` der Prüfpfad nach RFC 6962/9162 (Geschwister von der Blattebene aufwärts). **Die Länge von `path` ergibt
sich aus `size` und `index`** (höchstens 10). `genTime` und `accuracyMs` sind die des Tokens: sie gelten für den Baum.
Ohne `RELAY_BATCH_MS` gibt es das Feld `batch` nicht.

**Größe der Antwort** (gemessen mit dem echten FreeTSA-Token der Fixture, 4634 Byte, JSON mit base64url): ohne Sammeln
6294 Byte; `n = 1`: 6392 Byte (+98: Salz, leerer Pfad); `n = 16`: 6576 Byte (Pfad von 4: +282); `n = 128`: 6715 Byte (Pfad
von 7: +421). Das Token macht fast alles aus; der Beleg (`batch`) allein ist bei `n = 128` etwa 420 Byte groß.

### Einstellungen

| Einstellung       | Bedeutung                                                                                    |
| ----------------- | -------------------------------------------------------------------------------------------- |
| `RELAY_BATCH_MS`  | Fenster in ms, ganze Zahl 1000 bis 60000, streng gelesen; leer, nicht gesetzt oder `0` = aus |
| `RELAY_BATCH_MAX` | Höchstzahl wartender Anfragen je Fenster und Dienst, 2 bis 1024, Vorgabe 128                 |

Ungültige Werte (`999`, `60001`, `1.5`, `abc`, `1e4`, mit Leerzeichen …) beenden den Start mit einer deutschen Zeile
`config-error`. **Der Start prüft zusätzlich:** `RELAY_BATCH_MS` muss mindestens so groß sein wie `minIntervalMs`
**jedes** gewählten Dienstes, sonst `config-error` (ein Fenster **kürzer als das Mindestintervall** würde das Limit des Dienstes verletzen; FreeTSA: 5000; Sectigo, DigiCert, Certum: 15000, also mit ihnen
mindestens `RELAY_BATCH_MS=15000`). Die Startzeile im Protokoll nennt dann `batchMs`.

### Budgets und Zähler

- Das **Dienstbudget** (`60000 / minIntervalMs` je Minute) zählt **einen Stempel je Fenster**: nur die Anfrage, die ein
  Fenster öffnet, braucht freies Budget (sonst `429`, wie sonst auch, oder ein kurzes Warten auf den nächsten Platz, siehe „Schlüsselarten und Solo-Stempel“); wer in ein offenes Fenster kommt, verbraucht
  davon nichts. Der Stempel des Dienstes ist verbraucht, auch wenn der Dienst fehlschlägt (wie im Einzelbetrieb).
- `perMinutePerKey` und `perMinuteTotal` **zählen weiter jede Anfrage**, auch innerhalb eines Fensters. **Folge:** das
  Relay nimmt höchstens `perMinuteTotal` = 60 Anfragen je Minute an (ein Schlüssel höchstens 20), ein Fenster wird
  also nie größer als das; ein `RELAY_BATCH_MAX` über 60 füllt sich nur, wenn die Grenzen geändert werden (sie wurden
  für den Sammelbetrieb **nicht** geändert, siehe „Offene Punkte“).
- Eine abgewiesene Anfrage (`401`, `400`, `415`, `429`, `503`) kommt nie in ein Fenster und kostet kein Budget.
- Der Wiederholungsspeicher gegen abgespielte Köpfe und die Prüfung der Frische arbeiten unverändert.
- **Zähler:** `stamped` zählt die Stempel, die der Dienst gegeben hat (im Sammelbetrieb einen je Fenster), und es gibt
  `batched`, die Zahl der mit einem Beleg beantworteten Anfragen. Beides sind reine Summen. Ein Fehler im Fenster zählt
  unter `refused` **je Anfrage** (`upstream-failed` usw.), `upstream-too-old` einmal je Fenster. Das Relay protokolliert
  weder Hashes noch Salze, Pfade, Kennungen oder Adressen.
- **Speicher:** je Fenster und Dienst warten höchstens `RELAY_BATCH_MAX` Anfragen; ein volles Fenster nimmt keine
  weiteren auf (die nächste Anfrage öffnet ein neues, wenn das Dienstbudget es zulässt). Dazu kommen Fenster, deren
  Aufruf beim Dienst läuft (höchstens `upstreamTimeoutMs`, 10 s). Insgesamt warten nie mehr Anfragen, als
  `perMinuteTotal` (60 je Minute) in Fenster plus Dienstzeit hineinlässt.

### Fehlerfälle

| Fall                                                            | Folge                                                                                                                                                                                     |
| --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Dienst nicht erreichbar, Frist, Ablehnung, ungültiges Token     | **Alle** Anfragen des Fensters bekommen dieselbe Antwort wie sonst (`502`/`504` mit demselben Code und `reason`)                                                                          |
| Das Relay wird beendet (`SIGTERM`), Fenster ist offen           | Die wartenden Anfragen bekommen `503 shutting-down`, nichts hängt; ein Fenster, dessen Aufruf läuft, wird noch fertig                                                                     |
| Neue Anfrage nach dem Beenden                                   | `503 shutting-down`                                                                                                                                                                       |
| Prozess stirbt, Neustart                                        | Wartende Anfragen verlieren die Verbindung (kein Zustand wird gespeichert); die App versucht es neu, mit frischem Kopf                                                                    |
| Ein Client bricht ab, während er wartet                         | Sein Blatt bleibt im Baum (der Baum ist beim Schließen schon festgelegt), die anderen werden bedient; Zähler `client-aborted`                                                             |
| Dienstbudget aufgebraucht, wenn ein neues Fenster öffnen müsste | `429` mit `Retry-After`, wenn der nächste Platz später als `RELAY_MAX_WAIT_MS` frei wird; sonst wartet die Anfrage (siehe „Schlüsselarten und Solo-Stempel“, danach höchstens `503 busy`) |

### Latenz und Fristen

Die Antwort kommt **nach dem Fenster** plus der Zeit des Dienstes, im ungünstigsten Fall nach `RELAY_BATCH_MS` + 10 s
(`upstreamTimeoutMs`) + Prüfung. Die Frist von 5 s (`requestTimeoutMs`) gilt nur dem **Lesen der Anfrage**; die Antwort
darf später kommen. **Folge für die Fristen:**

- Die Frist der App ab Sendebeginn ist **mindestens `RELAY_BATCH_MS` + 17 s** (statt 17 s); bei 5000 ms also 22 s
  (`AbortSignal.timeout(batchMs + 17_000)`).
- Der Reverse-Proxy braucht ein Lese-Timeout von mindestens **Fenster + 17 s** (nginx `proxy_read_timeout`, Caddy
  `response_header_timeout`), besser 3 s mehr. Mit dem Wert aus „Betrieb hinter einem Reverse-Proxy“ (17 bis 20 s)
  bricht der Proxy Anfragen ab, die das Relay noch zählt.
- Wartet eine Anfrage zusätzlich auf einen freien Platz (siehe „Schlüsselarten und Solo-Stempel“), kommt die Wartezeit
  dazu: Frist der App und Lese-Timeout des Proxys mindestens **`RELAY_MAX_WAIT_MS` + Fenster + 17 s** (Vorgabe 30 s
  Wartegrenze: bei 5 s Fenster 52 s; bei einer Wartegrenze von 60 s und einem Fenster von 60 s 137 s). Ohne Fenster
  (Solo-Stempel) genügt Wartegrenze + 17 s.
- Sie ist **keine Echtzeit**: wer sofort einen Stempel braucht, nimmt den Einzelbetrieb (eine zweite Relay-Instanz
  ohne `RELAY_BATCH_MS`).

### Client-Rezept

```ts
import { fromBase64Url, verifyBatchedTimestamp, verifyTimestampToken } from 'zeitstempel';

// … Anfrage wie in „Die App als Client“ signieren und senden, mit der längeren Frist:
//   fetch(relay + path, { method: 'POST', headers, body, signal: AbortSignal.timeout(batchMs + 17_000) })
const body = await res.json(); // 200 { service, genTime, accuracyMs, serial, token, batch? }
const token = fromBase64Url(body.token)!;
const options = { now: new Date(), minGenTime: new Date(sentMs - 60_000) };
const verified =
  body.batch === undefined
    ? await verifyTimestampToken(token, hash, [ankerPem], options) // Einzelstempel
    : await verifyBatchedTimestamp({ token, hash, batch: body.batch }, [ankerPem], options);
if (!verified.ok) throw new Error(verified.reason);
// Aufbewahren, zusammen mit dem Hash: Kennung des Dienstes, body.token und das GANZE body.batch
// (salt, index, size, path). Ohne das Salz und den Pfad lässt sich der Beleg nicht mehr rechnen.
const record = {
  service: body.service,
  hash: toBase64Url(hash),
  token: body.token,
  batch: body.batch,
};
```

`verifyBatchedTimestamp` rechnet das Blatt aus `hash` und `salt`, folgt dem Pfad bis zur Wurzel, bildet `imprint` und
prüft das Token dagegen mit `verifyTimestampToken` (dieselben Anker und Optionen, dasselbe Ergebnis, dazu
`batch: { size, index }`). Ein Pfad, der zu einer anderen Wurzel führt, ein verändertes Salz, ein anderer Hash,
`index` oder `size` und ein Token eines anderen Fensters enden alle in **`imprint-mismatch`**; es gibt dafür keinen
eigenen Code. Eine Form, die kein Beleg dieses Baumes sein kann (`size` oder `index` außerhalb, Pfad der falschen
Länge, falscher Typ oder falsche Größe eines Feldes, unbekanntes Feld), ist **`bad-batch`**.

### Was der Beleg sagt, und was nicht

- **Vertraulichkeit gegenüber dem Dienst:** Der externe Dienst sieht **nur `imprint`**, keinen Hash eines Einreichers
  und nicht einmal die Wurzel. Ein Dienst nur über `http` (`digicert`, `certum`) lässt diesen Wert auf der Strecke
  mitlesen, aber auch er verrät keinen Hash.
- **Vertraulichkeit gegenüber anderen Einreichern:** Der Beleg enthält die Geschwister-Knoten des Pfades. Jedes Blatt ist
  mit einem Salz verschleiert, das nur der Einreicher kennt (256 Bit, vom Relay gezogen); ein anderer Einreicher kann
  daraus keinen fremden Hash erraten oder bestätigen. Er erfährt die Zahl der Blätter (`size`).
- **Das Relay sieht alle Hashes** (wie im Einzelbetrieb), dazu zieht es die Salze: wer dem Relay nicht traut, was die
  Vertraulichkeit angeht, stempelt einen gesalzenen Hash. Die Bindung an den Hash muss die App dem Relay nicht glauben:
  sie rechnet den Beleg selbst nach.
- **Beweiskraft:** Der Beleg zeigt, dass der Hash **in der Menge** lag, die der Dienst zu `genTime` gestempelt hat. Es
  gibt **keinen Einzelstempel auf den Hash**. Wie jeder Stempel der mitgelieferten Dienste ist er **nicht qualifiziert**
  und hat keine Sperrprüfung (`docs/grenzen.md`). Das Relay könnte weitere Blätter in den Baum legen; es kann aber keinen
  Hash nachträglich aus einem gestempelten Baum nehmen oder zurückdatieren.
- **Kein ERS:** Das Format des Belegs ist **kein Evidence Record (ERS, RFC 4998 und RFC 6283)**. Es ist ein eigenes
  JSON-Format; der Baum hat zwar die Form von RFC 6962/9162 (innere Knoten mit `0x01`, Blätter mit `0x00`, geteilt
  bei der größten Zweierpotenz, kein verdoppeltes Blatt) und der Wert, den der Dienst stempelt, trägt die Zahl der
  Blätter, aber ERS rechnet mit sortierten Hash-Gruppen ohne diese Präfixe und mit einem eigenen ASN.1-Aufbau samt
  Erneuerung (neue Zeitstempel auf alte). Eine Umrechnung in einen ERS ist **nicht möglich**, und die Werkzeuge der
  Beweiswerterhaltung (z. B. nach BSI TR-ESOR) lesen diesen Beleg nicht. Wer **juristische Verwertbarkeit** oder eine
  Erneuerung der Beweiskraft über Jahre braucht, braucht einen ERS-Export oder einen Einzelstempel (`mode: "solo"`);
  ob ein ERS-Export gebaut wird, entscheidet der Eigentümer. Die Prüfpfade und Wurzeln stimmen mit den
  veröffentlichten RFC-6962-Werten überein (`tests/batch-vectors.test.ts`).
- **Aufbewahren:** Hash, Token und der ganze Beleg gehören zusammen. Geht das Salz oder der Pfad verloren, ist der
  Stempel für diesen Hash nicht mehr nachzuweisen (er lässt sich nicht aus dem Token wiederherstellen).

### Offene Punkte

- `perMinuteTotal` (60) und `perMinutePerKey` (20) bremsen die Fenstergröße; für große Fenster müssten sie im Sammelbetrieb
  je Fenster statt je Anfrage zählen oder höher stehen (Entscheidung des Eigentümers, derzeit nicht geändert).
- Nicht ausgerollt, nicht von einem Menschen geprüft, nicht im Browser getestet; der Test nutzt einen Stub als Dienst,
  gegen einen echten Dienst lief der Sammelbetrieb nicht (kein Netz).

## Schlüsselarten und Solo-Stempel

Nur im Sammelbetrieb. Ohne `RELAY_BATCH_MS` bekommt jede Anfrage ohnehin einen direkten Stempel: `mode: "solo"` ändert
dann nichts, und die Schlüsselart wird nicht geprüft (Typ-1-Prüfung entfällt).

### Die zwei Schlüsselarten

| Art | Eintrag in der Schlüsseldatei                | Darf                                                                                                     |
| --- | -------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| 1   | `{"id", "publicKey"}` (oder `"solo": false`) | normal stempeln (Beleg im Sammelfenster); Solo nur, wenn für den Dienst **niemand sonst wartet**         |
| 2   | `{"id", "publicKey", "solo": true}`          | Solo-Stempel immer verlangen, im Rahmen der Grenzen (`soloPerMinutePerKey`, Warteschlange, Dienstbudget) |

`solo` muss ein **boolescher** Wert sein (`true`/`false`); alles andere ist ein Fehler der Schlüsseldatei
(`config-error` beim Start, beim Neulesen `keyReloadFailed`; die Meldung nennt den Eintragsindex `keys[i]`, nie den
Inhalt). Die Art gehört zur Konfiguration des Relays, **nicht** zur Anfrage. Schlüssel der Art 2 vergibt nur der
Eigentümer; `node scripts/make-key.ts <kennung> --solo` gibt den Eintrag mit `"solo": true` aus (sonst nichts anderes).

### Die Anfrage

`{"hash": "<base64url>", "mode": "solo"}`. Der Modus steht **im Körper**, und der Körper ist über seinen Hash an die
Signatur gebunden: ein nachträglich hinzugefügtes oder entferntes `mode` ändert den Körper-Hash und endet mit `401`
(ein Test belegt beides). Unbekannte Werte (`"normal"`, `"SOLO"`, `1`, `null` …) sind `400 bad-mode`; ein weiteres Feld
oder ein fehlender Hash bleibt `400 bad-hash`. Rohbytes (`application/octet-stream`) können keinen Modus tragen und sind
immer eine normale Anfrage. `signRelayRequest` bleibt unverändert: die App legt `mode` in den Körper, den sie signiert.

```ts
const body = JSON.stringify({ hash: toBase64Url(hash), mode: 'solo' });
const header = await signRelayRequest({
  privateKey,
  keyId,
  method: 'POST',
  path,
  body: new TextEncoder().encode(body),
  nowMs: Date.now(),
}); // Result<string>: der Wert des Kopfes X-Zeitstempel-Auth
```

Die **Antwort** ist ein gewöhnlicher Einzelstempel **ohne** `batch`: der Dienst stempelt den Hash selbst (so verlangt es
ein PDF-Dokumentzeitstempel, `docs/recherche.md` §5). Die App prüft sie mit `verifyTimestampToken` (nicht mit
`verifyBatchedTimestamp`); sie muss beide Formen verarbeiten (mit und ohne `batch`).

### Zulassung

1. Art 2: Solo immer, im Rahmen der Grenzen.
2. Art 1: Solo nur, wenn das Fenster des Dienstes **leer** ist (kein offenes Fenster mit wartenden Anfragen und keine
   Anfrage in der Warteschlange des Dienstes), sonst `403 solo-not-allowed` (Zähler `soloDenied`); die Prüfung
   geschieht vor dem Budget und kostet nichts. **Nebenwirkung:** die Antwortart verrät einem Schlüssel der Art 1 grob,
   ob für den Dienst gerade jemand anderes wartete.
3. Zusätzlich gilt für jedes Solo die **eigene niedrige Grenze je Schlüssel** `soloPerMinutePerKey` (4 je Minute, nur im
   Arbeitsspeicher): die fünfte Anfrage in der Minute ist `429` mit `Retry-After`. Diese Zahl steht **nicht im Log**
   (keine Zahlen je Schlüssel im Betreiberlog); die Zähler unten sind Summen.

### Der Planer je Dienst

Fenster gelten **immer je externem Dienst**. Ein **Platz** ist ein Stempel des Dienstes im Rahmen seines Budgets
(`60000 / minIntervalMs` je Minute); ein Sammelfenster belegt einen Platz, ein Solo-Stempel ebenfalls (er belegt den
Platz ganz, nicht nur einen Teil des Fensters). Ein Fenster ist **voll** durch `RELAY_BATCH_MAX` oder durch einen
Solo-Stempel; **der Rest wartet**.

- **Warten nur im Mangelfall.** Ist ein Platz frei, wird die Anfrage sofort bedient (ein Fenster öffnet, ein Solo-Stempel
  geht an den Dienst); eine Anfrage in ein **offenes** Fenster braucht keinen Platz.
- **Abwechselnd.** Warten ein Solo-Stempel und ein Sammelfenster zugleich, bekommen sie die Plätze **abwechselnd**: nichts
  verhungert. Das Fenster nimmt alle wartenden normalen Anfragen bis `RELAY_BATCH_MAX` auf; der Rest wartet auf den
  nächsten Platz.
- **Wartegrenze `RELAY_MAX_WAIT_MS`** (ganze Zahl 1000 bis 60000, Vorgabe 30000, streng gelesen, ungültig = deutsche Zeile
  `config-error`): wer so lange keinen Platz bekommt, bekommt `503 busy` mit `Retry-After`. Ist schon beim Eingang klar,
  dass der nächste Platz **später** als die Wartegrenze frei wird (Dienstbudget für längere Zeit aufgebraucht), bleibt es
  beim bisherigen `429 rate-limited`; gewartet wird nur bei einem kurzen Engpass.
- **Die Solo-Warteschlange je Dienst ist begrenzt** (`soloQueueMax`, 6): eine weitere Solo-Anfrage bekommt sofort
  `503 busy`. Die normalen Wartenden sind durch `perMinuteTotal` und die Wartegrenze begrenzt.
- Die 60 s der Anmeldung (Zeitfenster der Signatur) und die ±60 s der Frischeprüfung des Tokens werden von der
  Wartezeit nicht berührt: sie werden beim Eingang beziehungsweise beim Senden an den Dienst gemessen.
- `perMinuteTotal` (60) und `perMinutePerKey` (20) bleiben **unverändert** und zählen jede angenommene Anfrage, auch eine
  Solo-Anfrage und auch eine, die später `503 busy` bekommt (das Budget wird bei der Annahme verbraucht und nicht
  zurückgegeben). Mit den mitgelieferten Diensten werden sie weiterhin nicht erreicht; das Solo-Limit je Schlüssel (4)
  liegt unter `perMinutePerKey` (20), die Grenzen kollidieren also nicht.
- **Kapazität:** ein Solo-Stempel kostet einen ganzen Platz. Mit FreeTSA (12 Plätze je Minute) und abwechselnder Vergabe
  höchstens 6 Solo-Stempel je Minute für **alle** Schlüssel der Art 2 zusammen (sonst bleibt der Sammelbetrieb stehen);
  bei den Diensten mit 15 s sind es 4 Plätze, also höchstens 2.
- **Beim Beenden** (`SIGTERM`, `restartAfter`) bekommen auch die auf einen Platz Wartenden `503 shutting-down`.

### Zähler

Nur Summen, nichts je Schlüssel, nichts von der Anfrage (Variante A). Sie erscheinen in `relay.stats()` und in der
Zeile `counts` erst, wenn sie zum ersten Mal gezählt wurden:

| Zähler            | Bedeutung                                                                                                             |
| ----------------- | --------------------------------------------------------------------------------------------------------------------- |
| `solo`            | Solo-Stempel, die der Dienst gegeben hat (zählt auch in `stamped`)                                                    |
| `soloDenied`      | Solo-Anfragen der Art 1, die `403 solo-not-allowed` bekamen (auch unter `refused`)                                    |
| `keyReloads`      | Neulesen der Schlüsseldatei, das übernommen wurde (das erste Lesen nach dem Start zählt nicht)                        |
| `keyReloadFailed` | Neulesen, das verworfen wurde (ungültige oder verschwundene Datei, der alte Satz bleibt); je Zustand der Datei einmal |

`busy` und `solo-not-allowed` stehen außerdem unter `refused` wie jeder Fehlercode.

### Schlüsseldatei laufend lesen

Das Relay sieht alle `keyFileCheckMs` (5 s) nach, ob sich Änderungszeit, Größe oder Inode der Schlüsseldatei geändert
haben, und liest sie dann **streng** neu (dieselben Regeln wie beim Start).

- **Neuer Schlüssel:** gilt ab dem Übernehmen. **Entfernter Schlüssel:** ist **sofort** ungültig (jede Anfrage prüft gegen
  den aktuellen Satz); das ist der Weg, einen Schlüssel zu **sperren**. Auch eine geänderte Art (`solo`) gilt sofort.
- **Ungültige Datei** (kein JSON, Regelverstoß, halb geschrieben, verschwunden): der **alte Satz bleibt aktiv**,
  `keyReloadFailed` zählt, es wird nichts aus der Datei protokolliert. Schon beim nächsten Nachsehen wird es erneut
  versucht (eine halb geschriebene Datei wird so bald gelesen, wie sie fertig ist).
- **Zähler, Wiederholungsspeicher und Solo-Zähler bleiben** beim Neulesen erhalten.
- **Das Relay schreibt nie in die Schlüsseldatei.** Sie gehört dem Betreiber; schreiben soll man sie atomar (neue Datei
  schreiben, dann umbenennen).
- Gilt nur mit `RELAY_KEYS_FILE` (nicht mit `RELAY_AUTH=off`).

### `restartAfter`: einmaliger sauberer Neustart

Optionales Feld der Schlüsseldatei auf oberster Ebene: `{"version": 2, "restartAfter": 1795000000, "keys": […]}`, eine
ganze Zahl in Unix-Sekunden (1000000000 bis 99999999999, sonst ist die Datei ungültig). Das Relay merkt sich seine
Startzeit. Gilt `Startzeit / 1000 < restartAfter <= jetzt / 1000`, beendet es sich **einmal** sauber (wie bei `SIGTERM`:
`close()` beantwortet Wartende mit `503 shutting-down`, die Verbindungen enden, **Exit-Code 0**, eine Zeile
`{"event":"restart-after"}`). Ein **Prozess-Überwacher** (systemd `Restart=always`, Docker `restart: always`) startet es
neu; ohne Überwacher bleibt es aus. Der neue Prozess startet **nach** `restartAfter` und beendet sich deshalb nicht
erneut: keine Schleife, auch wenn die Datei unverändert bleibt. Das Relay schreibt **nie** in die Datei.

Ein Neustart leert den Wiederholungsschutz (Lücke bis zu 120 s, siehe oben „Grenzen“ der Anmeldung) und die Zähler;
**das laufende Neulesen ist deshalb der Normalweg**, `restartAfter` die Ausnahme (z. B. wenn ein Prozess nach einer
Änderung der Einstellungen neu starten soll).

### Warnung: Solo-Schlüssel im Browser

Ein privater Schlüssel, den eine Web-App im Browserspeicher hält, ist **für die Nutzer dieses Browsers auslesbar**.
Schlüssel der Art 2 daher **nur an vertraute Nutzergruppen** ausgeben (ein Schlüssel je Nutzergruppe); das niedrige
Solo-Limit je Schlüssel begrenzt den Schaden, und ein missbrauchter Schlüssel wird **durch Entfernen aus der Datei**
gesperrt (wirkt nach spätestens `keyFileCheckMs`, sobald die Datei gespeichert ist). Wer einen Solo-Schlüssel
hat, kann die Solo-Plätze eines Dienstes bis zu dessen Kapazität belegen (siehe „Kapazität“).

## Zugangsdaten zu bezahlten Diensten

Ein bezahlter Dienst will Zugangsdaten sehen. Die App darf sie **selbst mitliefern** (wie sie ihren Relay-Schlüssel
selbst verwahrt), oder das Relay hält sie. Die vier mitgelieferten freien Dienste haben kein Feld `auth` und ändern
sich nicht: für sie wird nichts gesendet, und ein `upstream` in der Anfrage ist `400 bad-upstream`.

### Arten und Quellen (`auth` in `services.json`)

`auth: {"kind": …, "source": …}`; ohne das Feld gilt `{"kind": "none"}`. Der Leser ist streng: unbekannte Felder und Werte,
ein fehlendes Feld, falsche Typen ergeben `bad-services`.

| `kind`   | Was das Relay dem Dienst schickt                                                                 | `upstream` im Körper der App     |
| -------- | ------------------------------------------------------------------------------------------------ | -------------------------------- |
| `none`   | nichts (kein Feld `source`)                                                                      | nicht erlaubt                    |
| `basic`  | `Authorization: Basic <base64(Benutzer:Passwort)>` (RFC 7617)                                    | `{"user": "…", "password": "…"}` |
| `bearer` | `Authorization: Bearer <Token>`                                                                  | `{"token": "…"}`                 |
| `header` | `<Name>: <Token>`; `Name` steht in `services.json` (`"header": "X-Api-Key"`), nie in der Anfrage | `{"token": "…"}`                 |

Der Headername muss `[A-Za-z0-9-]{1,40}` sein und darf keiner der verbotenen oder Hop-by-hop-Köpfe sein (`Authorization`
(dafür gibt es `basic` und `bearer`), `Host`, `Content-Type`, `Content-Length`, `Transfer-Encoding`, `Connection`,
`Upgrade`, `TE`, `Cookie`, `Set-Cookie`, `User-Agent`, `Accept`, `Date`, `Origin`, Köpfe mit `Proxy-`, `Sec-`, `If-`,
`X-Forwarded-`, `Access-Control-`, `X-Zeitstempel`, …; ohne Rücksicht auf Groß- und Kleinschreibung). **`basic`, `bearer`
und `header` sind nur für `https`-Adressen erlaubt:** der Leser lehnt eine `http`-Adresse mit `auth` ab (`bad-services`), das
Relay startet nicht damit, und `relay/upstream.ts` baut vor jeder Verbindung keine Anfrage mit Zugangsdaten an einen
`http`-Dienst auf (`upstream-failed`, ohne Verbindung).

| `source` | Wer liefert                                                                                                                                                              |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `relay`  | nur das Relay, aus seiner Umgebung (`RELAY_UPSTREAM_AUTH_<ID>`); ein `upstream` der App ist `400 bad-upstream`; fehlt der Wert, startet das Relay nicht (`config-error`) |
| `client` | nur die App; `upstream` ist **Pflicht**, sonst `400 bad-upstream`; das Relay hält nichts (eine Variable dafür ist ein Fehler beim Start)                                 |
| `either` | die App, wenn sie `upstream` mitschickt (**Vorrang**), sonst die Werte des Relays, sonst `400 bad-upstream`                                                              |

### Der Körper und seine Grenzen

```ts
const body = JSON.stringify({
  hash: toBase64Url(hash),
  upstream: { user: 'konto', password: '…' }, // basic; bei bearer und header: { token: '…' }
}); // optional zusätzlich mode: 'solo'
const header = await signRelayRequest({
  privateKey,
  keyId,
  method: 'POST',
  path,
  body: new TextEncoder().encode(body),
  nowMs: Date.now(),
});
```

`signRelayRequest` bleibt unverändert: die App baut den Körper selbst und signiert ihn. **`upstream` steht im signierten
Körper**, ist also durch die Signatur gebunden: ein nachträglich geänderter, hinzugefügter oder entfernter Wert ändert den
Körper-Hash und endet mit `401` (Tests belegen es). Ohne gültigen Relay-Schlüssel gibt es weiterhin keine Anfrage und
damit auch keine Weitergabe von Zugangsdaten.

Strenge Prüfung (`400 bad-upstream` bei jedem Verstoß, nach bestandener Anmeldung): genau die Mitglieder der Art, nur
Strings; **druckbares ASCII** (0x20 bis 0x7E; beim Token ohne Leerzeichen, `"` und `\`), also keine Steuerzeichen, kein
CR/LF (Header-Einschleusung), kein NUL, kein Nicht-ASCII; der Benutzername bei `basic` ohne `:` (RFC 7617), das Passwort darf
`:` enthalten; leere Werte sind abgelehnt; Längen `upstreamUserMax` (64), `upstreamPasswordMax` (128), `upstreamTokenMax` (384).
Auch im ungünstigsten Fall (jedes Zeichen maskiert) passt der Körper mit `hash`, `mode` und `upstream` in die 512 Byte, die
`signRelayRequest` höchstens signiert (ein Test belegt es). Die Prüfung läuft ein zweites Mal, bevor das Relay den Kopf an
den Dienst baut (`relay/upstream.ts`).

### Sammelbetrieb, Solo, Planer und Budget je Identität

Die **Identität** der Zugangsdaten ist ein SHA-256-Digest über Art und Felder (nur im Arbeitsspeicher, **nie ausgegeben,
nie ins Protokoll, in keinen Zähler und in keinen Fehlertext**); die Zugangsdaten des Relays und ein Dienst ohne `auth`
haben die Identität „der Dienst selbst“, wie bisher. **Fenster, Plätze, Warteschlangen und das Dienstbudget (`minIntervalMs`)
gelten je (Dienst, Identität).** Hashes mit verschiedenen Zugangsdaten landen **nie** im selben Fenster und nie im selben
Baum (der Dienst sähe sonst Hashes unter fremden Zugangsdaten gebündelt); ob einem Schlüssel der Art 1 ein Solo-Stempel erlaubt
ist (wartet sonst jemand?), wird **je Spur der Identität** entschieden.

- **Obergrenze:** höchstens `upstreamIdentitiesMax` (64) Identitäten je Dienst gleichzeitig. Eine Identität wird verworfen,
  wenn sie ein ganzes Fenster (60 s) ruhig war und nichts mehr für sie wartet (Fenster, Warteschlange, laufender Aufruf);
  dann fallen auch ihre Zähler weg. Eine **weitere neue** Identität bekommt `503 busy` mit `Retry-After` (die Sekunden bis
  zum Verfall der ersten); bekannte Identitäten gehen weiter. Eine abgelehnte Anfrage hinterlässt nichts.
- **Das Budget des Relays als Ganzes bleibt:** `perMinuteTotal` (60) und `perMinutePerKey` (20) zählen **jede** Anfrage
  über alle Dienste und Identitäten und ändern sich nicht. Ein Stempel beim Dienst setzt mindestens eine angenommene
  Anfrage voraus; die Zahl der Aufrufe bei Diensten (alle mit der IP des Relays) ist daher höchstens `perMinuteTotal` je
  Minute, auch wenn jede Identität ein eigenes Dienstbudget hat. Das Dienstbudget je Identität schützt das **Konto** bei
  einem Anbieter mit Kontolimit; ein **IP-Limit** des Anbieters schützt es nicht (das Relay hat nur eine Adresse), dafür
  steht `perMinuteTotal`.
- **Offen:** die Tabelle der Identitäten ist je Dienst für alle Schlüssel gemeinsam; ein Schlüssel mit vielen verschiedenen
  (auch falschen) Zugangsdaten kann sie füllen, bis die ersten ablaufen (`perMinutePerKey` bremst ihn auf 20 je Minute, mit
  mehreren Schlüsseln nicht). Falsche Zugangsdaten kosten einen Aufruf beim Dienst, der sie mit `401` ablehnt (`502
upstream-refused`).

### Was das Relay sieht

Die Zugangsdaten der App (im signierten Körper, im Arbeitsspeicher, solange eine Anfrage, ein Fenster oder die Spur der
Identität sie braucht) und beim Dienst den fertigen Kopf; **nie im Protokoll, nie in Zählern (`stats()`), nie in
Fehlerantworten.** Die Fehlerantworten nennen nur Codes (`bad-upstream`, `upstream-refused` …); ein Test setzt einen
Markierungswert in die Zugangsdaten und prüft Antwortkörper, Köpfe, `stats()`, Konsole und Prozessströme bei Erfolg und
bei jedem Fehler des Dienstes (Zeitüberschreitung, `failed`, `401`, ungültige Antwort). Das Relay folgt keiner
Weiterleitung, die Zugangsdaten gehen also nie an eine andere Adresse als die in `services.json`; Adresse, Pfad, Methode
und Zielhost kommen weiter nur von dort (kein offener Proxy). Der Betreiber sieht Zugangsdaten **im Speicher des
Prozesses** und, falls er sie dort ablegt, in der Umgebung (`RELAY_UPSTREAM_AUTH_<ID>`; das Relay entfernt die Variablen
nach dem Lesen aus `process.env`). Eigene Werte des Relays nie in das Repository, nie in ein Image.

### Warnungen und Grenzen

- **Zugangsdaten im Speicher eines Browsers** (`localStorage`, `IndexedDB`, im Quelltext der Seite) sind **für die Nutzer
  dieses Browsers auslesbar** und bei Cross-Site-Scripting offen; wie ein privater Relay-Schlüssel in der App. Wer sie dort
  hält, tut es nur für Zugänge, die diesen Nutzern gehören oder deren Missbrauch begrenzt ist (Kontolimit, Zugang nur für
  Stempel, widerrufbar).
- **Verträge:** Bezahlte Dienste (z. B. InfoCert Art. 7, Certum) untersagen die Weitergabe von Zugangsdaten an Dritte. Für die
  **eigene** App ist das Relay kein Dritter; für Zugangsdaten **fremder** Apps oder Kunden gilt das nicht, das ist vorher
  zu klären. Diese Aussage ist nicht rechtlich geprüft.
- **Nicht abgedeckt:** Dienste, die über die **IP-Freigabe** zugelassen werden (z. B. SK) oder ein **Zertifikat** verlangen
  (z. B. Disig, D-Trust), passen nicht zu diesem Verfahren; **Privatschlüssel von Zertifikaten werden nicht übertragen**.
  Es gibt nur `basic`, `bearer` und einen Namenskopf.
- Nicht ausgerollt, gegen keinen echten bezahlten Dienst getestet (kein Netz; Stubs im Test, ein TLS-Stub für den
  Weg nach draußen), nicht von einem Menschen geprüft, nicht im Browser getestet. Mitgelieferte Dienste haben kein `auth`:
  es gibt noch **keinen** Eintrag in `services.json`, der es nutzt.

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
  Hash und, bei einem bezahlten Dienst, den Zugangsdaten (streng geprüft, nur als ein Kopf nach `https`, siehe
  „Zugangsdaten zu bezahlten Diensten“).
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
- **Im Sammelbetrieb** prüft das Relay das Token gegen den `imprint` des Baumes (nicht gegen die Hashes der
  Einreicher); die Hashes bindet der Beleg, den die App selbst prüft.
- `Cache-Control: no-store`, `Vary: Origin`, `X-Content-Type-Options: nosniff`.

## Was das Relay sieht

Zeitpunkt und Netzadresse des Aufrufers (wie jeder Server), den **Hash** (im Sammelbetrieb zusätzlich die Salze, die es
zieht, und die Bäume; sie bleiben im Speicher, bis das Fenster beantwortet ist) und den Kopf `X-Zeitstempel-Auth`
(Kennung, Zeit, Signatur), nie Inhalte und nie den privaten Schlüssel. Es schreibt **nichts** über Anfragen ins Protokoll:
keine Adresse, keinen Hash, kein Token, keine Kennung, keine Signatur. Alle fünf Minuten steht eine
Zeile mit Zählern im Protokoll (Anzahl gestempelter Anfragen und Zahl der Ablehnungen je Art). Die
Netzadresse sieht allerdings die Infrastruktur davor (Hoster, Lastverteiler); das ist Sache des Betreibers.

## Grenzen (`relay/limits.ts`)

| Name                    | Wert   | Bedeutung                                                                                                                                                      |
| ----------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `bodyBytes`             | 512    | Größter Körper einer Anfrage                                                                                                                                   |
| `upstreamBytes`         | 65536  | Größte Antwort eines Dienstes                                                                                                                                  |
| `upstreamTimeoutMs`     | 10000  | Frist für den ganzen Aufruf beim Dienst                                                                                                                        |
| `requestTimeoutMs`      | 5000   | Frist für die ganze eingehende Anfrage (auch die Kopfzeilen)                                                                                                   |
| `perMinuteTotal`        | 60     | Anfragen je Minute über alle Dienste                                                                                                                           |
| `windowMs`              | 60000  | Zeitfenster der Zähler                                                                                                                                         |
| `perMinutePerKey`       | 20     | Anfragen je Minute für eine Schlüsselkennung (ein Drittel)                                                                                                     |
| `authWindowSeconds`     | 60     | Erlaubter Zeitunterschied (Sekunden) der Anfrage zur Relay-Uhr                                                                                                 |
| `authReplayEntries`     | 512    | Obergrenze gemerkter Nachrichten (real höchstens 180); voll: `429`                                                                                             |
| `authReplayKeyShare`    | 0.5    | Anteil des Speichers, den eine Kennung höchstens hält                                                                                                          |
| `genTimeSlackMs`        | 60000  | Token-Zeit: höchstens so weit vor dem Zeitpunkt der Anfrage und so weit hinter der Relay-Uhr (`time-too-old`, `time-in-future`)                                |
| `maxOrigins`            | 16     | Zahl der einstellbaren Herkünfte                                                                                                                               |
| `maxConnections`        | 256    | Gleichzeitig offene Verbindungen; weitere lehnt der Server ab                                                                                                  |
| `keepAliveProxyMs`      | 65000  | Leerlauf einer Verbindung zwischen zwei Anfragen bei Loopback-Bindung (`127.0.0.1`, `::1`, `localhost`; länger als der Leerlauf-Timeout üblicher Proxys, 60 s) |
| `keepAliveDirectMs`     | 5000   | Leerlauf bei jeder anderen Bindung (entspricht `requestTimeoutMs`)                                                                                             |
| `keepAliveMinMs`        | 1000   | `RELAY_KEEPALIVE_MS`: kleinster Wert                                                                                                                           |
| `keepAliveMaxMs`        | 120000 | `RELAY_KEEPALIVE_MS`: größter Wert                                                                                                                             |
| `batchMsMin`            | 1000   | `RELAY_BATCH_MS`: kleinster Wert (0 oder leer schaltet den Sammelbetrieb aus)                                                                                  |
| `batchMsMax`            | 60000  | `RELAY_BATCH_MS`: größter Wert                                                                                                                                 |
| `batchMaxDefault`       | 128    | `RELAY_BATCH_MAX`: Wert ohne Angabe                                                                                                                            |
| `batchMaxMin`           | 2      | `RELAY_BATCH_MAX`: kleinster Wert                                                                                                                              |
| `batchMaxMax`           | 1024   | `RELAY_BATCH_MAX`: größter Wert (so große Bäume prüft die Bibliothek, `MAX_SIZE`)                                                                              |
| `soloPerMinutePerKey`   | 4      | Solo-Anfragen je Minute für eine Schlüsselkennung (zusätzlich zu `perMinutePerKey`; nur im Arbeitsspeicher, nicht im Log)                                      |
| `soloQueueMax`          | 6      | Solo-Anfragen, die je Dienst auf einen Platz warten dürfen; eine weitere bekommt `503 busy`                                                                    |
| `maxWaitDefaultMs`      | 30000  | `RELAY_MAX_WAIT_MS`: Wert ohne Angabe                                                                                                                          |
| `maxWaitMinMs`          | 1000   | `RELAY_MAX_WAIT_MS`: kleinster Wert                                                                                                                            |
| `maxWaitMaxMs`          | 60000  | `RELAY_MAX_WAIT_MS`: größter Wert (Proxy- und Client-Fristen dann mindestens Wartegrenze + 17 s)                                                               |
| `upstreamUserMax`       | 64     | Zugangsdaten der App: längster Benutzername bei `basic` (druckbares ASCII, ohne `:`)                                                                           |
| `upstreamPasswordMax`   | 128    | längstes Passwort bei `basic` (druckbares ASCII)                                                                                                               |
| `upstreamTokenMax`      | 384    | längstes Token bei `bearer` und `header` (druckbares ASCII ohne Leerzeichen, `"` und `\`)                                                                      |
| `upstreamIdentitiesMax` | 64     | gleichzeitig bekannte Zugangsdaten-Identitäten je Dienst (nur Arbeitsspeicher); eine weitere neue bekommt `503 busy`                                           |
| `keyFileCheckMs`        | 5000   | Abstand, in dem das Relay die Änderungszeit der Schlüsseldatei prüft                                                                                           |

Je Schlüsselkennung gilt zusätzlich `perMinutePerKey`. Je Dienst gilt zusätzlich `60000 / minIntervalMs` Anfragen je Minute (bei 15 s: 4, bei FreeTSA mit 5 s: 12). `perMinuteTotal` und
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

**Leerlauf-Verbindungen (`keepAliveProxyMs`, `keepAliveDirectMs`, `RELAY_KEEPALIVE_MS`):** Der Leerlauf einer
Verbindung zwischen zwei Anfragen hängt von der Bindung ab:

- **Loopback-Bindung** (Vorgabe `127.0.0.1`; auch `::1` und `localhost`): 65 s (`keepAliveProxyMs`). Verbinden kann nur
  ein Proxy auf demselben Rechner; er bündelt viele Clients auf wenige Verbindungen und schließt unbenutzte nach
  seinem eigenen Leerlauf-Timeout (60 s ist üblich). Läge der Wert des Relays darunter, träfe eine Anfrage eine
  Verbindung, die das Relay gerade schließt (Fehler `502` am Proxy). **Ein Proxy mit Leerlauf-Timeout T braucht ein
  Relay-keepAlive größer als T**; bei einem größeren T als 60 s `RELAY_KEEPALIVE_MS` entsprechend setzen.
- **Jede andere Bindung** (`RELAY_HOST` nennt eine andere Adresse, z. B. `0.0.0.0` im Container): 5 s
  (`keepAliveDirectMs`, so lang wie die Frist für eine Anfrage). Mit 65 s könnte ein einzelner Client alle
  `maxConnections` (256) Plätze mit Leerlauf-Verbindungen füllen und sie über eine Minute halten, ohne eine Anfrage
  halb zu schicken; mit 5 s sind sie nach höchstens etwa 8 s frei (ein Test belegt es: 256 Verbindungen mit je einer
  Anfrage, danach wird ein weiterer Client bedient). Bei dieser Bindung ist der Proxy (oder die Infrastruktur davor)
  selbst für **Verbindungsgrenzen je Adresse** zuständig; das Relay kennt keine Adressen. Steht der Proxy auf einem
  anderen Rechner und hält Verbindungen länger als 5 s offen, trifft er gelegentlich eine schon geschlossene
  Verbindung (`502`): dann `RELAY_KEEPALIVE_MS` setzen (größer als sein Leerlauf-Timeout) und dafür sorgen, dass nur der
  Proxy das Relay erreicht (Netzwerkregel).
- **`RELAY_KEEPALIVE_MS`** (ganze Zahl von 1000 bis 120000, streng gelesen: ungültig bricht den Start mit einer Zeile
  `config-error` ab) übersteuert beide Werte. Wer ihn bei einer Nicht-Loopback-Bindung hoch setzt, übernimmt das
  Risiko oben bewusst.

Die Frist für eine **Anfrage** (`requestTimeoutMs`, 5 s, auch für die Kopfzeilen) gilt unverändert auch auf einer
Verbindung, die schon benutzt wurde (ein Test belegt es: eine halbe zweite Anfrage endet mit `408`), und
`maxConnections` ist unverändert 256. Mit einem Reverse-Proxy auf demselben Rechner sieht das Relay nur dessen wenige
Verbindungen; der Schutz vor vielen Verbindungen eines Clients ist Sache des Proxys (Verbindungs- und Ratenlimit je
Adresse).

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
  dazu die Prüfung. Kürzere Fristen des Proxys brechen Stempel ab, die das Relay noch zählt. **Im Sammelbetrieb**
  kommt das Fenster dazu: mindestens `RELAY_BATCH_MS` + 17 s („Sammelbetrieb“, „Latenz und Fristen“).
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
  (bei 15 s: **4 Stempel je Minute**; FreeTSA hat 5 s: 12). Mit FreeTSA allein (dem einzigen Dienst mit ausdrücklich erlaubter
  allgemeiner Nutzung, `docs/dienste.md`) sind das 12 Stempel je Minute für alle. Das Budget wird **auch bei einem Fehler des Dienstes
  oder einem ungültigen Token verbraucht** (die Anfrage ging hinaus). Wer mehr braucht, bündelt (Merkle-Wurzel; das Relay kann das selbst: „Sammelbetrieb“) oder
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
