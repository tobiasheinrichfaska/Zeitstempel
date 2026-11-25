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

| Einstellung                | Bedeutung                                                                                                                                                                                                                                                                                                                                                | Vorgabe                                      |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| `PORT`                     | Port, ganze Zahl von 1 bis 65535, nur Dezimalziffern (`0x50`, `1e2`, Leerzeichen, `0` und ein leerer Wert beenden den Start; `0` = vom System gewählter Port ist nicht erlaubt, Proxy und Firewall brauchen einen bekannten Port)                                                                                                                        | 8080                                         |
| `RELAY_ORIGINS`            | Browser-Herkünfte, durch Komma getrennt, genau `https://host[:port]` (oder `http://localhost…`)                                                                                                                                                                                                                                                          | keine                                        |
| `RELAY_ALLOW_PLAIN_HTTP`   | `1` erlaubt Dienste, die nur über `http` antworten                                                                                                                                                                                                                                                                                                       | aus                                          |
| `RELAY_SERVICES`           | Kennungen der angebotenen Dienste, durch Komma getrennt; **Pflicht** (Start bricht sonst ab)                                                                                                                                                                                                                                                             | keine                                        |
| `RELAY_KEYS_FILE`          | Pfad der Schlüsseldatei (siehe „Zugangsschlüssel“); Pflicht, außer mit `RELAY_AUTH=off`                                                                                                                                                                                                                                                                  | keine                                        |
| `RELAY_AUDIENCE`           | Der Name dieses Relays im signierten Kopf (Audience): druckbares ASCII ohne Leerzeichen, 1 bis 128 Zeichen, üblich die öffentliche Herkunft (`https://relay.example`); **Pflicht mit `RELAY_KEYS_FILE`** (sonst Startabbruch, `RELAY_AUDIENCE fehlt …`), bei `RELAY_AUTH=off` nicht nötig; je Instanz und Umgebung eine eigene, siehe „Zugangsschlüssel“ |
| `RELAY_AUTH`               | nur `off` ist gültig: Start ohne Schlüssel, **nur für die lokale Entwicklung**                                                                                                                                                                                                                                                                           | aus                                          |
| `RELAY_HOST`               | Adresse, auf der das Relay lauscht; mit `RELAY_AUTH=off` nur eine Loopback-Adresse erlaubt                                                                                                                                                                                                                                                               | `127.0.0.1`                                  |
| `RELAY_KEEPALIVE_MS`       | Leerlauf einer Verbindung zwischen zwei Anfragen in ms, ganze Zahl 1000 bis 120000 (übersteuert beide Werte, siehe „Leerlauf-Verbindungen“)                                                                                                                                                                                                              | nach Bindung: 65000 bei Loopback, sonst 5000 |
| `RELAY_BATCH_MS`           | Sammelbetrieb: Fenster in ms, ganze Zahl 1000 bis 60000; leer oder `0` = aus (jede Anfrage bekommt einen eigenen Stempel); siehe „Sammelbetrieb“                                                                                                                                                                                                         | aus                                          |
| `RELAY_BATCH_MAX`          | Sammelbetrieb: höchstens so viele Anfragen in einem Fenster, ganze Zahl 2 bis 1024; ein volles Fenster schließt sofort                                                                                                                                                                                                                                   | 128                                          |
| `RELAY_UPSTREAM_AUTH_<ID>` | Zugangsdaten eines bezahlten Dienstes, die das Relay selbst hält (`<ID>`: Kennung in Großbuchstaben, `-` als `_`); `Benutzer:Passwort` bei `basic`, sonst das Token; **Pflicht** für einen gewählten Dienst mit Quelle `relay`, **freiwillig** bei `either`; siehe „Zugangsdaten zu bezahlten Diensten“                                                  | keine                                        |
| `RELAY_MAX_WAIT_MS`        | Längste Wartezeit einer Anfrage in ms, ganze Zahl 1000 bis 60000: im Sammelbetrieb auf einen freien Platz beim Dienst, im Einzelbetrieb auf den Mindestabstand zum letzten Aufruf des Dienstes; danach `503 busy`; siehe „Schlüsselarten und Solo-Stempel“ und „Grenzen (`relay/limits.ts`)“                                                             | 30000                                        |
| `RELAY_KEY_SHARE`          | Anteil in ganzen Prozent, 10 bis 100 (Vorgabe 100 = aus, nichts ändert sich): so viel vom Minutenbudget **eines Dienstes** darf **eine** Schlüsselkennung höchstens belegen; darüber `429 key-share`; leerer oder ungültiger Wert = Startabbruch; siehe „Anteil je Schlüssel am Dienstbudget“                                                            |

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

**Kopf:** `X-Zeitstempel-Auth: v3.<kid>.<ts>.<jti>.<sig>`

- `ts`: Unix-**Millisekunden**, ganze Dezimalzahl ohne führende Nullen (12 bis 15 Stellen, im heutigen Bereich 13).
- `jti`: 16 zufällige Byte, die die App **für jede Anfrage neu** wählt, als base64url ohne `=` (22 Zeichen, nur die eine
  kanonische Schreibweise: die 4 überzähligen Bits des letzten Zeichens sind 0). Das `jti` macht jede Anfrage einzeln
  und ist der Schlüssel des Wiederholungsspeichers.
- `sig` = base64url (ohne `=`, 86 Zeichen) der 64 Byte `r || s` (IEEE P1363, so wie WebCrypto ECDSA/SHA-256 sie
  ausgibt) über die Nachricht `"zeitstempel-auth-v3\n" + METHODE + "\n" + PFAD + "\n" + AUD + "\n" + ts + "\n" + jti +
"\n" + hex(SHA-256(Körper))`. `PFAD` ist der Pfad ohne Abfrage (`/v1/stamp/freetsa`), `Körper` sind die rohen Bytes,
  wie gesendet, `AUD` ist die Audience (nächster Absatz). Die Kennung ist nicht Teil der Nachricht; sie wählt den
  Schlüssel, gegen den geprüft wird. Die Bibliothek rechnet das: `signRelayRequest` (siehe unten). Köpfe früherer
  Fassungen (`v1.…` HMAC, `v2.…` Sekunden ohne `jti` und ohne Audience) werden wie jede falsche Form mit `401` abgelehnt.
- **Audience (`AUD`):** der Name dieses Relays, den der Betreiber in `RELAY_AUDIENCE` setzt (druckbares ASCII ohne
  Leerzeichen, 1 bis 128 Zeichen; üblich die öffentliche Herkunft, z. B. `https://relay.example`) und der App mitteilt.
  Die App trägt ihn bei `signRelayRequest({ audience })` ein; das Relay prüft, dass die signierte `AUD` **genau** seiner
  eigenen gleicht (Byte für Byte, auch Groß- und Kleinschreibung und ein Schrägstrich am Ende zählen). Weil sie in der
  Signatur steht, gilt ein bei einem Relay abgefangener Kopf bei einem anderen nicht, auch wenn beide dieselbe
  Schlüsseldatei benutzen: **je Instanz und je Umgebung (Test, Betrieb) eine eigene Audience**. Die Audience ist kein
  Geheimnis.

**Was das Relay prüft** (jeder Fehler der Anmeldung ist ein einheitliches `401 {"error":"unauthorized"}`; die
Antwort verrät nicht, ob Kennung, Zeit oder Signatur falsch war. Die Reihenfolge der Prüfungen: `403`
(Herkunft), `400` (Anfrageziel, Abfragezeichenfolge), `405` (Methode), `404` (Dienst), dann `401` (Anmeldung),
`413` beim Lesen des Körpers, und erst nach der Anmeldung `415`/`400` (Hash) und `429`. Alles vor der
Anmeldung verrät nur Öffentliches (welche Dienste es gibt, das Größenlimit, die Form des Ziels) und ist kein
Orakel für Kennung oder Signatur. Ohne Kopf gibt es für einen bekannten Dienst mit erlaubter Herkunft, Methode
POST und kanonischem Ziel nie etwas anderes als `401`):

1. Form des Kopfes und `ts` innerhalb von ±`authWindowSeconds` (60 s) der Uhr des Relays, **vor** dem Lesen des
   Körpers; zusätzlich darf `ts` nicht vor dem Start des Prozesses liegen (`ts` ≥ Startzeit − `AUTH_START_SLACK_MS`, 1000 ms; `ts` und alle Zeiten sind Millisekunden, das Fenster ist `authWindowSeconds` · 1000 ms und gilt auf die Millisekunde genau: `now − 60000 ≤ ts ≤ now + 60000`; die Schonfrist von einer Sekunde deckt, dass die App einen Augenblick vor der Uhrablesung des Relays signiert). Die
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
3. Ein Kopf, dessen `jti` bei derselben Kennung schon angenommen wurde, wird abgelehnt (Wiederholung): nach `200` und nach
   `502`/`504` (die Anfrage wurde angenommen) braucht jeder weitere Versuch einen frischen Kopf (ein neues `jti`, das
   `signRelayRequest` bei jedem Aufruf selbst zieht). Nach `429` (nichts wurde eingetragen) darf **derselbe** Kopf
   innerhalb des Zeitfensters wiederholt werden. **Gemerkt wird das Paar (Kennung, `jti`), nicht die Signatur und nicht
   ein Digest der Nachricht:** ECDSA ist formbar, zu einer gültigen Signatur `(r, s)` ist auch `(r, n − s)` für dieselbe
   Nachricht gültig, und ein Speicher über Signaturen ließe die Zwillingssignatur als neu durch; die Zwillingssignatur
   trägt aber dasselbe `jti` und bleibt deshalb eine Wiederholung (ein Test belegt beides). Weil das `jti` je Anfrage
   zufällig ist, sind zwei Anfragen mit demselben Schlüssel, demselben Pfad, demselben Körper und derselben
   Millisekunde (oder Sekunde) **zwei Anfragen**, keine Wiederholung; früher ergab das dieselbe Nachricht und die zweite
   bekam `401`. Dasselbe `jti` bei einer anderen Kennung ist ein eigener Eintrag. Eine Wiederholung stirbt mit `401` **vor** dem `Content-Type`, vor der Prüfung des Hashes
   und vor dem Budget: sie verbraucht weder Budget noch Eintrag. Der Speicher wird nur **gelesen**, solange die Anfrage
   nicht bis zum Budget durchgekommen ist; eingetragen wird erst, wenn Hash und Form des Körpers stimmen und
   Budget **und** Speicher die Anfrage zulassen. Abgewiesene Versuche (`400`, `415`, `429`) füllen den Speicher
   also nicht und verbrauchen kein Budget.
   Der Speicher ist auf `authReplayEntries` Einträge begrenzt, davon darf eine Kennung höchstens den Anteil
   `authReplayKeyShare` halten (eine Kennung kann die anderen nicht aussperren). Ein Eintrag bleibt bis
   `ts + authWindowSeconds · 1000 + requestTimeoutMs` (alles in Millisekunden), also höchstens 125 s nach dem Eintragen (bei
   richtiger Uhr; ein Eintrag hält mindestens bis zum Ende des Fensters seines Kopfes, also 60 s nach dem `ts` plus die
   Zeit, die ein Körper noch kommen darf). Weil nur zugelassene Anfragen eingetragen
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

**Ein Relay in der Nachricht (Audience):** Die signierte Nachricht trägt die Audience des Relays. Wird **derselbe Schlüssel
bei zwei Relays** eingetragen, die **verschiedene** `RELAY_AUDIENCE` haben, gilt ein Kopf nur bei dem Relay, für das er
signiert wurde: ein bei dem einen abgefangener Kopf wird bei dem anderen mit `401` abgelehnt (Querwiederholung ist damit
zu). Haben beide **dieselbe** Audience, ist das nicht der Fall (jede Instanz hat ihren eigenen Wiederholungsspeicher, ein
Kopf gilt bei beiden einmal). **Je Instanz und je Umgebung eine eigene Audience**, und Schlüssel trotzdem nicht ohne
Not auf mehrere Relays teilen; je Relay einen eigenen einzutragen bleibt die einfachste Regel. Ein App-Betreiber, der
für mehrere Relays signiert, hält die Audience je Relay (sie gehört zur Adresse des Relays in der App).

**Anfrageziel:** Das rohe Ziel der Anfrage muss gleich dem kanonischen Pfad sein (kein `./`, `..`, Rückwärtsstrich,
keine Absolutform `http://…`, kein leeres `?`); sonst `400 bad-request`. So bindet die Signatur den Pfad wörtlich:
was signiert wurde, ist das, was geroutet wird.

Das Relay schreibt weder Kennung noch Zeit noch Signatur ins Protokoll; die Zähler kennen nur `unauthorized`.

**Abgebrochene Anfragen:** Bricht der Client die Verbindung ab, während der Körper noch kommt (`ECONNRESET`,
`aborted`), wird das **nicht beantwortet** (die Verbindung ist weg) und nicht als `internal` gezählt, sondern in
`refused` unter `client-aborted`. `internal` zählt nur echte Ausnahmen im Relay.

**Abbruch während des Wartens:** Wartet eine Anfrage auf einen Platz (Sammelbetrieb) oder auf den Mindestabstand
(Einzelbetrieb), und bricht der Client dann ab, gilt je Betriebsart:

- **Einzelbetrieb:** Das Relay ruft den Dienst für diese Anfrage **nicht** auf. Sie zählt unter `refused` als
  `client-aborted`. Ihre Zeit auf der Spur wird nur zurückgegeben, wenn sie die letzte Anfrage der Kette war; eine Lücke
  in der Mitte bleibt, die Reihenfolge des Eingangs bleibt erhalten. Der Abbruch wird zum berechneten Zeitpunkt des Aufrufs
  geprüft, nicht sofort: bis dahin hält die Anfrage ihren Platz in der Warteschlange und zählt gegen `singleQueueMax`
  (16 Plätze je Spur, also je Dienst und Identität, nicht je Dienst). `res.destroyed` wird nur in diesem Zeitpunkt und
  nach einer Antwort des Sammelbetriebs geprüft: eine Anfrage, die sofort aufgerufen wird (nichts davor), und ein
  Client, der schon vor dieser Entscheidung weg ist, werden noch gestempelt (`stamped` zählt, `client-aborted` nicht);
  ein Aufruf, der schon läuft, wird fertig. Dieselbe Rückgabe gilt für eine letzte Anfrage, die `503 busy` bekommt.
- **Sammelbetrieb:** Das Blatt bleibt im Baum (der Baum ist beim Schließen des Fensters schon festgelegt), das Fenster
  stempelt wie sonst, und die Anfrage zählt unter `client-aborted`. Der Dienst bekommt dafür keinen zusätzlichen Aufruf;
  der Stempel für den Hash kommt trotzdem zustande und wird nicht zurückgenommen.

In beiden Betriebsarten ist das Mengenbudget mit der Annahme verbraucht (siehe „Budgets und Zähler“).

**Zu langsame Anfragen:** Kommt eine Anfrage nicht innerhalb von `requestTimeoutMs` vollständig an (Kopfzeilen oder
Körper tröpfeln), beendet **der Server** die Verbindung und antwortet `408`. Das zählt unter `refused` als
`request-timeout` (einmal je Verbindung), **nicht** als `client-aborted`: dieses zählt nur Clients, die von sich aus
abbrechen. Die Zähler `unauthorized`, `rate-limited` usw. bleiben davon unberührt.

**Pipelining mit Müll:** Wer mehrere Anfragen hintereinander schickt (pipelined) und danach Müll nachschickt, bekommt nur die `400` und verliert die Antwort der laufenden Anfrage (wie bei Node).

**Schlüsseldatei** (Pfad aus `RELAY_KEYS_FILE`): `{"version": 2, "keys": [{"id": "app-1", "publicKey": "<base64url>"}]}`
(Version 3 mit weiteren Feldern je Eintrag: „Schlüsseldatei Version 3“ unten).
`publicKey` ist der **unkomprimierte Punkt** (65 Byte: `04 || X || Y`) als base64url ohne `=`. Streng gelesen: genau
diese Felder, 0 bis 64 Schlüssel (eine ausdrücklich leere Liste ist gültig und sperrt alle, siehe unten), `id` nach dem Muster, der Punkt muss **auf der Kurve P-256 liegen** (sonst
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
Schlüsseldatei; ein Hinweis dazu geht auf stderr. Optionale Schalter machen weitere Felder des Eintrags (Version 3):
`--solo`, `--not-after <unix>`, `--services a,b`, `--per-minute N` (Beispiel: `node scripts/make-key.ts app-1 --not-after
1900000000 --services freetsa --per-minute 5`); falsche Werte enden mit Exit 2 und ohne Ausgabe, die Datei schreibt das
Skript nie. Beispiel (gekürzt):

```text
$ node scripts/make-key.ts app-1
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg…        <- Zeile 1: privater Schlüssel, nur für die App
{"id":"app-1","publicKey":"BAsY3mTq0…"}                  <- Zeile 2: Eintrag für die Schlüsseldatei
```

Zeile 2 kommt in `keys` der Schlüsseldatei: `{"version": 2, "keys": [<Zeile 2>]}` (mit `notAfter`, `services` oder
`perMinute` in der Zeile: `"version": 3`). `npm run probe` liest `RELAY_PRIVATE_KEY` (der private Schlüssel,
base64url), `RELAY_KEY_ID` und `RELAY_AUDIENCE` (die Audience des Relays, gegen das es läuft) aus der Umgebung und signiert damit.

**Grenze:** Der private Schlüssel liegt in der App. Eine Web-App, die ihn im Browser hält, kann ihn nicht vor ihren
eigenen Besuchern verbergen; der Schlüssel schützt das Relay vor fremden Apps und Skripten, nicht vor den Nutzern
einer Seite, die ihn ausliefert. Er lässt sich pro App widerrufen (Eintrag aus der Datei entfernen oder mit `"revoked": true` sperren; wirkt nach spätestens 5 s, kein Neustart).
**Aussperren:** Die Dienst-Zähler gelten **global**, nicht je Kennung. Mit den mitgelieferten Diensten (je 4
Anfragen je Minute bei 15 s) sperrt ein einziger gültiger Schlüssel mit 4 Anfragen in einer Minute einen Dienst für
alle anderen Kennungen bis zum Ende des Zeitfensters (bei FreeTSA mit 5 s: 12 Anfragen). `perMinuteTotal` (60) wird mit
den mitgelieferten Diensten nie erreicht (die vier Dienstgrenzen ergeben zusammen nur 24 je Minute); `perMinutePerKey`
(20) kann ein Schlüssel erreichen, der mehrere Dienste zugleich nutzt. Beide greifen im Sammelbetrieb früher
(siehe dort: sie zählen jede Anfrage). **Ohne `RELAY_KEY_SHARE` (Vorgabe) verteilt das Relay das Budget eines Dienstes
nicht fair auf die Kennungen:** wer einen gültigen Schlüssel hat (auch einen gestohlenen), kann einen Dienst für alle
übrigen aussperren. Mit `RELAY_KEY_SHARE` (nächster Abschnitt) ist der Anteil einer Kennung begrenzt; ein Schlüssel
lässt sich außerdem widerrufen (Eintrag entfernen oder `"revoked": true`).

#### Anteil je Schlüssel am Dienstbudget (`RELAY_KEY_SHARE`)

`RELAY_KEY_SHARE` ist eine ganze Zahl in Prozent, 10 bis 100 (Vorgabe 100 = aus: das Verhalten bleibt wie ohne die
Einstellung, es wird nichts gezählt). Ein Wert unter 100 begrenzt, wie viel vom Minutenbudget eines Dienstes (`60000 /
minIntervalMs`, bei FreeTSA 12, bei 15 s 4) **eine** Schlüsselkennung in der gleitenden Minute belegen darf:

    Obergrenze = max(1, floor(Dienstbudget * Prozent / 100))        FreeTSA bei 50: 6      15-s-Dienst bei 50: 2

- **Je Spur.** Das Budget und der Anteil gelten je (Dienst, Identität): hat ein Dienst Zugangsdaten der App, ist jede
  Identität eine eigene Spur mit eigenem Budget und eigenem Anteil der Kennung. Ohne Schlüssel (`RELAY_AUTH=off`) gibt es
  keine Kennung und keinen Anteil.
- **Darüber `429`** mit `Retry-After` (die Zeit, bis der älteste Platz dieser Kennung in der Minute frei wird; folgt
  zugleich eine andere Grenze, gilt die längste Zeit) und dem Code **`key-share`**. Wenn **nur** der Anteil nein sagt,
  zählt `shareDenied` (global, nur die Summe, nie je Schlüssel) und `refused['key-share']`; sagt auch das Dienstbudget,
  `perMinutePerKey` oder `perMinuteTotal` nein, bleibt es bei `rate-limited`. Die Abweisung verbraucht nichts: kein
  Gesamt- und kein Schlüsselbudget, kein Eintrag gegen Wiederholung, keine Reservierung beim Planer, kein Platz im Anteil.
  Der Kopf einer abgewiesenen Anfrage ist also keine Wiederholung und gilt noch, bis der Anteil wieder frei ist.
- **Einzelbetrieb.** Gezählt wird die **Annahme** je (Spur, Kennung) in der gleitenden Minute, **auf der Wanduhr** wie die
  anderen Mengenzähler dieser Betriebsart (Dienstbudget, `perMinuteTotal`, `perMinutePerKey`); der Mindestabstand läuft
  weiter auf der monotonen Uhr. Das Dienstbudget und der Anteil zählen dieselben Annahmen, der Anteil nur je Kennung.
- **Sammelbetrieb (entschieden: nur Solo).** Jeder **Solo-Stempel** (Schlüsselart 2) nimmt einen ganzen Platz des Dienstes
  und zählt gegen den Anteil (monotone Uhr, wie der ganze Planer). **Hashes in einem Fenster teilen sich einen Platz:** ein
  Fenster ist ein Platz für alle seine Hashes, eine Anfrage, die ein offenes Fenster betritt, nimmt keinen Platz und
  zählt nicht gegen den Anteil. Eine Obergrenze je Kennung und Fenster (`max(1, floor(RELAY_BATCH_MAX * Prozent / 100))`
  Hashes) wurde geprüft und **nicht** gebaut: Fenster füllen sich auch aus der Warteschlange der Anfragen, die noch auf
  einen Platz warten, und das `Retry-After` „bis zum Fensterschluss“ gäbe es für ein Fenster, das noch nicht offen ist,
  nicht; das wären zwei neue Zustände im Planer für ein Risiko, das schon begrenzt ist: Hashes im Fenster kosten den
  Dienst nichts, die Zahl der Fenster hängt an der Zeit (nicht an der Kennung), und eine Kennung kann höchstens
  `perMinutePerKey` (20) Hashes je Minute einbringen (bei einem sehr kleinen `RELAY_BATCH_MAX` können wenige Kennungen die
  Fenster füllen: dort `RELAY_BATCH_MAX` nicht kleiner als die Zahl der Nutzer wählen). Das Aussperren am Dienstbudget kann
  im Sammelbetrieb nur ein Schlüssel der Art 2 mit Solo-Stempeln (die der Betreiber vergibt); der Anteil begrenzt ihn.
- **Zähler im Arbeitsspeicher, begrenzt.** Eine Tabelle je (Kennung, Spur); jede Annahme wirft die Einträge hinaus, deren
  Zeiten alle älter als die Minute sind. Sie hält also nur Kennungen und Spuren der letzten Minute (höchstens
  `perMinuteTotal` Annahmen; die Tabelle hat höchstens so viele Einträge). Das Neulesen der Schlüsseldatei ändert die
  Zähler nicht (ein Schlüssel, der aus der Datei verschwindet, ist ungültig; sein Zähler läuft aus). Eine Uhr, die
  zurückgestellt wird, setzt Zeiten in der Zukunft auf „jetzt“ (wie bei den anderen Zählern).
- **Empfehlung.** Mit mehreren Nutzergruppen (mehrere Apps, mehrere Schlüssel) im Pilot `RELAY_KEY_SHARE=50`: ein
  Schlüssel belegt höchstens die Hälfte der Plätze, ein zweiter bekommt immer welche (bei FreeTSA 6 von 12). Mit genau
  einer Nutzergruppe bringt die Einstellung nichts; sie senkt nur deren Anteil. Bei Anteilen unter 100 / (Zahl der
  Schlüssel) bleibt Budget ungenutzt, auch wenn kein anderer Schlüssel etwas will: der Anteil ist eine feste Grenze,
  kein Teilen nach Bedarf.

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
     audience: 'https://relay.example', // genau die RELAY_AUDIENCE dieses Relays
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
   endliche Zahl ab 1e11 und **unter 1e15** (Bruchteile sind erlaubt); ein kleinerer Wert, etwa Sekunden, ergibt `bad-options`, damit
   nicht stillschweigend eine Zeit im Jahr 1970 signiert wird, und ebenso ein größerer (`Number.MAX_VALUE`, `1e17`): unter 1e15
   hat `ts` höchstens 15 Stellen, mehr nimmt das Kopfformat des Relays nicht (1e15 ms sind das Jahr 33658). Bruchteile
   einer Millisekunde werden abgeschnitten (`ts` ist eine ganze Zahl).

   **`audience`** (Pflicht) ist die `RELAY_AUDIENCE` des Relays, das die Anfrage bekommt: druckbares ASCII ohne Leerzeichen,
   1 bis 128 Zeichen, sonst `bad-options` (kein eigener Code; auch eine fehlende oder falsche Art, etwa eine Zahl).
   **`jti`** (selten nötig) sind 16 Byte (`Uint8Array`); fehlt es, zieht die Bibliothek sie bei jedem Aufruf aus
   `crypto.getRandomValues` (WebCrypto, kein `node:`); ein anderes `jti` (Länge, Art) ist `bad-options`. Wer ein `jti`
   selbst vorgibt (Tests), darf es **nicht** für eine zweite Anfrage wiederverwenden: das Relay hielte sie für eine
   Wiederholung. Das Ergebnis ist der fertige Kopfwert `v3.<kid>.<ts>.<jti>.<sig>`.

   `signRelayRequest` wirft nie und weist nie ab: auch für feindliche Proxys als Eingabe, als `privateKey` oder als
   `body` (werfendes `getPrototypeOf`/`get`) gibt es einen Code (`bad-options`/`bad-key`). Jede Eingabe wird einmal
   gelesen und kopiert, nie über einen Iterator; `privateKey` darf höchstens 256 Byte, `body` höchstens 512 Byte
   haben (sonst `bad-key`/`bad-options`). **Realm:** ein `Uint8Array` aus einem anderen Realm (iframe, Worker, `vm`)
   wird abgewiesen; `privateKey` und `body` als `new Uint8Array(x)` übergeben.

   Keine Cookies, kein `mode`-Zusatz nötig. Für jeden Versuch (auch nach `429`/`401`) neu signieren. Die Frist der App ab Sendebeginn sollte je Betriebsart betragen: **im Einzelbetrieb `RELAY_MAX_WAIT_MS` + 17 s** (Vorgabe 30 + 17 = 47 s), **im Sammelbetrieb `RELAY_MAX_WAIT_MS` + Fenster + Kette + 17 s** (Vorgabe mit einem 15-s-Dienst, Fenster und Kette je 15 s: 77 s; FreeTSA mit 5 s: 57 s; siehe „Latenz und Fristen“): bis zu 5 bis 6 s für den Körper
   (`requestTimeoutMs`), bis zu 10 s für den Dienst (`upstreamTimeoutMs`) und die Prüfung des Tokens, davor das Warten auf den Mindestabstand.

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
3. Bei `401`: Schlüssel, Kennung, Audience (genau die `RELAY_AUDIENCE` dieses Relays) und die Uhr der App prüfen (±60 s); ein Wiederholungsversuch mit demselben
   Kopf (also demselben `jti`) wird ebenfalls mit `401` abgelehnt. **Uhrversatz beheben (genau einmal):** Das Relay gibt `Date` frei
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
     audience: string, // die RELAY_AUDIENCE des Relays
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
         audience,
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

   `Date` hat nur ganze Sekunden: der Versatz ist auf etwa 1 s genau, das Fenster von ±60 s ist weit genug (die
   Millisekunden von `ts` ändern daran nichts: die App darf den Versatz auf die Sekunde runden). Jeder neue Kopf hat ein
   eigenes `jti`; ein erneutes Signieren, auch in derselben Millisekunde und mit unveränderter Uhr, ergibt deshalb eine
   **neue** Anfrage und keine Wiederholung: nach `502`/`504` (die Anfrage wurde angenommen) und nach `401` braucht man
   **nicht** zu warten, bevor man erneut signiert und sendet (früher mussten es wegen der Sekunden-Auflösung mindestens
   1 s sein). Nur ein **bereits gesendeter** Kopf darf nicht noch einmal gesendet werden (derselbe Kopf ist dasselbe `jti`).
   Bei `429`: `Retry-After` (Sekunden) lesen und erst dann wieder
   fragen. Bei `502`/`504`/Netzwerkfehler: später
   noch einmal versuchen oder einen anderen Dienst nehmen; ein Fehlschlag ist kein Beweis für etwas.

4. Das Token (base64url-Text) zusammen mit Kennung des Dienstes, Hash und dem Ergebnis der Prüfung
   (`signerNotAfter`!) aufbewahren; die **Rechnung** (Hash, Signatur, Kette zur `genTime`) lässt sich später mit denselben
   Mitteln ohne das Relay wiederholen, die **Aussage** wird aber schwächer: nach `signerNotAfter` des
   Zeitstempel-Zertifikats oder wenn dessen Schlüssel kompromittiert wird, verfällt die Beweiskraft (es gibt keine
   Sperrprüfung, die Frische lässt sich später nicht mehr prüfen; `docs/grenzen.md`, „Langzeitaussage“). Für Nachweise
   über längere Zeit: **rechtzeitig neu stempeln** (vor `signerNotAfter`) und **mehrere Dienste** stempeln.

Fehler sind `{"error": "<code>"}`; bei 502 mit `reason` aus der Prüfung:

| Status | Code                                                                            | Bedeutung                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ------ | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 400    | `bad-hash`                                                                      | Hash nicht 32 Byte, ungültiges base64url, zusätzliche Felder, kein JSON-Objekt                                                                                                                                                                                                                                                                                                                                                                                                                                |
| 400    | `no-query`                                                                      | Abfragezeichenfolge (`?…`) ist nicht erlaubt                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| 400    | `bad-request`                                                                   | Anfrageziel ist keine gültige Adresse (z. B. `//`, `//[`) oder nicht gleich dem kanonischen Pfad (`./`, `\`, Absolutform)                                                                                                                                                                                                                                                                                                                                                                                     |
| 400    | `bad-mode`                                                                      | `mode` im JSON-Körper hat einen anderen Wert als `"solo"` (nur nach bestandener Anmeldung)                                                                                                                                                                                                                                                                                                                                                                                                                    |
| 400    | `bad-upstream`                                                                  | `upstream` passt nicht zum Dienst: vorhanden, wo der Dienst keines nimmt (Quelle `relay`, keine `auth`), fehlend, wo die App eines liefern muss, falsche Form, Zeichen oder Länge (nur nach bestandener Anmeldung)                                                                                                                                                                                                                                                                                            |
| 401    | `unauthorized`                                                                  | Auth-Fehler: Kopf `X-Zeitstempel-Auth` fehlt oder ist ungültig (Form, Zeit, Kennung, Signatur, Wiederholung); einheitlich                                                                                                                                                                                                                                                                                                                                                                                     |
| 403    | `origin-not-allowed`                                                            | Aufruf aus einem Browser von einer nicht konfigurierten Herkunft                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| 403    | `service-not-allowed`                                                           | Der Schlüssel trägt `services` (Schlüsseldatei Version 3) und der angefragte Dienst steht nicht darin; kommt **sofort** nach der Anmeldung, vor jeder Arbeit: kein Fenster, kein Platz, kein Warten, kein Budget verbraucht, kein Eintrag im Wiederholungsspeicher; nur die Zähler `serviceDenied` und `refused` kennen es                                                                                                                                                                                    |
| 403    | `solo-not-allowed`                                                              | Ein Schlüssel der Art 1 (oder ohne Art 2) verlangte `mode: "solo"` (nur im Sammelbetrieb; kommt **sofort** nach der Prüfung der Form des Körpers (`415`, `400 bad-hash`, `bad-mode`, `bad-upstream` gehen vor), vor jeder Arbeit: kein Fenster, kein Platz, kein Warten, kein Budget verbraucht; nur die Zähler `soloDenied` und `refused` kennen es)                                                                                                                                                         |
| 404    | `unknown-service`, `not-found`                                                  | Dienst oder Pfad nicht vorhanden                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| 405    | `method-not-allowed`                                                            | `/v1/stamp/…` nur mit POST                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| 413    | `too-large`                                                                     | Körper über dem Limit (Verbindung wird geschlossen); kommt vor der Signaturprüfung, nennt nur das öffentliche Limit                                                                                                                                                                                                                                                                                                                                                                                           |
| 415    | `unsupported-media-type`                                                        | weder JSON noch `application/octet-stream`                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| 429    | `rate-limited`                                                                  | Limit erreicht (auch je Schlüssel, auch Speicher gegen Wiederholung voll); `Retry-After` in Sekunden                                                                                                                                                                                                                                                                                                                                                                                                          |
| 429    | `key-share`                                                                     | Nur der Anteil dieser Schlüsselkennung am Dienstbudget (`RELAY_KEY_SHARE`) ist erreicht; `Retry-After` in Sekunden; nichts verbraucht; zählt `shareDenied`                                                                                                                                                                                                                                                                                                                                                    |
| 500    | `internal`                                                                      | Unerwarteter Fehler im Relay (ohne Einzelheiten nach außen)                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| 502    | `upstream-failed`, `upstream-too-large`, `upstream-refused`, `upstream-invalid` | Dienst nicht erreichbar, zu große oder unpassende Antwort, ungültiges Token (`reason`; auch `time-too-old`/`time-in-future`)                                                                                                                                                                                                                                                                                                                                                                                  |
| 503    | `shutting-down`                                                                 | Das Relay wird beendet; die Anfrage wartete (im Sammelbetrieb in einem Fenster oder auf einen Platz, im Einzelbetrieb auf den Mindestabstand) und ist nicht gestempelt, die App versucht es später neu                                                                                                                                                                                                                                                                                                        |
| 503    | `busy`                                                                          | Im Sammelbetrieb: kein freier Platz beim Dienst innerhalb von `RELAY_MAX_WAIT_MS`, oder die Solo-Warteschlange des Dienstes ist voll; im Einzelbetrieb: die Warteschlange auf den Mindestabstand ist voll (`singleQueueMax`) oder der Aufruf läge mehr als `WAIT_TOLERANCE_MS` (50 ms) über der Wartegrenze (Stillstand des Relays; auch in der Warteschlange des Sammelbetriebs); immer: die Tabelle der Zugangsdaten-Identitäten des Dienstes ist voll (`upstreamIdentitiesMax`); `Retry-After` in Sekunden |
| 504    | `upstream-timeout`                                                              | Dienst antwortete nicht rechtzeitig                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |

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
- Eine **sofort** abgewiesene Anfrage (`401`, `400`, `415`, `429`, das `403 solo-not-allowed` und das `503 busy` bei voller Tabelle der Identitäten
  oder voller Solo-Warteschlange) kommt nie in ein Fenster und kostet kein Budget. Eine **angenommene** Anfrage hat das
  Budget dagegen verbraucht, auch wenn sie nach dem Warten `503 busy` oder beim Beenden `503 shutting-down` bekommt (das
  Budget wird bei der Annahme verbraucht und nicht zurückgegeben; so auch im Abschnitt „Schlüsselarten und Solo-Stempel“).
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

| Fall                                                            | Folge                                                                                                                                                                                                                                                      |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Dienst nicht erreichbar, Frist, Ablehnung, ungültiges Token     | **Alle** Anfragen des Fensters bekommen dieselbe Antwort wie sonst (`502`/`504` mit demselben Code und `reason`)                                                                                                                                           |
| Das Relay wird beendet (`SIGTERM`), Fenster ist offen           | Die wartenden Anfragen bekommen `503 shutting-down`; ein Fenster, dessen Aufruf läuft, wird noch fertig (siehe „Fristen beim Beenden“: nach `shutdownGraceMs` werden alle Verbindungen geschlossen, nach `shutdownHardMs` endet der Prozess in jedem Fall) |
| Neue Anfrage nach dem Beenden                                   | `503 shutting-down`                                                                                                                                                                                                                                        |
| Prozess stirbt, Neustart                                        | Wartende Anfragen verlieren die Verbindung (kein Zustand wird gespeichert); die App versucht es neu, mit frischem Kopf                                                                                                                                     |
| Ein Client bricht ab, während er wartet (Sammelbetrieb)         | Sein Blatt bleibt im Baum (der Baum ist beim Schließen schon festgelegt), die anderen werden bedient; Zähler `client-aborted`. Im Einzelbetrieb kein Aufruf für ihn (siehe „Abbruch während des Wartens“)                                                  |
| Dienstbudget aufgebraucht, wenn ein neues Fenster öffnen müsste | `429` mit `Retry-After`, wenn der nächste Platz später als `RELAY_MAX_WAIT_MS` frei wird; sonst wartet die Anfrage (siehe „Schlüsselarten und Solo-Stempel“, danach höchstens `503 busy`)                                                                  |

### Latenz und Fristen

Die Antwort kommt **nach dem Fenster** plus der Zeit des Dienstes, im ungünstigsten Fall nach `RELAY_BATCH_MS` + 10 s
(`upstreamTimeoutMs`) + Prüfung, wenn der Dienst frei ist. Die Frist von 5 s (`requestTimeoutMs`) gilt nur dem **Lesen
der Anfrage**; die Antwort darf später kommen. Dazu kommen zwei Wartezeiten, die nur im Mangelfall auftreten:

- **Warten auf einen Platz** (nur eine Anfrage, die ein neues Fenster öffnen muss, siehe „Schlüsselarten und
  Solo-Stempel“): höchstens `RELAY_MAX_WAIT_MS`.
- **Warten des geschlossenen Fensters auf den Mindestabstand** (Kettenwartezeit, siehe „Der Planer je Dienst“): ein
  Fenster, das voll schließt oder kurz nach einem Solo-Stempel stempelt, ruft den Dienst erst `minIntervalMs` nach dem
  Aufruf davor. Liegen schon `k` andere Fenster vor ihm, die ebenfalls warten (jedes ein Abstand nach dem vorigen), wartet
  es bis zu **(k + 1) · `minIntervalMs`**, nicht nur `minIntervalMs`. **Obergrenze:** jedes wartende Fenster hält einen
  Platz im Mengenbudget des Dienstes (`60000 / minIntervalMs` je Minute), die Kette liegt also immer innerhalb **einer
  Budgetminute: höchstens 60 s** (bei den mitgelieferten Diensten 60 s: 4 Plätze zu je 15 s, FreeTSA 12 zu je 5 s).
  **Wie lang sie wirklich wird:** nur **volle** Fenster bilden Ketten; ein Fenster füllt sich nur, wenn in seiner Zeit
  `RELAY_BATCH_MAX` Anfragen kommen, und das Relay nimmt höchstens `perMinuteTotal` (60) je Minute an. Bei
  `RELAY_BATCH_MAX` > 60 (Vorgabe 128) kann also kein Fenster voll werden: dann wartet ein Fenster nur auf einen
  Solo-Stempel unmittelbar davor, **höchstens `minIntervalMs`**. Mit kleinem `RELAY_BATCH_MAX` (zum Beispiel 2) können
  bis zu `⌊60 / RELAY_BATCH_MAX⌋` volle Fenster je Minute entstehen und die Kette wächst bis zur Obergrenze.

**Folge für die Fristen** (`Kette` = `minIntervalMs` bei `RELAY_BATCH_MAX` > 60, sonst 60 s als sichere Obergrenze):

- Die Frist der App ab Sendebeginn ist **mindestens `RELAY_BATCH_MS` + Kette + 17 s** (17 s = 10 s Dienst + 7 s Reserve
  für Lesen des Körpers und Prüfung); wartet die Anfrage auch auf einen Platz, kommt `RELAY_MAX_WAIT_MS` dazu:
  **`RELAY_MAX_WAIT_MS` + Fenster + Kette + 17 s** (`AbortSignal.timeout(maxWaitMs + batchMs + chainMs + 17_000)`).
  Beispiele für die Vorgabe (Wartegrenze 30 s, `RELAY_BATCH_MAX` 128; das Fenster ist `RELAY_BATCH_MS` und mindestens
  `minIntervalMs` des Dienstes, der Start verlangt das): FreeTSA (5 s), Fenster 5 s, Kette 5 s: 30 + 5 + 5 + 17 = **57 s**;
  ein 15-s-Dienst (digicert, certum), Fenster 15 s, Kette 15 s: 30 + 15 + 15 + 17 = **77 s**. Mit kleinem
  `RELAY_BATCH_MAX` (Kette bis 60 s): FreeTSA 30 + 5 + 60 + 17 = **112 s**, 15-s-Dienst 30 + 15 + 60 + 17 = **122 s**.
  Ohne Wartegrenze (die Anfrage bekommt sofort einen Platz) entfällt der Wartebetrag: FreeTSA 5 + 5 + 17 = 27 s,
  15-s-Dienst 15 + 15 + 17 = 47 s; mit kleinem `RELAY_BATCH_MAX` 5 + 60 + 17 = 82 s beziehungsweise 15 + 60 + 17 = 92 s.
  **Formel für eine andere Wartegrenze `W`** (bis `maxWaitMaxMs` 60 s): Frist = `W` + Fenster + Kette + 17 s, beim Proxy
  dazu 3 s Reserve. Mit 3 s Reserve für den Proxy ergibt die Vorgabe 30 s: Einzelbetrieb 50 s, Sammelbetrieb FreeTSA 60 s,
  15-s-Dienst 80 s, im Extrem (kleines `RELAY_BATCH_MAX`) 125 s. Die Beispiele unten nehmen dafür 130 s als Obergrenze.
- Der Reverse-Proxy braucht ein Lese-Timeout von mindestens **derselben Frist** (nginx `proxy_read_timeout`, Caddy
  `response_header_timeout`), besser 3 s mehr. Ein Lese-Timeout von 17 bis 20 s
  bricht im Einzelbetrieb (Vorgabe 47 s) und im Sammelbetrieb (Vorgabe 77 s, FreeTSA 57 s) Anfragen ab, die das Relay noch zählt.
- Ein Solo-Stempel der Art 2 hat kein Fenster; sein Warten auf den Mindestabstand (auch hinter einer Kette) liegt
  **innerhalb** der Wartegrenze: Frist der App und Lese-Timeout des Proxys mindestens `RELAY_MAX_WAIT_MS` + 17 s.
- **Im Einzelbetrieb** wartet eine Anfrage nur auf den Mindestabstand zum Aufruf davor (kein Fenster, keine Kette): Frist der App
  und Lese-Timeout des Proxys mindestens **`RELAY_MAX_WAIT_MS` + 17 s** (Vorgabe 47 s), besser 3 s mehr.
- Sie ist **keine Echtzeit**: wer sofort einen Stempel braucht, nimmt den Einzelbetrieb (eine zweite Relay-Instanz
  ohne `RELAY_BATCH_MS`).

### Client-Rezept

```ts
import { fromBase64Url, verifyBatchedTimestamp, verifyTimestampToken } from 'zeitstempel';

// … Anfrage wie in „Die App als Client“ signieren und senden. Die Frist hängt von der Betriebsart ab
//   (siehe „Latenz und Fristen“); die Werte setzt die App wie das Relay gestartet ist:
//   maxWaitMs = RELAY_MAX_WAIT_MS (Vorgabe 30_000)
//   batchMs   = RELAY_BATCH_MS im Sammelbetrieb (Beispiel 15_000 für einen 15-s-Dienst), im Einzelbetrieb 0
//   chainMs   = minIntervalMs des Dienstes im Sammelbetrieb (Beispiel 15_000; bei kleinem RELAY_BATCH_MAX 60_000), im Einzelbetrieb 0
//   Einzelbetrieb: 30 + 17 = 47 s; Sammelbetrieb mit einem 15-s-Dienst: 30 + 15 + 15 + 17 = 77 s
//   fetch(relay + path, { method: 'POST', headers, body, signal: AbortSignal.timeout(maxWaitMs + batchMs + chainMs + 17_000) })
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
- Nicht ausgerollt, nicht von einem Menschen geprüft; im Browser nur mit Chromium geprüft (Prüfskript vom 2026-11-24, nicht im
  Repo); der Test nutzt einen Stub als Dienst, gegen einen echten Dienst lief der Sammelbetrieb nicht (kein Netz).
- Einzelbetrieb: Die Mengenzähler (gesamt, je Schlüssel, je Spur) zählen die Annahme auf der Wanduhr, nicht den Aufruf auf
  der monotonen Uhr. Folgen: Das Minutenbudget kann ausgegeben sein, ohne dass der Dienst einen Aufruf sah (`429` bei
  freiem Dienst; Beispiel FreeTSA: sieben Anfragen bei 0 s, sechs bei 50 s, die sechste bekommt `429`, obwohl der Dienst
  in dieser Minute höchstens neun Aufrufe sieht). Und nach einem Stillstand des Relays kann der Dienst kurz mehr Aufrufe je
  Minute sehen als das Budget erlaubt (Beispiel: Abstand 25 s, Budget 2: drei Aufrufe in 50 s); nur der Abstand bleibt dabei
  hart gewahrt. Entscheidung des Eigentümers: die Mengenzähler des Einzelbetriebs auf die monotone Uhr und an den Aufruf
  binden. Derzeit nicht umgesetzt. Auch ein Sprung der Wanduhr **nach vorn** (nicht nur ein Stillstand) gibt dort Plätze des
  Mengenbudgets zurück: Beispiel Abstand 7 s, Budget 8 je Minute: ein Sprung lässt neun Aufrufe in einer gleitenden Minute
  zu; der Abstand bleibt in jedem Fall gewahrt. Bei den Abständen der mitgelieferten Dienste (5 s, 15 s) ohne Wirkung, weil
  der Abstand allein schon auf 12 beziehungsweise 4 Aufrufe je Minute begrenzt.

## Schlüsselarten und Solo-Stempel

Nur im Sammelbetrieb. Ohne `RELAY_BATCH_MS` bekommt jede Anfrage ohnehin einen direkten Stempel: `mode: "solo"` ändert
dann nichts, und die Schlüsselart wird nicht geprüft (keine Prüfung, kein `403`).

### Die zwei Schlüsselarten

| Art | Eintrag in der Schlüsseldatei                | Darf                                                                                                      |
| --- | -------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| 1   | `{"id", "publicKey"}` (oder `"solo": false`) | normal stempeln (Beleg im Sammelfenster); **kein Solo**: `mode: "solo"` ist sofort `403 solo-not-allowed` |
| 2   | `{"id", "publicKey", "solo": true}`          | Solo-Stempel immer verlangen, im Rahmen der Grenzen (`soloPerMinutePerKey`, Warteschlange, Dienstbudget)  |

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
  audience, // die RELAY_AUDIENCE des Relays
}); // Result<string>: der Wert des Kopfes X-Zeitstempel-Auth
```

Die **Antwort** ist ein gewöhnlicher Einzelstempel **ohne** `batch`: der Dienst stempelt den Hash selbst (so verlangt es
ein PDF-Dokumentzeitstempel, `docs/recherche.md` §5). Die App prüft sie mit `verifyTimestampToken` (nicht mit
`verifyBatchedTimestamp`); sie muss beide Formen verarbeiten (mit und ohne `batch`).

### Zulassung

Solo-Stempel gibt es **nur für die Schlüsselart 2**.

1. Art 2: Solo **sofort**, mit einem Platz des Dienstes für sich allein, im Rahmen der Grenzen, und nach dem
   **Mindestabstand** zum letzten Aufruf desselben Dienstes (siehe „Der Planer je Dienst“).
2. Art 1 (oder eine Anfrage ohne Schlüssel): `mode: "solo"` ist **sofort** `403 solo-not-allowed`, **vor jeder Arbeit**, aber
   **nach der Prüfung der Form des Körpers**: ein falscher Medientyp (`415`), ein ungültiger Hash (`400 bad-hash`), ein
   anderer `mode` (`400 bad-mode`) und ungültige oder fehlende Zugangsdaten des Dienstes (`400 bad-upstream`) kommen vor
   dem `403` (Reihenfolge im Code: Form des Körpers, dann Zugangsdaten, dann Schlüsselart). Mit **`RELAY_AUTH=off`** gibt es
   keinen Schlüssel und damit keine Art 2: im Sammelbetrieb ist **jedes** `mode: "solo"` ein `403`.
   Die Anfrage wartet nicht, öffnet kein Fenster, tritt keinem bei, bucht keinen Platz, kommt nicht in den Baum, legt keine
   Zugangsdaten-Identität an und ruft den Dienst nicht auf; gültige Zugangsdaten der Anfrage spielen keine Rolle (ungültige sind `400 bad-upstream`, siehe oben). Die
   Fenster der anderen bleiben unberührt. **Zähler:** `soloDenied` und `refused['solo-not-allowed']` zählen die
   Abweisung. **Budget:** sie kostet **kein** Gesamt-, Schlüssel- und Solo-Budget und schreibt nichts in den
   Wiederholungsspeicher (dieselbe Anfrage noch einmal gesendet bekommt wieder `403`, nicht `401`), wie die anderen sofortigen
   Abweisungen (`400 bad-mode`, `400 bad-hash`, `415`). Begründung: das
   Einfachere und Sicherere. Es gibt keine Arbeit, für die das Budget haften müsste (kein Platz, kein Dienstaufruf, kein
   Warten), und eine Abweisung, die Budget kostet, ließe einen Schlüssel mit einem Versehen (`mode` bei Art 1) seine
   normalen Anfragen sperren. Die Last einer Flut solcher Anfragen ist die einer jeden anderen sofortigen Abweisung (Prüfung
   der Signatur und der Form; Schutz durch Reverse-Proxy und die Frist zum Lesen der Anfrage).
3. **Ohne Sammelbetrieb** ändert `mode: "solo"` nichts: jede Anfrage ist ohnehin direkt, die Schlüsselart wird **nicht**
   geprüft und es gibt keinen `403`. Die Prüfung gilt nur im Sammelbetrieb (dort gibt es den Unterschied zwischen Beleg
   im Fenster und direktem Stempel).
4. **Budget und Zähler** einer angenommenen Solo-Anfrage der Art 2 wie bisher **einmal je Anfrage**: `perMinuteTotal`,
   `perMinutePerKey` und das Solo-Limit je Schlüssel (`soloPerMinutePerKey`) werden bei der Annahme verbraucht (auch wenn
   sie später `503 busy` bekommt). Das Dienstbudget braucht der Stempel selbst.
5. **Latenz und Fristen:** ein Solo der Art 2 antwortet sofort, wenn ein Platz frei ist und der Mindestabstand eingehalten
   ist, sonst nach dem Warten (höchstens `RELAY_MAX_WAIT_MS`; der Abstand, auch hinter wartenden Fenstern, liegt darin).
   Frist der App und Lese-Timeout des Proxys: Wartegrenze + 17 s (der Abstand liegt innerhalb der Wartegrenze).
6. Zusätzlich gilt für jedes Solo die **eigene niedrige Grenze je Schlüssel** `soloPerMinutePerKey` (4 je Minute, nur im
   Arbeitsspeicher): die fünfte Anfrage in der Minute ist `429` mit `Retry-After`. Diese Zahl steht **nicht im Log**
   (keine Zahlen je Schlüssel im Betreiberlog); die Zähler unten sind Summen.

### Der Planer je Dienst

Fenster gelten **immer je externem Dienst**. Ein **Platz** ist ein Stempel des Dienstes im Rahmen seines Budgets
(`60000 / minIntervalMs` je Minute); ein Sammelfenster belegt einen Platz, ein Solo-Stempel ebenfalls (er belegt den
Platz ganz, nicht nur einen Teil des Fensters). Ein Fenster ist **voll** durch `RELAY_BATCH_MAX` oder durch einen
Solo-Stempel der Art 2; **der Rest wartet**.

- **Der Platz wird zur Zeit des Stempels gebucht.** Ein Solo-Stempel bucht seinen Platz, wenn er an den Dienst geht. Ein
  Fenster hält seinen Platz **ab dem Öffnen** und bucht ihn für den Zeitpunkt, an dem es gestempelt wird (Öffnung plus
  Fensterlänge, bei einem vollen Fenster der tatsächliche frühere Zeitpunkt). Solo-Stempel, die während des offenen
  Fensters kommen, sehen den Platz schon als belegt. Folge: der Dienst sieht in jeder gleitenden Minute **der monotonen
  Uhr des Prozesses** höchstens `60000 / minIntervalMs` Aufrufe, auch bei einem Gemisch aus Fenstern und Solo-Stempeln;
  ein Sprung der Wanduhr (auch nach vorn, etwa ein NTP-Schritt) ändert daran nichts, weil der Planer die Wanduhr nicht liest.
  Zur Schließzeit ist der **Mengenplatz** immer frei (er war reserviert und jeder Stempel danach hat ihn mitgezählt); auf
  den Mindestabstand (nächster Punkt) kann ein Fenster dann noch warten. Wartende
  bekommen den Platz in der Reihenfolge, die der Abschnitt beschreibt; ihre Wartegrenze ist `RELAY_MAX_WAIT_MS`.
  Der Start prüft weiter `RELAY_BATCH_MS` >= `minIntervalMs`.
- **Mindestabstand.** Zwei Aufrufe des Relays an denselben Dienst (und dieselbe Zugangsdaten-Identität, also dieselbe Spur)
  liegen **mindestens `minIntervalMs` auseinander**, gleich ob der vorige ein Fenster oder ein Solo-Stempel war. Das gilt
  **zusätzlich** zum gleitenden Mengenbudget (der Abstand allein erlaubt bei `minIntervalMs` = 25 s noch drei Aufrufe in
  einer Minute, das Budget nur zwei) und in beiden Betriebsarten (im Einzelbetrieb wartet die Anfrage im Rahmen von `RELAY_MAX_WAIT_MS`, siehe „Grenzen (`relay/limits.ts`)“).
  - **Solo-Stempel (Art 2)** warten auf den Abstand (im Rahmen von `RELAY_MAX_WAIT_MS`): ein Solo direkt nach einem
    Fenster oder einem anderen Solo geht erst nach `minIntervalMs` an den Dienst; die Latenz wächst um
    `minIntervalMs`, hinter `k` wartenden Fenstern um bis zu `(k + 1) · minIntervalMs`, immer im Rahmen der Wartegrenze (bei
    den mitgelieferten Diensten 5 s oder 15 s je Abstand). Mit dem Abstand erfüllt geht es **sofort**. Ist schon
    beim Eingang klar, dass der Abstand **länger** als die Wartegrenze dauert, bleibt es beim bisherigen `429 rate-limited`
    mit `Retry-After` (wie bei einem Platz, der zu spät frei wird); wer in der Warteschlange länger als die Wartegrenze
    wartet, bekommt `503 busy`.
  - **Fenster** halten den Abstand beim **Stempel**: ein Fenster öffnet wie bisher, sobald ein Platz frei ist, und stempelt
    zur Schließzeit. Liegt der letzte Aufruf (ein Solo-Stempel, der während des Fensters kam, oder ein Fenster, das
    voll geschlossen hat) dann noch keine `minIntervalMs` zurück, **wartet das geschlossene Fenster** bis dahin (es nimmt
    keine weiteren Anfragen mehr auf, hält seinen Platz und bucht ihn zur Zeit des Aufrufs); die Antwort kommt um so viel
    später. Mehrere solche Fenster rufen in der Reihenfolge des Schließens auf, **jedes einen Abstand nach dem vorigen** (das
    `k`-te wartende Fenster wartet bis zu `k · minIntervalMs`, die Kette liegt innerhalb der Budgetminute, siehe „Latenz und
    Fristen“). Ein Fenster nach einem Fenster mit
    `RELAY_BATCH_MS` >= `minIntervalMs` braucht den Abstand ohnehin schon (es stempelt erst nach seiner Sammelzeit); nur ein
    volles Fenster wäre früher dran und wartet.
  - **Uhr des Planers:** Abstand, Dienstbudget (Plätze im gleitenden Fenster), die Zeit der Fenster und jede Wartezeit
    rechnen im Sammelbetrieb mit **einer** Uhr, der monotonen Uhr des Prozesses (`performance.now()`, im Relay die
    Funktion `mono`), nicht mit der Wanduhr. Ein Sprung der Wanduhr nach vorn (30 s oder 59 s; mehr lässt die Anmeldung
    nicht zu) gibt weder Abstand noch Plätze zurück, ein Sprung zurück hält nichts fest (kein Dauerlock). Die Wanduhr
    bleibt für die Anmeldung (`ts`, Wiederholungsspeicher), die Prüfung von `genTime` und die Startzeit. Das Warten eines
    Fensters ist **ein** Zeitgeber auf den berechneten Zeitpunkt (kein Abfragen im Millisekundentakt): kommt er zu früh
    (Stillstand der Ereignisschleife, ein Zeitgeber, der früh feuert), prüft das Relay den Abstand noch einmal und wartet
    den Rest; ein Fenster hinter einem wartenden Fenster wird von diesem angestoßen, sobald es gerufen hat. Ein Stillstand
    der Ereignisschleife, nach dem mehrere Zeitgeber zugleich fällig sind, bringt zwei Aufrufe daher nicht näher zusammen
    als `minIntervalMs`; das `k`-te wartende Fenster wartet höchstens `k · minIntervalMs`.
- **Warten nur im Mangelfall.** Ist ein Platz frei (und für ein Solo der Mindestabstand erfüllt), wird die Anfrage sofort
  bedient (ein Fenster öffnet, ein Solo-Stempel geht an den Dienst); eine Anfrage in ein **offenes** Fenster braucht keinen Platz.
- **Abwechselnd.** Warten ein Solo-Stempel und ein Sammelfenster zugleich, bekommen sie die Plätze **abwechselnd**: nichts
  verhungert. Das Fenster nimmt alle wartenden normalen Anfragen bis `RELAY_BATCH_MAX` auf; der Rest wartet auf den
  nächsten Platz.
- **Wartegrenze `RELAY_MAX_WAIT_MS`** (ganze Zahl 1000 bis 60000, Vorgabe 30000, streng gelesen, ungültig = deutsche Zeile
  `config-error`): wer so lange keinen Platz bekommt, bekommt `503 busy` mit `Retry-After`. Ist schon beim Eingang klar,
  dass der nächste Platz **später** als die Wartegrenze frei wird (Dienstbudget für längere Zeit aufgebraucht), bleibt es
  beim bisherigen `429 rate-limited`; gewartet wird nur bei einem kurzen Engpass.
- **Die Solo-Warteschlange je Dienst ist begrenzt** (`soloQueueMax`, 6; nur Art 2): eine weitere Solo-Anfrage der Art 2 bekommt sofort
  `503 busy`. Die normalen Wartenden sind durch `perMinuteTotal` und die Wartegrenze begrenzt.
- Die 60 s der Anmeldung (Zeitfenster der Signatur) und die ±60 s der Frischeprüfung des Tokens werden von der
  Wartezeit nicht berührt: sie werden beim Eingang beziehungsweise beim Senden an den Dienst gemessen.
- `perMinuteTotal` (60) und `perMinutePerKey` (20) bleiben **unverändert** und zählen jede angenommene Anfrage, auch eine
  Solo-Anfrage und auch eine, die später `503 busy` bekommt (das Budget wird bei der Annahme verbraucht und nicht
  zurückgegeben). Mit den mitgelieferten Diensten (zusammen 24 Plätze je Minute) kann ein Schlüssel, der mehrere Dienste
  nutzt, `perMinutePerKey` (20) erreichen; `perMinuteTotal` (60) wird nicht erreicht. Das Solo-Limit je Schlüssel (4)
  liegt unter `perMinutePerKey` (20), die Grenzen kollidieren also nicht.
- **Kapazität:** ein Solo-Stempel der Art 2 kostet einen ganzen Platz. Mit FreeTSA (12 Plätze je Minute) und abwechselnder Vergabe
  höchstens 6 Solo-Stempel je Minute für **alle** Schlüssel der Art 2 zusammen (sonst bleibt der Sammelbetrieb stehen);
  bei den Diensten mit 15 s sind es 4 Plätze, also höchstens 2.
- **Beim Beenden** (`SIGTERM`, `restartAfter`) bekommen auch die auf einen Platz Wartenden `503 shutting-down`; Verbindungen,
  die ihre Antwort bekommen haben, werden danach geschlossen, damit der Prozess nicht auf das Ende ihres Keep-alive wartet.
  **Fristen beim Beenden:** Nach `server.close()` prüft Node die Fristen für Kopfzeilen und Anfrage nicht mehr; eine
  Verbindung mit halbem Request (halber Header, halber Body) bliebe sonst offen und hielte den Prozess. Deshalb schließt
  das Relay nach `shutdownGraceMs` (2 s) **alle** Verbindungen, auch solche mit laufender Anfrage (ein Aufruf beim Dienst,
  der noch läuft, bekommt seine Antwort also nur, wenn er innerhalb dieser Frist fertig wird), und beendet den Prozess
  spätestens nach `shutdownHardMs` (10 s) mit Exit-Code 0, was auch noch offen ist. Die Zeitgeber halten den Prozess
  nicht (`unref`); ohne offene Verbindungen endet er sofort.

### Zähler

Nur Summen, nichts je Schlüssel, nichts von der Anfrage (Variante A). Sie erscheinen in `relay.stats()` und in der
Zeile `counts` erst, wenn sie zum ersten Mal gezählt wurden:

| Zähler            | Bedeutung                                                                                                                                           |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `solo`            | Solo-Stempel, die der Dienst gegeben hat (zählt auch in `stamped`)                                                                                  |
| `soloDenied`      | Solo-Anfragen der Art 1 (oder ohne Schlüssel), die sofort `403 solo-not-allowed` bekamen (auch unter `refused`)                                     |
| `keyReloads`      | Neulesen der Schlüsseldatei, das übernommen wurde (das erste Lesen nach dem Start zählt nicht)                                                      |
| `keyReloadFailed` | Neulesen, das verworfen wurde (ungültige oder verschwundene Datei, der alte Satz bleibt); je Zustand der Datei einmal                               |
| `keyFileWritable` | Die Schlüsseldatei wurde für Gruppe oder Andere schreibbar (je Wechsel des Zustands einmal; nur eine Warnung)                                       |
| `keyRevoked`      | Anfragen mit **gültiger Signatur** eines gesperrten Schlüssels (`"revoked": true`); Antwort `401`, wie bei unbekannter Kennung                      |
| `keyExpired`      | Anfragen mit gültiger Signatur eines Schlüssels nach seinem `notAfter`; Antwort `401`, wie bei unbekannter Kennung                                  |
| `serviceDenied`   | Anfragen eines Schlüssels mit `services`, der einen anderen Dienst verlangte: `403 service-not-allowed` (auch unter `refused`)                      |
| `shareDenied`     | Anfragen, die nur wegen des Anteils der Kennung am Dienstbudget `429 key-share` bekamen (`RELAY_KEY_SHARE`; auch unter `refused`); nie je Schlüssel |

`busy`, `solo-not-allowed` und `key-share` stehen außerdem unter `refused` wie jeder Fehlercode.

### Schlüsseldatei laufend lesen

Das Relay liest alle `keyFileCheckMs` (5 s) die Schlüsseldatei und bildet den SHA-256 ihres Inhalts. Hat er sich
geändert, liest es sie **streng** neu (dieselben Regeln wie beim Start). Der Inhalt zählt, nicht Änderungszeit, Größe
oder Inode: eine an Ort und Stelle geschriebene Datei mit zurückgesetzter Änderungszeit wird ebenso gefunden (sonst
bliebe ein gesperrter Schlüssel gültig). Das Lesen ist billig: die Datei ist höchstens `keyFileMaxBytes` (64 KiB) groß.

- **Nur eine reguläre, kleine Datei.** Das Relay öffnet sie ohne zu warten und prüft das geöffnete Handle: eine FIFO, ein
  Gerät, ein Verzeichnis oder eine Datei über `keyFileMaxBytes` wird nicht gelesen (beim Start `config-error`, beim
  Neulesen zählt `keyReloadFailed` einmal je Zustand, der alte Satz bleibt). Ein **Symlink wird verfolgt** (ein Link auf
  eine reguläre Datei ist ein üblicher Weg, sie auszurollen); sein Ziel muss dieselbe Prüfung bestehen.
- **Schreibrechte werden bei jedem Nachsehen geprüft** (POSIX), nicht nur beim Start: ist die Datei für Gruppe oder
  Andere schreibbar, steht eine Zeile `warning` im Log (Pfad und Modus, nichts aus der Datei) und `keyFileWritable` zählt,
  **einmal je Wechsel des Zustands**. Es ist eine Warnung, kein Abbruch: die Datei wird weiter gelesen. Ein beim Start
  schon gemeldeter Zustand wird nicht zum zweiten Mal gemeldet.

- **Neuer Schlüssel:** gilt ab dem Übernehmen. **Entfernter Schlüssel:** ist **sofort** ungültig, sobald das Relay die
  Datei neu gelesen hat (jede Anfrage prüft gegen den aktuellen Satz; das Neulesen geschieht nach spätestens
  `keyFileCheckMs`, auch wenn Änderungszeit, Größe und Inode gleich geblieben sind); das ist der Weg, einen Schlüssel
  zu **sperren**. Auch eine geänderte Art (`solo`) gilt sofort.
- **Ungültige Datei** (kein JSON, Regelverstoß, halb geschrieben, **gelöscht oder unlesbar**): der **alte Satz bleibt aktiv**
  (auch bei einer gelöschten Datei: nicht „kein Schlüssel“, sondern der letzte gültige Satz),
  `keyReloadFailed` zählt, es wird nichts aus der Datei protokolliert. **Alle sperren** geht also nicht durch Löschen der
  Datei, sondern mit einer **ausdrücklich leeren Liste** (`"keys": []`, Abschnitt „Schlüsseldatei Version 3“). Schon beim nächsten Nachsehen wird es erneut
  versucht (eine halb geschriebene Datei wird so bald gelesen, wie sie fertig ist).
- **Zähler, Wiederholungsspeicher und Solo-Zähler bleiben** beim Neulesen erhalten.
- **Das Relay schreibt nie in die Schlüsseldatei.** Sie gehört dem Betreiber; schreiben soll man sie atomar (neue Datei
  schreiben, dann umbenennen).
- Gilt nur mit `RELAY_KEYS_FILE` (nicht mit `RELAY_AUTH=off`).

### Schlüsseldatei Version 3: Sperren, Ablauf, Dienste, eigene Grenze

`{"version": 3, "restartAfter"?: …, "keys": [{"id", "publicKey", "solo"?, "revoked"?, "notAfter"?, "services"?, "perMinute"?}]}`.
Version 2 bleibt lesbar und gilt unverändert; **die vier neuen Felder in einer Version-2-Datei sind ein Lesefehler**
(`v3-field-in-v2-file in keys[i]`). Alles ist streng gelesen wie bisher: keine unbekannten Felder, keine Doppelten, in
Fehlern der Eintragsindex `keys[i]` und nie Inhalt. `restartAfter` und `solo` gelten in beiden Versionen.

| Feld        | Form                                                   | Wirkung                                                                                                                                                                                                                      |
| ----------- | ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `revoked`   | Boolesch (`true`/`false`, nichts sonst)                | Der Schlüssel bleibt in der Datei, wird aber abgewiesen: **dasselbe `401` wie bei unbekannter Kennung**, kein Hinweis an den Aufrufer. Zähler `keyRevoked`                                                                   |
| `notAfter`  | Ganze Zahl, Unix-Sekunden (1000000000 bis 99999999999) | Ab diesem Zeitpunkt wie gesperrt (`jetzt >= notAfter * 1000`, **Wanduhr des Relays**): `401`, Zähler `keyExpired`. Eine Millisekunde davor gilt der Schlüssel noch                                                           |
| `services`  | Liste von 1 bis 16 verschiedenen Dienstkennungen       | Der Schlüssel darf nur diese Dienste nutzen, sonst `403 service-not-allowed`. Jede Kennung muss in `services.json` stehen (auch ein Dienst, den dieses Relay nicht anbietet), sonst Lesefehler `services-unknown in keys[i]` |
| `perMinute` | Ganze Zahl 1 bis `perMinutePerKey` (20)                | Eigene Minutengrenze dieses Schlüssels anstelle von `perMinutePerKey` (`429` mit `Retry-After` darüber); andere Schlüssel bleiben unberührt. Größere Werte: Lesefehler `per-minute`                                          |

**Reihenfolge der Prüfung** (jede Stufe vor der Arbeit der nächsten): Form des Kopfes und Zeit, dann **eine** Signaturprüfung
(auch für unbekannte, gesperrte und abgelaufene Kennungen; bei unbekannter gegen einen Scheinschlüssel, bei gesperrter und
abgelaufener gegen den echten, in jedem Fall genau eine), dann die Entscheidung über den Schlüssel, dann Wiederholungsschutz,
Form des Körpers, `services`, Schlüsselart, Budgets. Ein unbekannter, ein gesperrter und ein abgelaufener Schlüssel
bekommen **dieselbe Antwort** (Status, Körper, Kopfzeilen) und tun **dieselbe Arbeit**; die Antwortzeit verrät nichts.
`keyRevoked` und `keyExpired` zählen nur Anfragen mit **gültiger Signatur** (das Raten einer Kennung zählt nicht), global,
nie je Schlüssel, und jede Abweisung steht außerdem unter `refused['unauthorized']`. Das `403 service-not-allowed` kommt
erst nach gültiger Anmeldung, **vor jeder Arbeit** (wie `solo-not-allowed`): kein Platz, kein Fenster, kein Warten, kein
Budget, kein Wiederholungseintrag.

**Neulesen:** Ein Wechsel auf `"revoked": true` (oder ein geänderter Wert der anderen Felder) wirkt beim nächsten Blick
auf die Datei, **spätestens `keyFileCheckMs` (5 s) nach dem Speichern**. Zähler, Wiederholungsspeicher und die Zeiten
je Schlüssel bleiben (ein neues `perMinute` zählt gegen die schon gezählten Zeiten).

**Leere Liste (`"keys": []`):** gilt in Version 2 und 3 als **gültig** und bedeutet „niemand darf“. Beim **Neulesen** sind
danach alle Schlüssel ungültig (jeder Aufruf `401`), und das Relay schreibt eine Zeile `warning`
(„… keinen Schlüssel …: kein Schlüssel = niemand darf“). Beim **Start** ist die leere Liste zulässig, aber das Relay warnt
mit derselben deutlichen Zeile (ein Relay ohne Schlüssel ist fast immer ein Versehen). Eine **fehlende** Liste (`keys`
nicht vorhanden oder kein Array) ist weiter ungültig.

**Gelöschte, unlesbare oder ungültige Datei:** der alte Satz bleibt aktiv (`keyReloadFailed`), auch wenn die Datei gelöscht
wurde. Wer alle sperren will, **schreibt** eine Datei mit leerer Liste (atomar), er löscht sie nicht. Abläufe für den
Betrieb (sperren, entsperren, Notfall, Rotation mit `notAfter`): `docs/betrieb.md`.

**Sperren und Entsperren:** `"revoked": true` setzen (der Eintrag bleibt als Spur in der Datei, die Kennung bleibt belegt);
entsperren: das Feld entfernen oder auf `false` setzen, der Schlüssel gilt ab dem nächsten Blick wieder. Ein neues
Schlüsselpaar braucht eine **neue** Kennung.

### `restartAfter`: einmaliger sauberer Neustart

Optionales Feld der Schlüsseldatei auf oberster Ebene: `{"version": 2, "restartAfter": 1795000000, "keys": […]}`, eine
ganze Zahl in Unix-Sekunden (1000000000 bis 99999999999, sonst ist die Datei ungültig). Das Relay merkt sich seine
Startzeit. Gilt `Startzeit / 1000 < restartAfter <= jetzt / 1000`, beendet es sich **einmal** sauber (wie bei `SIGTERM`:
`close()` beantwortet Wartende mit `503 shutting-down`, die Verbindungen enden (spätestens nach `shutdownHardMs`, auch bei halbem Request), **Exit-Code 0**, eine Zeile
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
  audience,
});
```

`signRelayRequest` bleibt (bis auf `audience` und das `jti`) unverändert: die App baut den Körper selbst und signiert ihn. **`upstream` steht im signierten
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
Baum (der Dienst sähe sonst Hashes unter fremden Zugangsdaten gebündelt); der Mindestabstand zwischen zwei Aufrufen des Dienstes
gilt **je Spur der Identität** (eine andere Identität hält keinen Aufruf auf). Eine Solo-Anfrage der Art 1 wird vor jeder
Arbeit abgewiesen (nach der Prüfung der Form des Körpers, ungültige Zugangsdaten sind vorher `400 bad-upstream`); gültige
Zugangsdaten spielen dabei keine Rolle und legen keine Identität an.

- **Obergrenze:** höchstens `upstreamIdentitiesMax` (64) Identitäten je Dienst gleichzeitig. Eine Identität wird verworfen,
  wenn sie `max(60 s, minIntervalMs)` ruhig war (auf der monotonen Uhr, ab dem Ende ihrer letzten Anfrage) und nichts mehr für sie wartet (Fenster, Warteschlange, laufender Aufruf);
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
  Weg nach draußen), nicht von einem Menschen geprüft, im Browser nur mit Chromium geprüft und dort nur ohne `upstream`. Mitgelieferte Dienste haben kein `auth`:
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
  hinaus). Springt die **eigene** Uhr des Relays während eines Dienstaufrufs um mehr als 60 s zurück, ergibt das
  `time-in-future` für das **ganze** Fenster (der Dienststempel ist verbraucht, alle Anfragen des Fensters bekommen `502`). Eine Grenze nach 60 s lässt eine Uhrabweichung zwischen Dienst und Relay von bis zu einer Minute zu; ein
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
(Kennung, Zeit, `jti`, Signatur), nie Inhalte und nie den privaten Schlüssel. Es schreibt **nichts** über Anfragen ins Protokoll:
keine Adresse, keinen Hash, kein Token, keine Kennung, keine Signatur. Alle fünf Minuten steht eine
Zeile mit Zählern im Protokoll (Anzahl gestempelter Anfragen und Zahl der Ablehnungen je Art). Die
Netzadresse sieht allerdings die Infrastruktur davor (Hoster, Lastverteiler); das ist Sache des Betreibers.

## Grenzen (`relay/limits.ts`)

| Name                    | Wert   | Bedeutung                                                                                                                                                           |
| ----------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `bodyBytes`             | 512    | Größter Körper einer Anfrage                                                                                                                                        |
| `upstreamBytes`         | 65536  | Größte Antwort eines Dienstes                                                                                                                                       |
| `upstreamTimeoutMs`     | 10000  | Frist für den ganzen Aufruf beim Dienst                                                                                                                             |
| `requestTimeoutMs`      | 5000   | Frist für die ganze eingehende Anfrage (auch die Kopfzeilen)                                                                                                        |
| `perMinuteTotal`        | 60     | Anfragen je Minute über alle Dienste                                                                                                                                |
| `windowMs`              | 60000  | Zeitfenster der Zähler                                                                                                                                              |
| `perMinutePerKey`       | 20     | Anfragen je Minute für eine Schlüsselkennung (ein Drittel)                                                                                                          |
| `authWindowSeconds`     | 60     | Erlaubter Zeitunterschied (Sekunden) der Anfrage zur Relay-Uhr                                                                                                      |
| `authReplayEntries`     | 512    | Obergrenze gemerkter Köpfe, je ein Eintrag (Kennung, `jti`) (real höchstens 180); voll: `429`                                                                       |
| `authReplayKeyShare`    | 0.5    | Anteil des Speichers, den eine Kennung höchstens hält                                                                                                               |
| `genTimeSlackMs`        | 60000  | Token-Zeit: höchstens so weit vor dem Zeitpunkt der Anfrage und so weit hinter der Relay-Uhr (`time-too-old`, `time-in-future`)                                     |
| `maxOrigins`            | 16     | Zahl der einstellbaren Herkünfte                                                                                                                                    |
| `maxConnections`        | 256    | Gleichzeitig offene Verbindungen; weitere lehnt der Server ab                                                                                                       |
| `keepAliveProxyMs`      | 65000  | Leerlauf einer Verbindung zwischen zwei Anfragen bei Loopback-Bindung (`127.0.0.1`, `::1`, `localhost`; länger als der Leerlauf-Timeout üblicher Proxys, 60 s)      |
| `keepAliveDirectMs`     | 5000   | Leerlauf bei jeder anderen Bindung (entspricht `requestTimeoutMs`)                                                                                                  |
| `keepAliveMinMs`        | 1000   | `RELAY_KEEPALIVE_MS`: kleinster Wert                                                                                                                                |
| `keepAliveMaxMs`        | 120000 | `RELAY_KEEPALIVE_MS`: größter Wert                                                                                                                                  |
| `batchMsMin`            | 1000   | `RELAY_BATCH_MS`: kleinster Wert (0 oder leer schaltet den Sammelbetrieb aus)                                                                                       |
| `batchMsMax`            | 60000  | `RELAY_BATCH_MS`: größter Wert                                                                                                                                      |
| `batchMaxDefault`       | 128    | `RELAY_BATCH_MAX`: Wert ohne Angabe                                                                                                                                 |
| `batchMaxMin`           | 2      | `RELAY_BATCH_MAX`: kleinster Wert                                                                                                                                   |
| `batchMaxMax`           | 1024   | `RELAY_BATCH_MAX`: größter Wert (so große Bäume prüft die Bibliothek, `MAX_SIZE`)                                                                                   |
| `soloPerMinutePerKey`   | 4      | Solo-Anfragen je Minute für eine Schlüsselkennung (zusätzlich zu `perMinutePerKey`; nur im Arbeitsspeicher, nicht im Log)                                           |
| `soloQueueMax`          | 6      | Solo-Anfragen, die je Dienst auf einen Platz warten dürfen; eine weitere bekommt `503 busy`                                                                         |
| `singleQueueMax`        | 16     | Einzelbetrieb: Anfragen, die je Spur (Dienst und Identität) auf den Mindestabstand warten dürfen; eine weitere bekommt `503 busy` (nicht `soloQueueMax`)            |
| `maxWaitDefaultMs`      | 30000  | `RELAY_MAX_WAIT_MS`: Wert ohne Angabe                                                                                                                               |
| `maxWaitMinMs`          | 1000   | `RELAY_MAX_WAIT_MS`: kleinster Wert                                                                                                                                 |
| `maxWaitMaxMs`          | 60000  | `RELAY_MAX_WAIT_MS`: größter Wert (Proxy- und Client-Fristen im Einzelbetrieb mindestens Wartegrenze + 17 s, im Sammelbetrieb Wartegrenze + Fenster + Kette + 17 s) |
| `keyShareMin`           | 10     | `RELAY_KEY_SHARE`: kleinster Wert in Prozent                                                                                                                        |
| `keyShareMax`           | 100    | `RELAY_KEY_SHARE`: größter Wert und Wert ohne Angabe (100 = aus)                                                                                                    |
| `upstreamUserMax`       | 64     | Zugangsdaten der App: längster Benutzername bei `basic` (druckbares ASCII, ohne `:`)                                                                                |
| `upstreamPasswordMax`   | 128    | längstes Passwort bei `basic` (druckbares ASCII)                                                                                                                    |
| `upstreamTokenMax`      | 384    | längstes Token bei `bearer` und `header` (druckbares ASCII ohne Leerzeichen, `"` und `\`)                                                                           |
| `upstreamIdentitiesMax` | 64     | gleichzeitig bekannte Zugangsdaten-Identitäten je Dienst (nur Arbeitsspeicher); eine weitere neue bekommt `503 busy`                                                |
| `shutdownGraceMs`       | 2000   | Beenden: nach dieser Zeit werden alle Verbindungen geschlossen (auch eine mit halbem Request; Leerlauf-Verbindungen sofort)                                         |
| `shutdownHardMs`        | 10000  | Beenden: spätestens nach dieser Zeit endet der Prozess mit Exit-Code 0, was auch noch offen ist                                                                     |
| `keyFileCheckMs`        | 5000   | Abstand, in dem das Relay die Schlüsseldatei liest (SHA-256 des Inhalts) und ihre Schreibrechte prüft                                                               |
| `keyFileMaxBytes`       | 65536  | Größte Schlüsseldatei, die das Relay liest (Bytes); größere und Nicht-Dateien (FIFO, Gerät, Verzeichnis) werden nicht gelesen                                       |

Je Schlüsselkennung gilt zusätzlich `perMinutePerKey`. Je Dienst gilt zusätzlich `60000 / minIntervalMs` Anfragen je Minute (bei 15 s: 4, bei FreeTSA mit 5 s: 12). `perMinuteTotal` und
`minIntervalMs` sind zuerst ein **Mengenbudget je Minute**: Das Relay lässt höchstens so viele Anfragen durch, dass der
**Dienst** in jedem gleitenden Fenster von einer Minute höchstens so viele Aufrufe sieht; danach kommen Anfragen mit `429`
und `Retry-After` (oder, im Sammelbetrieb, eine kurze Wartezeit). Im **Sammelbetrieb** zählt der Zeitpunkt des **Stempels**
(des Aufrufs beim Dienst; Fenster und Solo-Stempel, siehe „Der Planer je Dienst“), im **Einzelbetrieb** dagegen die
**Annahme** der Anfrage (Tür, Wanduhr; siehe unten). **Im Sammelbetrieb** gilt zusätzlich der
**Mindestabstand** `minIntervalMs` zwischen zwei Aufrufen desselben Dienstes (und derselben Zugangsdaten-Identität), in
**beiden Betriebsarten**: im Sammelbetrieb für Solo-Stempel und Fenster, im **Einzelbetrieb** für jeden Stempel. Im
Einzelbetrieb nimmt eine Anfrage den nächsten freien Zeitpunkt ihrer Spur (Reihenfolge des Eingangs) und wartet darauf,
höchstens `RELAY_MAX_WAIT_MS` (Vorgabe 30 s). Liegt der Zeitpunkt schon beim Eingang später als die Wartegrenze, gibt es
`429` mit `Retry-After` (wie beim Mengenbudget), sonst wartet sie; höchstens `singleQueueMax` (16) Anfragen je Spur (Dienst und
Identität) warten, eine weitere bekommt `503 busy`. Läuft ein Aufruf später als geplant (das Relay stand still) und würde die
Anfrage dadurch die Wartegrenze um mehr als `WAIT_TOLERANCE_MS` (50 ms: Verspätungen der Zeitgeber werden toleriert)
überschreiten (verglichen wird der Zeitpunkt, zu dem der Zeitgeber wirklich feuert, nicht nur der gebuchte), bekommt sie
`503 busy`, ohne gestempelt zu werden; im Sammelbetrieb gilt dasselbe für eine Anfrage in der Warteschlange auf einen Platz; `close()` beantwortet alle
Wartenden mit `503 shutting-down`. Das Mengenbudget gilt zusätzlich; im Einzelbetrieb zählt es die Annahme (Tür, Wanduhr),
nicht den Aufruf beim Dienst. Gemessen wird auf der
monotonen Uhr des Prozesses (`performance.now()`), nicht auf der Wanduhr. **Welche Zähler auf welcher Uhr laufen:** im Sammelbetrieb
**alle** Zähler je Minute (Dienst je Spur, gesamt `perMinuteTotal`, je Schlüssel `perMinutePerKey`, Solo je Schlüssel) sowie
Abstand und Wartezeiten auf der monotonen Uhr; im Einzelbetrieb der Mindestabstand und der Ablauf einer Zugangsdaten-Identität (sie endet frühestens
`max(60 s, minIntervalMs)` nach dem Ende ihrer letzten Anfrage; der Abstand bleibt davon unberührt, weil der letzte Aufruf
vor diesem Ende liegt). Die Mengenzähler dort (gesamt, je Schlüssel, je Spur) bleiben auf der Wanduhr: ein Sprung der
Wanduhr nach vorn gibt dort Plätze des Mengenbudgets zurück. Die Anmeldung (60 s) und die Prüfung von `genTime` (±60 s)
werden von der Wartezeit nicht berührt: der Kopf wird beim Eingang geprüft und gemerkt, die Wartegrenze ist höchstens 60 s,
und der Token wird erst beim Senden an den Dienst (nach dem Warten) angefordert und gegen diesen Zeitpunkt geprüft.

**Grenze der Zähler:** Die globalen und die Dienst-Zähler gelten für alle Aufrufer zusammen, nicht je
Netzadresse (das Relay kennt keine Adressen); je Aufrufer zählt nur die Schlüsselkennung. Wer einen gültigen
Schlüssel hat, kann sein Budget und das gemeinsame Limit für alle ausschöpfen. Schutz vor Überlast durch viele
Aufrufer ist Aufgabe der Infrastruktur davor.

**Uhr zurückgestellt:** Die Zähler der Fenster (gesamt, je Dienst, je Kennung) und die Restzeit der Einträge des
Wiederholungsspeichers rechnen Zeitpunkte in der Zukunft beim Lesen als „jetzt“. (Im Sammelbetrieb läuft der Planer mit den
Zählern je Minute auf der monotonen Uhr und sieht die Wanduhr nicht; die Regel gilt dort für die Wanduhr-Teile, also den
Wiederholungsspeicher, und gegen eine künstlich zurückgesetzte monotone Uhr.) Ein Rückwärtssprung der Uhr sperrt
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
- Eine **Lese-Frist von mindestens `RELAY_MAX_WAIT_MS` + 17 s** (Einzelbetrieb, Vorgabe 47 s, besser 3 s mehr): bis zu 5 bis 6 s für den Körper, bis zu 10 s für den Dienst,
  dazu die Prüfung und, im Einzelbetrieb wie im Sammelbetrieb, das Warten auf den Mindestabstand (höchstens `RELAY_MAX_WAIT_MS`). Kürzere Fristen des Proxys brechen Stempel ab, die das Relay noch zählt. **Im Sammelbetrieb**
  kommen das Fenster und die Kette der auf den Mindestabstand wartenden Fenster dazu:
  mindestens `RELAY_MAX_WAIT_MS` + `RELAY_BATCH_MS` + Kette + 17 s („Latenz und Fristen“).
- **Ratenlimit und Verbindungslimit je Adresse.** Das Relay selbst kennt keine Adressen. Der Rahmen ist klein: die vier
  mitgelieferten Dienste erlauben zusammen 24 Anfragen je Minute (FreeTSA mit 5 s: 12, die drei anderen mit 15 s: je 4).
- **Das Limit je Adresse muss deutlich unter dem Budget eines Schlüssels liegen.** Ein App-Schlüssel gehört allen
  Besuchern dieser App; `perMinutePerKey` ist 20 je Minute und Schlüsselkennung. Erlaubt der Proxy je Adresse ebenfalls
  20 je Minute, kann **ein einzelner Besucher** (mit dem ausgelesenen Schlüssel oder nur mit dem normalen Aufruf der App)
  das ganze Budget der App aufbrauchen und alle anderen Besucher aussperren. Die Beispiele erlauben deshalb je Adresse
  **5 je Minute** (Burst 3): ein Besucher stempelt selten mehr als einmal, die Dienste mit 15 s erlauben ohnehin nur 4 je
  Minute für alle, und es braucht mindestens vier Adressen, um 20 je Minute zu erreichen. Das ist eine Empfehlung, kein
  Beweis: wer Besucher hinter einer gemeinsamen Adresse hat (Firmennetz, mobiles Netz mit gemeinsamer Adresse), wählt die Zahl
  nach seiner Last, oder setzt **eine eigene Schicht in der App** davor (Anmeldung des Besuchers, Zähler je Konto), und lässt
  den App-Schlüssel nur dieser Schicht gehören. Ein Limit je Adresse ersetzt keinen Schutz vor einem ausgelesenen
  Schlüssel: Sperren heißt, den Schlüssel aus der Datei zu entfernen („Schlüsseldatei laufend lesen“); dann sind auch alle
  ehrlichen Besucher der App ausgesperrt, bis die App einen neuen Schlüssel hat.
- **Genau eine Relay-Instanz je Schlüsseldatei und Audience.** Die Signatur bindet Methode, Pfad, Audience, Zeit, `jti` und
  Körper, **nicht den Host**: haben zwei Instanzen mit derselben Schlüsseldatei **dieselbe** `RELAY_AUDIENCE`, wird derselbe
  Kopf von beiden angenommen (`200`, dann `401` an der ersten, `200` an der zweiten); haben sie **verschiedene**, gilt er nur
  bei der gemeinten (`401` bei der anderen). Jede Instanz hat eigene Budgets (`perMinuteTotal`, `perMinutePerKey`, Dienstbudget)
  und einen eigenen Wiederholungsspeicher; zwei Instanzen verdoppeln also die Budgets und lassen bei gleicher Audience einen abgefangenen Kopf
  zweimal gelten. Wer mehr Last oder Ausfallsicherheit braucht, nimmt **getrennte Schlüsseldateien** (andere Schlüsselkennungen
  je Instanz) oder einen Proxy, der alle Anfragen eines Schlüssels an dieselbe Instanz leitet. Test- und Produktivschlüssel
  gehören nicht in dieselbe Datei. Ein Neustart (auch `restartAfter`) leert den Wiederholungsspeicher.
- Körper höchstens 512 Byte (das Relay lehnt mehr ab); der Proxy darf früher abweisen.
- `GET /health` ist für Überwachung gedacht; es prüft keinen Dienst.

**nginx** (Beispiel, nicht getestet):

```nginx
# Der Preflight (OPTIONS) bekommt einen leeren Schlüssel: nginx begrenzt ihn nicht.
map $request_method $zs_key {
    OPTIONS  "";
    default  $binary_remote_addr;
}
limit_req_zone  $zs_key zone=zs_rate:10m rate=5r/m;
limit_conn_zone $binary_remote_addr zone=zs_conn:10m;

upstream zeitstempel_relay {
    server 127.0.0.1:8080;
    keepalive 8;                            # ohne diesen Block hält nginx keine Verbindung zum Relay offen
}

server {
    listen 443 ssl;
    server_name relay.example;
    # ssl_certificate / ssl_certificate_key: eigene Einrichtung

    client_max_body_size   1k;
    client_header_timeout  6s;
    client_body_timeout    6s;

    # Alles außer dem Stempel: ohne Ratenlimit (Preflight, /health, /v1/services); die Verbindungsgrenze bleibt.
    location / {
        limit_conn zs_conn 10;
        limit_conn_status 429;

        proxy_pass http://zeitstempel_relay;   # ohne Pfad hinter der Adresse: der Pfad bleibt unverändert
        proxy_http_version 1.1;
        proxy_set_header Connection "";     # nur zusammen mit keepalive im upstream-Block wirksam
        proxy_set_header Host $host;
        proxy_connect_timeout 5s;
        proxy_read_timeout    10s;
        proxy_redirect off;
    }

    # Nur der Stempel wird je Adresse gedrosselt; der Preflight (OPTIONS) zählt nicht mit (leerer Schlüssel oben).
    location /v1/stamp/ {
        limit_req  zone=zs_rate burst=3 nodelay;   # je Adresse 5 je Minute (siehe unten), nie das ganze Schlüsselbudget
        limit_conn zs_conn 10;
        limit_req_status  429;
        limit_conn_status 429;

        proxy_pass http://zeitstempel_relay;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_connect_timeout 5s;
        proxy_send_timeout    20s;
        proxy_read_timeout    130s;         # Obergrenze für die Vorgabe (30 s Wartegrenze): Einzelbetrieb mindestens 47 s,
                                            # Sammelbetrieb FreeTSA 57 s, 15-s-Dienst 77 s, bei kleinem RELAY_BATCH_MAX
                                            # 112 s beziehungsweise 122 s, mit 3 s Reserve bis 125 s; siehe „Latenz und Fristen“
        proxy_redirect off;
        # Origin und X-Zeitstempel-Auth gibt nginx von sich aus weiter: nicht mit proxy_set_header leeren.
    }
}
```

Hinweise zum Beispiel: `limit_req` steht nur in der `location` des Stempels, damit der Preflight (`OPTIONS`), `/health` und
`/v1/services` nicht in dasselbe Budget fallen (sonst ist es nach Preflight, Dienstliste und erstem Stempel schon fast
verbraucht). Wer den Preflight dennoch im selben Block begrenzen will, setzt für ihn ein eigenes, höheres Limit.
**Antworten von nginx selbst** (`429` vom Ratenlimit, `413`, `408`, `502`/`504`) tragen keine CORS-Köpfe: der Browser meldet
dann einen Netzwerkfehler, ohne Status und ohne `Retry-After`; die App kann das nicht von einem Ausfall unterscheiden und
sollte nach einer Pause einmal wiederholen. Nur die Antworten des Relays tragen `Access-Control-*` und `Retry-After`.

**Caddy** (Beispiel, nicht getestet). Caddy kann ohne Zusatzmodul **kein** Ratenlimit je Adresse; das Modul (zum Beispiel
`caddy-ratelimit`) muss hinzugebaut werden, sonst fehlt der wichtigste Teil. Die Zeilen dazu hängen von dessen Fassung
ab und stehen deshalb hier nur als Gerüst:

```caddyfile
relay.example {
    # rate_limit { zone je_adresse { key {remote_host}  events 5  window 1m } }   # Zusatzmodul nötig
    reverse_proxy 127.0.0.1:8080 {
        # Caddy hält Verbindungen zum Relay von sich aus offen (keepalive ist vorgegeben); nichts zu setzen.
        transport http {
            dial_timeout            5s
            response_header_timeout 130s   # Obergrenze für die Vorgabe (30 s Wartegrenze): Einzelbetrieb mindestens 47 s,
                                           # Sammelbetrieb FreeTSA 57 s, 15-s-Dienst 77 s, bei kleinem RELAY_BATCH_MAX
                                           # 112 s beziehungsweise 122 s, mit 3 s Reserve bis 125 s
        }
    }
}
```

`reverse_proxy` gibt Pfad und Köpfe (`Origin`, `X-Zeitstempel-Auth`) von sich aus unverändert weiter. Das Ratenlimit (Zusatzmodul)
gehört auch hier nur auf den Pfad `/v1/stamp/*` (Matcher `@stamp path /v1/stamp/*`), nicht auf Preflight, `/health` und
`/v1/services`; Antworten von Caddy selbst tragen ebenfalls keine CORS-Köpfe.

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
- **Relay- und App-Stand müssen zusammenpassen.** Die Kopfform (`v3`, mit Audience), die Kennungen der Dienste (`services.json`), die
  Anker und die Regeln der Prüfung (hier: die Zeitgrenzen) gehören zu einem Stand. Wird das Relay oder `services.json`
  aktualisiert, die App gleich mitnehmen (und umgekehrt): eine App mit alten Ankern meldet `untrusted-chain`, ein Relay
  mit alten Ankern `upstream-invalid`; eine App ohne `minGenTime` prüft die Frische nicht, auch wenn das Relay es tut.
