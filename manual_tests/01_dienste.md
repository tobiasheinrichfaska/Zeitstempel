# 01 Dienste

## MT-01: Alle Dienste antworten und werden doppelt geprüft

**Voraussetzung:** Vorbereitung erledigt.

**Schritte**

1. Im Projektordner `npm run spike` ausführen.
2. Die Tabelle am Ende ansehen.

**Erwartet**

- Vier Zeilen: `freetsa`, `sectigo`, `digicert`, `certum`.
- In jeder Zeile steht bei `own` und bei `openssl` jeweils `OK`, die Antwort ist `200 application/timestamp-reply`,
  und `time` zeigt die aktuelle Zeit in UTC.
- Letzte Zeile: `all services OK`.
- Nicht offensichtlich: Fehlt `openssl` auf dem Rechner, steht in der Spalte `n/a`. Das ist kein Fehler, aber dann
  wurde nur mit unserer eigenen Prüfung geprüft.
- Antwortet ein Dienst nicht (Wartung, Sperre), steht dort ein Fehler. Dann den Test später wiederholen, bevor
  ein Fehler im Projekt vermutet wird.

## MT-02: Ein Stempel über das Relay

**Voraussetzung:** Vorbereitung erledigt; mindestens eine Minute seit dem letzten Lauf.

**Schritte**

1. `npm run probe -- --service freetsa` ausführen.

**Erwartet**

- Eine Zeile `freetsa: HTTP 200 in … ms, time …, own verification of the returned token: OK`.
- Danach `npm run probe -- --service gibtesnicht`: die Meldung `unknown service` und kein Netzverkehr.

**Schlüssel:** Dieser Lauf braucht **keine** Schlüssel (das Relay läuft in demselben Prozess, mit einem Schlüsselpaar
nur für diesen Lauf). Nur mit `--relay <url>` (ein laufendes Relay, das signierte Anfragen verlangt) müssen
`RELAY_PRIVATE_KEY` (privater Schlüssel, wie ihn `npm run make-key -- <kennung>` in der ersten Zeile ausgibt) und
`RELAY_KEY_ID` in der Umgebung stehen, nie auf der Kommandozeile.

## MT-03: Das Relay von außen ansprechen

**Voraussetzung:** Vorbereitung erledigt. Zwei Wege; das Relay läuft jeweils in einem zweiten Fenster, Port 8080.

### Weg a: lokal ohne Schlüssel (`RELAY_AUTH=off`, nur Loopback)

**Schritte**

1. `RELAY_AUTH=off RELAY_ORIGINS=http://localhost:5178 npm run relay` (Windows PowerShell:
   `$env:RELAY_AUTH='off'; $env:RELAY_ORIGINS='http://localhost:5178'; npm run relay`). Das Relay lauscht nur auf
   `127.0.0.1` und warnt beim Start auf stderr (`auth off, loopback only`).
2. Im Browser `http://localhost:8080/health` öffnen.
3. Im Terminal einen unsignierten POST senden:
   `curl -i -X POST -H "Content-Type: application/json" -d "{\"hash\":\"abc\"}" http://127.0.0.1:8080/v1/stamp/freetsa`

**Erwartet**

- Schritt 2 zeigt `{"ok":true,"services":["freetsa","sectigo"]}`; `digicert` und `certum` fehlen, weil sie nur
  über http antworten und das Relay sie ohne `RELAY_ALLOW_PLAIN_HTTP=1` nicht anbietet.
- Schritt 3 antwortet `400` mit `{"error":"bad-hash"}`: Es ging nichts an den Dienst (ohne Anmeldung wird der Körper
  gleich geprüft).

### Weg b: mit Schlüssel (`RELAY_KEYS_FILE`)

**Schritte**

1. Schlüsselpaar erzeugen: `npm run make-key -- test-app` (Ausgabe nur im Terminal). Zeile 1 ist der private
   Schlüssel (nirgends ablegen, nicht ins Repo), Zeile 2 der Eintrag für die Schlüsseldatei.
2. Eine Schlüsseldatei **außerhalb des Repos** (oder mit einem Namen, den `.gitignore` abdeckt, z. B.
   `relay-keys.json`) anlegen: `{"version": 2, "keys": [<Zeile 2>]}`.
3. `RELAY_KEYS_FILE=relay-keys.json RELAY_ORIGINS=http://localhost:5178 npm run relay` starten.
4. Im Browser `http://localhost:8080/health` öffnen.
5. Unsignierten POST senden (wie oben, Adresse `http://localhost:8080/v1/stamp/freetsa`).

**Erwartet**

- Schritt 4 wie in Weg a.
- Schritt 5 antwortet `401` mit `{"error":"unauthorized"}`: ohne den Kopf `X-Zeitstempel-Auth` gibt es keinen Stempel,
  und nichts ging an den Dienst. Einen signierten Aufruf macht `npm run probe -- --service freetsa --relay
http://localhost:8080` mit `RELAY_PRIVATE_KEY` und `RELAY_KEY_ID` in der Umgebung (das ist ein echter Stempel,
  also die Wartezeit von einer Minute beachten).
