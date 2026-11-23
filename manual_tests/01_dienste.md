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

## MT-03: Das Relay von außen ansprechen

**Voraussetzung:** Das Relay läuft (`RELAY_ORIGINS=http://localhost:5178 npm run relay`, in einem zweiten Fenster).

**Schritte**

1. Im Browser die Adresse `http://localhost:8080/health` öffnen.
2. Im Terminal: `curl -i -X POST -H "Content-Type: application/json" -d "{\"hash\":\"abc\"}" http://localhost:8080/v1/stamp/freetsa`

**Erwartet**

- Schritt 1 zeigt `{"ok":true,"services":["freetsa","sectigo"]}`; `digicert` und `certum` fehlen, weil sie nur
  über http antworten und das Relay sie ohne `RELAY_ALLOW_PLAIN_HTTP=1` nicht anbietet.
- Schritt 2 antwortet `400` mit `{"error":"bad-hash"}`: Es ging nichts an den Dienst.
