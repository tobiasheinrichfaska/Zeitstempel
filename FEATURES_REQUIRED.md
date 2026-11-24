# Critical User Paths — Zeitstempel

**Purpose:** Core workflows that must not break. Audit validates these end-to-end.

## Bibliothek

- [x] **Anfrage bauen** — gültiges DER, von openssl lesbar (Golden Bytes in `tests/der.test.ts`; „von openssl lesbar“ belegt `tests/openssl.test.ts`)
- [x] **Antwort lesen** — Status, Token, Inhalt; Ablehnung mit Statusnummer
- [x] **Token prüfen** — vier aufgezeichnete Antworten echter Dienste werden akzeptiert, jede Veränderung abgelehnt (`tests/verify.test.ts`, `tests/services-fixtures.test.ts`)
- [x] **Beleg im Sammelbetrieb prüfen** — `verifyBatchedTimestamp` gegen eine unabhängige Referenz des Baumes, jede Veränderung abgelehnt (`tests/batch.test.ts`)
- [x] **Übereinstimmung mit openssl** — `tests/openssl.test.ts` (nur mit openssl auf dem Rechner)
- [x] **Kern ohne Node-Importe** — Wächter-Test (`tests/coupling.test.ts`)
- [x] **Läuft in einem Browser** — nur eingeschränkt: einmal in Headless-Chromium, von Hand (`node scripts/browser-check.mjs`), **ohne Anmeldung am Relay**; Firefox, Safari und die Anmeldung (`signRelayRequest`) im Browser nicht geprüft

## Relay

- [x] **Hash stempeln** — JSON und Rohbytes, Antwort wird vor der Weitergabe geprüft (`tests/relay.test.ts`)
- [x] **Kein offener Proxy** — nur Kennungen aus `services.json`, Anfrage vom Relay gebaut
- [x] **Herkunft** — nur konfigurierte Browser-Herkünfte
- [x] **Relay lehnt Anfragen ohne gültige Signatur ab** — einheitlich `401` (`tests/relay.test.ts`, `tests/auth.test.ts`)
- [x] **Wiederholung wird abgelehnt** — Replay-Cache auf den Digest der signierten Nachricht (`tests/relay.test.ts`)
- [x] **Schlüsseldatei streng gelesen** — nur öffentliche Schlüssel, jede Abweichung ein Fehler (`tests/relay-keys.test.ts`)
- [x] **Sammelbetrieb** — ein Stempel je Fenster, Beleg je Anfrage, Fehler und Schließen beantworten alle (`tests/batch-relay.test.ts`; nur gegen einen Stub, nie gegen einen echten Dienst)
- [x] **Grenzen** — Körpergröße, Zähler, Fristen, Größe der Antwort
- [x] **Echte Dienste** — `npm run probe -- --service freetsa` und `npm run spike` (von Hand, Netz nötig)
- [ ] **Betrieb** — nicht ausgerollt, kein Image

| Path                                            | Impact                             | Audit Check                                          |
| ----------------------------------------------- | ---------------------------------- | ---------------------------------------------------- |
| Ein verändertes Token wird nie akzeptiert       | Falscher Nachweis                  | `tests/verify.test.ts` (jedes dritte Byte verändert) |
| Ein Token für einen anderen Hash wird abgelehnt | Falscher Nachweis                  | `imprint-mismatch` in `tests/verify.test.ts`         |
| Das Relay gibt nichts Ungeprüftes weiter        | App verlässt sich auf falsche Zeit | `tests/relay.test.ts` (`upstream-invalid`)           |
| Keine privaten Projektnamen im Repo             | Öffentliches Repo                  | `tests/coupling.test.ts`                             |
