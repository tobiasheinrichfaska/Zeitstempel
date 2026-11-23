# Critical User Paths — Zeitstempel

**Purpose:** Core workflows that must not break. Audit validates these end-to-end.

## Bibliothek

- [x] **Anfrage bauen** — gültiges DER, von openssl lesbar (`tests/der.test.ts`)
- [x] **Antwort lesen** — Status, Token, Inhalt; Ablehnung mit Statusnummer
- [x] **Token prüfen** — vier aufgezeichnete Antworten echter Dienste werden akzeptiert, jede Veränderung abgelehnt (`tests/verify.test.ts`, `tests/services-fixtures.test.ts`)
- [x] **Übereinstimmung mit openssl** — `tests/openssl.test.ts` (nur mit openssl auf dem Rechner)
- [x] **Kern ohne Node-Importe** — Wächter-Test (`tests/coupling.test.ts`)
- [ ] **Läuft in einem Browser** — nicht geprüft

## Relay

- [x] **Hash stempeln** — JSON und Rohbytes, Antwort wird vor der Weitergabe geprüft (`tests/relay.test.ts`)
- [x] **Kein offener Proxy** — nur Kennungen aus `services.json`, Anfrage vom Relay gebaut
- [x] **Herkunft** — nur konfigurierte Browser-Herkünfte
- [x] **Grenzen** — Körpergröße, Zähler, Fristen, Größe der Antwort
- [x] **Echte Dienste** — `npm run probe -- --service freetsa` und `npm run spike` (von Hand, Netz nötig)
- [ ] **Betrieb** — nicht ausgerollt, kein Image

| Path                                            | Impact                             | Audit Check                                          |
| ----------------------------------------------- | ---------------------------------- | ---------------------------------------------------- |
| Ein verändertes Token wird nie akzeptiert       | Falscher Nachweis                  | `tests/verify.test.ts` (jedes dritte Byte verändert) |
| Ein Token für einen anderen Hash wird abgelehnt | Falscher Nachweis                  | `imprint-mismatch` in `tests/verify.test.ts`         |
| Das Relay gibt nichts Ungeprüftes weiter        | App verlässt sich auf falsche Zeit | `tests/relay.test.ts` (`upstream-invalid`)           |
| Keine privaten Projektnamen im Repo             | Öffentliches Repo                  | `tests/coupling.test.ts`                             |
