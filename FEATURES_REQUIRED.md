# Critical User Paths — Zeitstempel

**Purpose:** Core workflows that must not break. Audit validates these end-to-end.

## Bibliothek

- [x] **Anfrage bauen** — gültiges DER, von openssl lesbar (Golden Bytes in `tests/der.test.ts`; „von openssl lesbar“ belegt `tests/openssl.test.ts`)
- [x] **Antwort lesen** — Status, Token, Inhalt; Ablehnung mit Statusnummer
- [x] **Token prüfen** — vier aufgezeichnete Antworten echter Dienste werden akzeptiert; jede Veränderung der signierten Teile oder des Abdrucks wird abgelehnt. Unsignierte Teile (etwa eine Zertifikatskopie außerhalb der Kette oder ungenutzte Felder) dürfen sich ändern, ohne das Ergebnis zu ändern: im FreeTSA-Token werden so 3864 von 9268 Ein-Bit-Änderungen angenommen, das Ergebnis bleibt identisch. Apps sollen Token deshalb nicht über ihre Bytes vergleichen (`tests/verify.test.ts`, `tests/services-fixtures.test.ts`)
- [x] **Beleg im Sammelbetrieb prüfen** — `verifyBatchedTimestamp` gegen eine unabhängige Referenz des Baumes, jede Veränderung abgelehnt (`tests/batch.test.ts`)
- [x] **Übereinstimmung mit openssl** — `tests/openssl.test.ts` (nur mit openssl auf dem Rechner)
- [x] **`tsa`-Name, TSTInfo als Schema, RSA-Mindestgröße** — `tsa` gegen das Zeitstempel-Zertifikat (`tsa-mismatch`), Reihenfolge und Wertebereiche des TSTInfo (`bad-tst-info`), `minRsaBits` (`weak-key`); jede Regel mit OpenSSL-Gegenprobe und dokumentiertem Unterschied (`tests/tstinfo.test.ts`, `tests/rsa-bits.test.ts`, `tests/openssl.test.ts`, Tabelle in `docs/grenzen.md`)
- [x] **Unterzeichner über `subjectKeyIdentifier` (SignerInfo Version 3)** — beide Formen gelesen, Version und Form müssen zusammenpassen (`unsupported-version`), Kandidatenwahl über den Hash des `signingCertificate`-Attributs, ein Zertifikat ohne die Erweiterung wird nie gefunden (`tests/ski-signer.test.ts`; Gegenprobe mit `openssl cms -verify` und einem von OpenSSL geschriebenen Token in `tests/openssl.test.ts`; noch kein echter Dienst, der so stempelt)
- [x] **Merkle-Baum gegen veröffentlichte RFC-6962-Werte** — Wurzeln und Prüfpfade der acht Testblätter (`tests/batch-vectors.test.ts`)
- [x] **Kern ohne Node-Importe** — Wächter-Test (`tests/coupling.test.ts`)
- [x] **Läuft in einem Browser** — nur Headless-Chromium 157: Relay-Authentifizierung am 2026-11-24 per Prüfskript (nicht im Repo) geprüft: signierte Aufrufe, CORS-Preflight, Sammelbetrieb, Solo, vier Fixtures: 47 Prüfungen ohne Unterschied zu Node; Firefox und Safari nicht geprüft. Das eingecheckte `scripts/browser-check.mjs` ist die ältere Fassung ohne Anmeldung

## Relay

- [x] **Hash stempeln** — JSON und Rohbytes, Antwort wird vor der Weitergabe geprüft (`tests/relay.test.ts`)
- [x] **Kein offener Proxy** — nur Kennungen aus `services.json`, Anfrage vom Relay gebaut
- [x] **Herkunft** — nur konfigurierte Browser-Herkünfte
- [x] **Relay lehnt Anfragen ohne gültige Signatur ab** — einheitlich `401` (`tests/relay.test.ts`, `tests/auth.test.ts`)
- [x] **Wiederholung wird abgelehnt** — Replay-Cache auf den Digest der signierten Nachricht (`tests/relay.test.ts`)
- [x] **Schlüsseldatei streng gelesen** — nur öffentliche Schlüssel, jede Abweichung ein Fehler (`tests/relay-keys.test.ts`)
- [x] **Sammelbetrieb** — ein Stempel je Fenster, Beleg je Anfrage, Fehler und Schließen beantworten alle (`tests/batch-relay.test.ts`; nur gegen einen Stub, nie gegen einen echten Dienst)
- [x] **Schlüsselarten und Solo-Stempel** — Solo nur für Art 2 (Art 1 mit `mode: "solo"` sofort `403 solo-not-allowed`, vor jeder Arbeit, ohne Budget), `mode` durch die Signatur gebunden, Planer je Dienst (Solo belegt den Platz, abwechselnd, Mindestabstand `minIntervalMs` zwischen zwei Aufrufen eines Dienstes (im Sammelbetrieb für Solo und Fenster, im Einzelbetrieb für jeden Stempel), `503 busy` nach `RELAY_MAX_WAIT_MS`, Warteschlange und Solo-Limit je Schlüssel begrenzt) (`tests/solo.test.ts`, `tests/solo-spacing.test.ts`, `tests/solo-chain.test.ts`: Ketten wartender Fenster, Stillstand der Ereignisschleife; Frist der App: im Einzelbetrieb Wartegrenze + 17 s, im Sammelbetrieb Wartegrenze + Fenster + Kette + 17 s; nur gegen einen Stub)
- [x] **Schlüsseldatei laufend neu gelesen** — neuer Schlüssel gilt, entfernter beim nächsten Blick nicht mehr (höchstens 5 s), ungültige Datei behält den alten Satz, `restartAfter` beendet einmal und die Datei wird nie geschrieben (`tests/solo.test.ts`)
- [x] **Zugangsdaten zu bezahlten Diensten** — `auth` streng gelesen (nur https), `upstream` im signierten Körper (`400 bad-upstream`, kein CR/LF, kein `:` im Benutzernamen), Quellen `relay`/`client`/`either`, Kopf nur nach https, Fenster und Dienstbudget je Identität nie gemischt, Obergrenze der Identitäten, nichts davon in Protokoll, Zählern oder Fehlern (`tests/upstream-auth.test.ts`, `tests/upstream-network.test.ts`; nur gegen Stubs, nie gegen einen echten bezahlten Dienst)
- [x] **Grenzen** — Körpergröße, Zähler, Fristen, Größe der Antwort
- [x] **Echte Dienste** — `npm run probe -- --service freetsa` und `npm run spike` (von Hand, Netz nötig)
- [ ] **Betrieb** — nicht ausgerollt, kein Image

| Path                                                                        | Impact                             | Audit Check                                                                                                         |
| --------------------------------------------------------------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Eine Veränderung der signierten Teile oder des Abdrucks wird nie akzeptiert | Falscher Nachweis                  | `tests/verify.test.ts` (jedes dritte Byte verändert; ausgenommen die ungenutzte Wurzel-Kopie, siehe „Token prüfen“) |
| Ein Token für einen anderen Hash wird abgelehnt                             | Falscher Nachweis                  | `imprint-mismatch` in `tests/verify.test.ts`                                                                        |
| Das Relay gibt nichts Ungeprüftes weiter                                    | App verlässt sich auf falsche Zeit | `tests/relay.test.ts` (`upstream-invalid`)                                                                          |
| Keine privaten Projektnamen im Repo                                         | Öffentliches Repo                  | `tests/coupling.test.ts`                                                                                            |
