# Übergabe an die Cloud-Session (Stand 2026-11-27)

**Für:** die nächste Claude-Code-Session im Web (claude.ai/code), die dieses Repo weiterbearbeitet.
Lies zuerst `CLAUDE.md`, dann dieses Blatt. Dieses Blatt ist der Arbeitsauftrag; es ersetzt `docs/AUFTRAG_2026-11-27.md` nicht, sondern sagt, wie weit der Auftrag ist.

## 1. Wo wir stehen

Bis hierher wurde auf dem lokalen Windows-PC gearbeitet. Ab jetzt wird **in der Cloud** gearbeitet: Code, Tests, Docs, Fehlersuche, über Commits und Pull Requests auf GitHub.

Der PC wird nur noch gebraucht für: Push nach GitHub nach Freigabe von Tobias, Prüfungen auf echten Geräten (Firefox, Safari) und Läufe gegen die echten Dienste von Hand. Kein Upload, keine Serverregeln, keine Zugangsdaten, kein Schlüssel liegt für dieses Projekt auf dem PC.

**Was vor der Übergabe passiert ist (Auftrag „Audit“, 2026-11-27), zwei Runden:**

- Runde 1: Audit durch vier lesende Agenten (Bibliothek, Relay, Client mit Doku, Test-Triage), jeder Befund gegen den Quellcode geprüft.
  - Behoben mit Regressionstest: `isRelayAddress` lässt ein Passwort in der Adresse nicht mehr durch (`https://:secret@relay.example`); der Client meldet `timeout`/`aborted` statt `bad-response`, wenn die Frist oder der Abbruch während des Lesens des 200-Körpers kommt; `scripts/fix-declarations.mjs` kam mit `%20`/`%7E` im Pfad nicht zurecht (`.pathname`, jetzt `fileURLToPath`).
  - Doku und `FEATURES_REQUIRED.md` mit dem Code abgeglichen (Client- und Beleg-Pfade ergänzt, Browser-Status 57 Prüfungen, `expectedPolicy` und `trust` als Zuordnung im Datenmodell, Warteschlange bei neu eingetragenem Schlüssel).
- Runde 2: der Client behält die erste Abbruchursache und wandelt nur einen Lesefehler des Körpers um (nicht ein echtes `bad-response`); `readServices` lehnt ein leeres `?` oder `#` ab; Windows-feste Tests (siehe 3).
- Ein Nachlauf-Audit der Änderungen und der bis dahin ungelesenen Dateien (`auth.ts`, `batch.ts`, `services.ts`) fand keine Lücke.

Der Auftrag verlangt, **nach jeder Runde Tobias zu fragen, ob eine weitere läuft**. Tobias hat Runde 2 bestätigt; eine Runde 3 ist nicht beauftragt.

## 2. Zuerst tun (in dieser Reihenfolge)

1. **Check „Tests“ auf `main` ansehen** (`gh run list --branch main --limit 3`). Er war vor dem Push der Audit-Commits rot, weil `docs/AUFTRAG_2026-11-27.md` nicht Prettier-formatiert war; das ist in den Audit-Commits behoben. Wenn der Lauf nach dem Push grün ist, ist die Ausgangslage sauber. Wenn nicht: Ursache zuerst, nichts anderes anfangen.
2. **Die Zeit-Tests auf Linux beurteilen.** Auf dem Windows-PC waren sie unter Dauerlast unzuverlässig (je Lauf andere rot, siehe 3). Linux in CI ist hier die Gegenprobe. Ein Test, der dort wiederholt rot ist, ist ein echter Befund; einer, der dort grün ist, ist nur auf Windows empfindlich.
3. **Ganze Suite lesen, nicht Zahlen übernehmen.** Vor jeder Aussage „grün“ `npm test` selbst vollständig laufen lassen und die echte Zusammenfassung samt Exitcode lesen (Workspace-Regel Test-Integrität). Die Zahlen aus diesem Blatt nicht weitergeben.

## 3. Bekannter Teststand (zuletzt auf dem Windows-PC, nicht grün)

- `typecheck`, `lint`, `format:check`, `build`: sauber.
- `npm test`: auf Windows zuletzt 9 rote Tests (Lauf davor 2, sequentiell sogar 13), jedes Mal **andere**; alle sind Tests gegen echte Zeit (Mindestabstände, Warteschlangen, Fensterketten, Leerlauf-Verbindungen) in `tests/solo*.test.ts`, `tests/single-*.test.ts`, `tests/key-share.test.ts`, `tests/audit9.test.ts`, `tests/relay-gaps2.test.ts`. Die CPU-Last des PCs lag bei 99 % durch einen fremden Prozess. Nicht bewiesen ist, dass es nur die Last war.
- Bereits Windows-fest gemacht: Dateiadresse für `--import`, Junction statt Symlink, Schrägstriche im openssl-Pfad, Exitcode nach SIGTERM nur unter POSIX geprüft, der 256-Leerlauf-Test (`tests/relay.test.ts`) unter Windows übersprungen.
- Fester Plan für die Zeit-Tests, falls sie auch in CI flackern: eine eingespritzte Uhr (das Relay nimmt `now` als Option, `relay/relay.ts`) statt echter Zeit; erst dann Toleranzen verbreitern, und jede Verbreiterung so, dass der alte Fehlerwert weiter fällt.

## 4. Nächste Schritte, nach Priorität

**A. Sofort (kein Beschluss nötig)**

1. Befunde mit Schweregrad niedrig, die noch offen sind: keine; alle bestätigten sind behoben. Offen sind nur die Beobachtungen unter B.
2. Regel „Jeder Fehler wird ein vorbeugender Test“: jeder neue Fehler bekommt zuerst einen Test, der auf dem alten Code rot ist.

**B. Beobachtungen, über die Tobias entscheidet (nicht von dir allein)**

1. `src/lib/der.ts` `time()`: ein GeneralizedTime-Bruchteil mit Endnull (`.50Z`) wird abgelehnt (DER-korrekt; in `docs/grenzen.md` schon genannt). Ein Dienst, der so schreibt, würde abgelehnt; die vier aufgezeichneten Dienste bestehen. Vorschlag: so lassen, bis ein echter Dienst so stempelt.
2. `src/lib/x509.ts` `readExtensions`: ein ausdrücklich geschriebenes `FALSE` bei `critical` wird angenommen (DER verbietet es). Bewusst nicht verschärft, weil echte Zertifikate so vorkommen können; kein Sicherheitseinfluss.
3. Der Client ist **nicht** Teil von `scripts/browser-check.mjs` (nur Bibliothek und Relay-Anmeldung). Vorschlag: einen Teil C für `zeitstempel/client` ergänzen (Stempeln gegen das Relay des Skripts, Beleg prüfen). Das ist die größte Lücke in der Browser-Prüfung.
4. Nicht auditiert wurden: echte TLS-Verbindung zum Dienst, die Proxy-Beispiele in `deploy/`, CPU-Last durch die synchrone ECDSA-Prüfung am Relay.

**C. Nicht tun ohne Tobias (hartes Verbot, steht auch in `CLAUDE.md`)**

- Nichts auf npm veröffentlichen, nichts taggen, nichts ausrollen oder deployen, kein Image veröffentlichen.
- Keinen qualifizierten Dienst vertraglich anbinden, keine Zugangsdaten in das Repo.
- Keine privaten Projektnamen im Repo (auch nicht in Commit-Texten; `tests/coupling.test.ts` prüft Dateien und Commit-Texte, nicht Branch-Namen und PR-Texte).
- Keine Befunde als „behoben“ melden ohne roten Test vorher und grünen danach.

**D. Offene Punkte aus dem Auftrag**

- Keine Prüfung auf Widerruf (Revocation), keine Name- und Pfad-Beschränkungen, keine Policy-Prüfung der Kette (`docs/grenzen.md`). Wenn beauftragt: erst Entwurf, nicht gleich bauen.
- Relay nicht ausgerollt, kein Image.
- Firefox und Safari ungeprüft: nur Tobias mit echtem Gerät.

## 5. Wie du arbeitest

- Kleine Agenten mit kleinen Aufgaben, der Haupt-Chat bleibt schlank: nur Ergebnisse und Entscheidungen.
- Reihenfolge je Runde: Audit, Widerlegung jedes Befundes gegen den Quellcode (nicht belegbare verwerfen), Behebung mit Regressionstest, Nachlauf-Audit, dann **Tobias fragen**.
- Deutsch im Chat, Berichte, Produkttexte und Doku; Code-Kommentare, Bezeichner und Commit-Texte englisch.
- Jede Verifikationsregel behält ihren Test; eine Regel wird gegen `openssl ts -verify` geprüft, wo es geht.
- Nach jeder strukturellen Änderung `CLAUDE.md` (Projektverzeichnis, Known Limitations) und, wenn sich das Modell ändert, `docs/data-model.html` im selben Schritt nachziehen (`tests/docs.test.ts` bindet Codes, Grenzen und Funktionen an den Code).

## 6. Was Tobias noch tun muss

- Dieses Projekt in der Liste der in die Cloud umgestellten Projekte im Workspace-`CLAUDE.md` eintragen (Abschnitt „Division of work“), damit die lokalen Sessions am PC hier keinen Code mehr ändern.
- Die beiden Audit-Commits pushen lassen (oder freigeben); ohne Push sieht die Cloud sie nicht.
