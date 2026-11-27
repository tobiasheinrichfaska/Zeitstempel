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
- Relay: Instanz A läuft zum Testen (Abschnitt E); für echten Betrieb fehlen Limit je Adresse, TLS-Zwang und Überwachung.
- Firefox und Safari ungeprüft: nur Tobias mit echtem Gerät.

**E. Relay auf Bunny Magic Containers (Entscheidung Tobias 2026-11-27: Instanz A zuerst, Instanz B später)**

Stand der Recherche (Bunny-Doku, nur oberflächlich gelesen, nicht ausprobiert):

- Magic Containers haben **persistente Volumes** (Name, Mount-Pfad, Größe; das Verzeichnis gehört `root`; Volumes sind regional, ohne Backup) und **Umgebungsvariablen** (per API setzbar, ein PUT ersetzt alle). Ein Feature, das eine Konfigurationsdatei oder ein Secret als Datei einhängt, wurde **nicht gefunden**. `RELAY_KEYS_FILE` verlangt aber eine Datei.
- Quellen: <https://docs.bunny.net/magic-containers/persistent-volumes>, <https://docs.bunny.net/magic-containers/environment-variables>.

**Entschieden und gebaut (2026-11-27):** `relay/container-start.ts` schreibt `RELAY_KEYS_JSON` in eine Datei und startet das Relay unverändert; ein Widerruf wirkt durch Neustart. Der Job „Image“ in `.github/workflows/tests.yml` baut, startet (`/health`) und legt von `main` aus `ghcr.io/<Konto>/zeitstempel-relay:<Commit>` ab. Anleitung: `docs/betrieb.md`, „Container-Dienst ohne Datei-Mount“.

**Stand 2026-11-27: Instanz A läuft zum Testen** (Image aus der CI, im Dashboard angelegt, ein echter Stempel mit OK). Erfahrungen: `docs/betrieb.md`, „Erfahrung mit Bunny Magic Containers“. Adresse, Kennungen und Werte der Instanz stehen nur im nicht öffentlichen Begleitrepo. Offen: TLS erzwingen, Limit je Adresse, Überwachung, Verbrauch, Browser-Aufruf mit `RELAY_ORIGINS`. Apps, die im Browser stempeln, brauchen eine `https`-Herkunft (eine aus der Datei geöffnete Seite kann nicht stempeln) und je Gerät einen eigenen Schlüssel in `RELAY_KEYS_JSON`.

Für den **ersten** Betrieb legt Tobias die App einmal im Dashboard an; ein Rollout-Skript ist erst danach nötig. Der **private** Schlüssel einer Instanz kommt in kein Repo (auch nicht ins nicht öffentliche Begleitrepo).

- **Ausrollen:** nicht über GitHub Actions (die Minuten des privaten Ausroll-Repos sind verbraucht), sondern von Tobias' PC aus mit einem Skript nach dem Vorbild der bestehenden PC-Rollouts; es setzt über die Bunny-API den neuen Image-Tag. Das Skript liegt auf dem PC außerhalb dieses Repos und wird erst nach Tobias' Ja angelegt. Der Bunny-API-Schlüssel gilt für das ganze Konto und liegt nur im DPAPI-Speicher auf dem PC; weder lesen noch ausgeben noch in ein öffentliches Repo oder einen öffentlichen Workflow legen.
- **Instanz A** (zuerst): ein Konto, eine Instanz, eine Region. `RELAY_SERVICES=freetsa`, eigene `RELAY_AUDIENCE`, eigene `RELAY_ORIGINS`, eigene Schlüssel. Danach der Erstlauf von Hand (`docs/betrieb.md`).
- **Instanz B** (später, anderes Konto): dasselbe Image, andere Konfiguration (eigene Audience, Herkünfte, Schlüssel, Pull-Zone). **Nicht anfangen**, bevor Tobias geklärt hat, ob freie, nicht qualifizierte Dienste mit ungeklärten Bedingungen für diesen Zweck überhaupt eingesetzt werden dürfen. Dieser Punkt gilt unabhängig von der Zahl der Instanzen.
- **Mehrere Apps an einem Relay** geht (mehrere Herkünfte, je App ein Schlüssel, `RELAY_KEY_SHARE=50`), ist aber für Apps mit Bezug zu Mandantendaten nicht vorgesehen.
- **TLS und Limit je Adresse:** TLS macht Bunny. Das Limit je Adresse (5 je Minute, Burst 3) kennt das Relay nicht; es müsste an der Pull-Zone entstehen. Ob und wie das bei Bunny geht, ist **nicht geprüft**. In `docs/betrieb.md` eine eigene Bunny-Fassung der Prüfliste schreiben, ehrlich mit „nicht geprüft“.
- **Dienstbudget:** FreeTSA zählt laut `docs/dienste.md` je IP. Teilen sich Magic Containers verschiedener Kunden eine ausgehende Adresse, kann FreeTSA ablehnen; ob das so ist, ist unbekannt. Mindestens einen zweiten Dienst in `RELAY_SERVICES` aufnehmen, damit der Client wechseln kann, oder eine feste ausgehende Adresse erfragen.
- **Zeit:** die Uhr des Containers lässt sich nicht prüfen oder steuern; das Relay verlangt einen laufend abgeglichenen Takt. Im Erstlauf `Date` im Antwortkopf mit der Gegenstelle vergleichen.
- **Was nicht ins öffentliche Repo darf:** Konten, Konto-Kennungen, Adressen, Betreiber- und Hosterangaben, Auftragsverarbeitung. Das gehört in das nicht öffentliche Begleitrepo. Im öffentlichen Repo nur „Instanz A/B“.

## 5. Wie du arbeitest

- Kleine Agenten mit kleinen Aufgaben, der Haupt-Chat bleibt schlank: nur Ergebnisse und Entscheidungen.
- Reihenfolge je Runde: Audit, Widerlegung jedes Befundes gegen den Quellcode (nicht belegbare verwerfen), Behebung mit Regressionstest, Nachlauf-Audit, dann **Tobias fragen**.
- Deutsch im Chat, Berichte, Produkttexte und Doku; Code-Kommentare, Bezeichner und Commit-Texte englisch.
- Jede Verifikationsregel behält ihren Test; eine Regel wird gegen `openssl ts -verify` geprüft, wo es geht.
- Nach jeder strukturellen Änderung `CLAUDE.md` (Projektverzeichnis, Known Limitations) und, wenn sich das Modell ändert, `docs/data-model.html` im selben Schritt nachziehen (`tests/docs.test.ts` bindet Codes, Grenzen und Funktionen an den Code).

## 6. Was Tobias noch tun muss

- Dieses Projekt in der Liste der in die Cloud umgestellten Projekte im Workspace-`CLAUDE.md` eintragen (Abschnitt „Division of work“), damit die lokalen Sessions am PC hier keinen Code mehr ändern.

- Zu E: die Herkünfte der ersten App nennen; später (optional) das PC-Rollout-Skript freigeben und den Bunny-Schlüssel selbst ablegen.
- Die Frage klären lassen, ob freie, nicht qualifizierte Dienste für Instanz B zulässig sind (rechtlich, nicht technisch).
