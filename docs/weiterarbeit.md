# Weiterarbeit: Stand, Arbeitsweise, Roadmap (Übergabe für eine neue Sitzung)

Stand: 2026-11-27, Entwicklungszweig `claude/confident-cori-19i12m`, letzter Stand `2cac700`. Nichts ist veröffentlicht,
getaggt oder ausgerollt (das entscheidet nur Tobias). Die Regeln, Grenzen und Entscheidungen des Codes stehen in
`CLAUDE.md` (Abschnitt „Known Limitations“, ein Bullet je Welle/Audit); dieses Dokument sagt, **wie weitergearbeitet wird**
und **was offen ist**. Geschäftliches (Anbieter, Kosten, Verträge, Pilot) steht im Begleitrepo, nicht hier.

## 1. Zustand in Zahlen

- Prüfungen: `npm run typecheck`, `npm run lint`, `npm run format:check`, `npm test` (74 Dateien, 2249 bestanden, 2 sichtbar
  übersprungen), `npm run build`. Alles grün ist die Bedingung für jeden Commit.
- Browser: `node scripts/browser-check.mjs` (nach `npm run build`, Chromium + Playwright sind vorinstalliert): 87 Prüfungen
  (A und B: Bibliothek und Relay-Anmeldung, C: Client), rund 80 s, Exitcode 0/1/2. Firefox und Safari nie gelaufen. Der
  CI-Job `browser` ist nur statisch geprüft, auf GitHub noch nie gelaufen.
- Kein Netz in der Sitzung: echte Dienste (`npm run spike`, `scripts/probe.ts`) sind nie aus der Sitzung gelaufen, nur gegen
  Stubs und aufgezeichnete Antworten (`tests/fixtures/`).
- Node 24 liegt unter `/opt/node24/bin` (`export PATH=/opt/node24/bin:$PATH`), OpenSSL 3.0.13 ist da.

## 2. Arbeitsweise (so wurde gearbeitet, so weitermachen)

Mandat von Tobias: offene Schleife **Audit → Widerlegung → Behebung → Neu-Audit**, agentenbasiert, kleine Pakete für
kleine Agenten (Sonnet für Audit und Behebung, Haiku für Widerlegung und Doku, Opus/Fable nur für große Audits). Die frühere
„Zwangspause“ (30 Läufe, 05:00 Uhr) ist abgelöst.

Regeln für den Hauptagenten:

1. **Selbst prüfen.** Berichte von Agenten sind Aussagen, keine Belege: nach jeder Behebung selbst die volle Suite laufen
   lassen (siehe 1), erst dann committen und pushen. Ist der Stand halbfertig oder rot, nicht committen (der Stop-Hook
   meldet ungesicherte Änderungen: dann warten oder erst die Suite laufen lassen).
2. **Widerlegung = erst ein fehlschlagender Test.** Jeder Befund wird mit einem Test nachgestellt, der vor der Behebung rot
   ist; lässt er sich nicht nachstellen, wird nichts geändert und das gemeldet. Neue Tests werden gegen den Mutanten geprüft
   (Mutation einbauen, Test muss rot werden, Mutation zurücknehmen).
3. **Agenten committen nicht** (Ausnahme: arbeitet nur EIN Agent zur Zeit, committet er lokal, einzeln mit `git add <Datei>`, ohne Push; der Hauptagent prüft selbst und pusht) und ändern `CLAUDE.md` nicht; sie liefern einen Satzvorschlag, der Hauptagent trägt ihn ein
   (ganze Zeilen/neue Bullets, knapp). Nach jedem Block: `npx prettier --write CLAUDE.md` (Prettier bricht die Tabelle neu
   um, das ergibt große, aber harmlose Diffs).
4. **Audits sind nur lesend** und arbeiten in einer Kopie (`cp -r` ohne `.git`, `node_modules` per Symlink) unter dem
   Scratchpad. Ein Audit liefert: Befunde nach Schwere mit Nachstell-Skript, Mutationsbilanz (mindestens 25 Mutanten),
   Differenztest alt gegen neu bei Umbauten, Doku gegen Code, Flackerprüfung.
5. **Parallel nur mit getrennten Dateimengen.** Das Agent-Werkzeug mit `isolation: "worktree"` scheitert, wenn das
   Arbeitsverzeichnis der Sitzung kein Git-Repo ist: dann Worktrees von Hand anlegen
   (`git worktree add -b agent-x /home/user/wt/x HEAD`, `ln -s …/node_modules`), im Worktree nie `git add -A`
   (der Symlink), danach zusammenführen, Worktree und Branch löschen.
6. Commit-Text englisch, Endzeilen laut Sitzung (`Co-Authored-By`, `Claude-Session`); keine privaten Projektnamen, keine
   Kosten, kein Hosting in diesem Repo (`tests/coupling.test.ts` prüft Dateien und Commit-Texte).
7. Nichts wird veröffentlicht, getaggt, ausgerollt oder deployed ohne Tobias.

## 3. Stolpersteine

- Die Relay-Logik ist in Module aufgeteilt (`relay/relay.ts`, `types`, `body`, `auth-head`, `budgets`, `identities`,
  `obtain`, `planner`, `flush`). Tests, die Dokumente an den Code koppeln, lesen sie über `tests/relay-source.ts`
  (`relaySource()`); ein neues Modul mit Regeln muss in `PARTS` stehen (`tests/relay-parts.test.ts` prüft das).
- `tests/docs.test.ts` verbietet im Relay-Quelltext den Bezeichner `lastCallMono`; Fehlercodes und Limits sind an
  `docs/relay.md`, `docs/data-model.html` und `docs/grenzen.md` gekoppelt (neuer Code ohne Doku ist rot).
- Einstellungen: jede `RELAY_*`-Einstellung steht in `deploy/relay.env.example` und umgekehrt
  (`tests/ops-templates.test.ts`); `.gitignore` schließt `*.env` aus, nicht `relay.env.example`.
- `src/lib` und `src/client` dürfen kein `fetch` (außer Client), `node:`, `Buffer`, `process`; auch das Wort „fetch“ in einem
  Kommentar der Bibliothek macht `tests/client-package.test.ts` rot.
- Einige Relay-Tests sind unter hoher CPU-Last empfindlich (`relay.test.ts` „Client liest nie“, zwei Fälle in
  `audit9.test.ts`); im Leerlauf sind sie grün. Nicht mehrere schwere Läufe gleichzeitig starten, wenn die Suite rot wird.
- Der Stop-Hook verlangt „commit and push“; das gilt nur für grünen Stand.

## 4. Audit-Verlauf (Kurzfassung; Befunde stehen in den CLAUDE.md-Bullets)

Audit 8 (Relay: wartende Anfragen, Rückgaben, Replay-Cache; Client) → Audit 9 (Freigaben, `services`/Solo bei Wartenden) →
Audit 10 (Kennung mit anderem öffentlichen Schlüssel) → Paket A/B/C (`/metrics`, Offline-CRL, Client im Browser) →
Audit 11 (CRL) und 12 (`/metrics`) → `relay.gauges()` und Aufteilung von `relay.ts` → Audit 13 (verhaltensneutral:
3500 Differenzläufe, 896 Startfehlerkombinationen) → Einzelbetrieb-Zähler monoton, Name Constraints (Audit 14: 600 Zufallskonstellationen
gegen OpenSSL), Erneuerungskette (Audit 15), RFC-4998-Record (Audit 16). Keine offenen Befunde; bekannte dokumentierte Lücken:
Name Constraints N4 (Kette endet am ersten Anker), `crls` je Glied nur zur Prüfzeit des Glieds. Die Berichte selbst lagen im Scratchpad der
Sitzung und sind **nicht** gesichert; was dauerhaft zählt, steht in `CLAUDE.md`, `docs/grenzen.md` und den Tests.

## 5. Offene Technik (Reihenfolge nach Nutzen)

1. **Echte Dienste** prüfen (`npm run spike`, `scripts/probe.ts`, `manual_tests/`): braucht Netz, also Tobias oder eine
   Umgebung mit Netz. Danach ggf. neue Fixtures.
2. **CI-Browserjob** einmal auf GitHub laufen lassen; GitHub-Actions per SHA pinnen (offline nicht prüfbar).
3. **Erneuerungskette und Evidence Record, Rest:** Der RFC-4998-Export steht (`exportEvidenceRecord`, `readEvidenceRecord`, `verifyEvidenceRecord`,
   `serializeEvidenceRecord`; `docs/client.md` „ERS-Export“): eine Kette, SHA-256, Einzelstempel; die Bindung der Erneuerung wurde dafür auf RFC 4998
   Abschnitt 5.2 umgestellt. Offen: der Export mit einem **fremden** ERS-Werkzeug (Bouncy Castle, `ers-tools`) gegenprüfen; Sammelbetrieb-Belege sind
   `export-unsupported` (anderer Baum, `docs/client.md`), Hash-Erneuerung und `reducedHashtree` beim Lesen `ers-unsupported`; Browser-Check
   `scripts/browser-check.mjs` um `renew` und den Export erweitern, ein echter Dienst, und der Umgang mit Sperrlisten über mehrere Glieder
   (`docs/client.md` „Ehrliche Grenzen“).
4. **Weitere Sperrprüfung**: `crls` bis in `stamp`/Relay durchreichen? (heute bewusst nicht, `docs/grenzen.md` Punkt 16),
   Brainpool/Ed25519.
5. **Planer**: ein gemeinsamer Planer für beide Betriebsarten (Differenztest-Treiber aus Audit 13 wiederverwenden: alte gegen
   neue Fassung, virtuelle Uhren). Die Mengenzähler des Einzelbetriebs laufen seit 2026-11-27 auf der monotonen Uhr
   (Test-Parameter `countersNow`); offen bleibt, sie an den Aufruf statt an die Annahme zu binden (`docs/relay.md`).
6. **Mehr Browser**: Firefox, Safari (Teil C erweitern); Client mit `upstream`-Zugangsdaten im Browser.
7. **Betriebsvorlagen** gegen echtes nginx, Caddy und Docker prüfen (heute nur statisch), Basis-Image-Digest setzen,
   Gesamtlauf mit echtem Proxy (Adressgrenzen, `/metrics`-Sperre).
8. **Abdeckungsbericht** (Paketinstallation war nicht möglich) und eine **menschliche Sicherheitsprüfung** (Status in
   `CLAUDE.md`: „not security-reviewed by a human“).

## 6. So startet eine neue Sitzung

1. `git log --oneline | head`, `git status`, volle Prüfung aus Abschnitt 1 (alles muss grün sein).
2. `CLAUDE.md` lesen (besonders die Bullets zu Relay, Planer, Audit 8/9, Metrics, CRL), dann dieses Dokument.
3. Mit Tobias den nächsten Block aus Abschnitt 5 oder aus dem Begleitrepo (`docs/stand.md`) wählen; Audit-Schleife nach
   Abschnitt 2.
