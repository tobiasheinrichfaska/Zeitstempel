# Betrieb des Relays (Pilot)

Vorlagen und Ablauf für **einen** Relay-Betrieb: eine Instanz, nur FreeTSA, Einzelbetrieb (ohne `RELAY_BATCH_MS`).
Die Einstellungen und Grenzen stehen in [`relay.md`](relay.md); dieses Dokument sagt, was ein Betreiber darum herum
einrichtet und beobachtet. Es enthält keine Kosten-, Vertrags- oder Hosterangaben.

**Stand und Ehrlichkeit:** Die Vorlagen unter `deploy/` sind **nur statisch geprüft** (`tests/ops-templates.test.ts` liest
sie und gleicht sie mit dem Code ab). Sie wurden **nicht** gebaut oder gestartet: kein Docker-Daemon, kein nginx, kein
Caddy in der Umgebung, in der sie entstanden. Einzige Ausnahme: `systemd-analyze verify` kannte die Unit (es meldete nur
den fehlenden Knotenpfad dieser Umgebung). Der erste echte Lauf ist Teil der Prüfliste unten. Das Relay ist nicht von
einem Menschen sicherheitsgeprüft (`SECURITY.md`).

| Datei                              | Zweck                                                                           |
| ---------------------------------- | ------------------------------------------------------------------------------- |
| `deploy/Dockerfile`                | Image auf `node:24`-Basis, Nicht-Root, Healthcheck, Exec-Form, ohne Geheimnisse |
| `deploy/Dockerfile.dockerignore`   | Ignorierliste zum Dockerfile (BuildKit nimmt sie neben der Datei)               |
| `deploy/zeitstempel-relay.service` | systemd-Unit mit Härtung, `Restart=always`                                      |
| `deploy/relay.env.example`         | Alle Einstellungen mit Platzhaltern                                             |
| `deploy/nginx.conf.example`        | nginx: TLS, Limit je Adresse nur auf `/v1/stamp/`, Fristen                      |
| `deploy/Caddyfile.example`         | Caddy: dasselbe, Ratenlimit nur als Gerüst (Zusatzmodul)                        |

## Pilot-Prüfliste

Voraussetzungen, vor dem ersten echten Stempel:

- [ ] **Genau eine Instanz** je Schlüsseldatei. Zwei Instanzen verdoppeln die Budgets und lassen einen mitgeschnittenen
      Kopf zweimal gelten (`relay.md`, „Betrieb hinter einem Reverse-Proxy“). Kein zweites Relay „zur Sicherheit“,
      kein Rolling-Update mit zwei laufenden Instanzen.
- [ ] **Zeitabgleich mit Slew.** Die Uhr des Rechners wird laufend abgeglichen (chrony oder systemd-timesyncd) und
      **läuft nicht sprunghaft**: nach dem Start nur sanftes Angleichen (bei chrony `makestep` nur für die ersten
      Messungen, nicht dauerhaft). Das Relay prüft ±60 s Zeitfenster und `genTime` ±60 s und merkt sich die Startzeit;
      ein Sprung der Uhr schwächt den Schutz vor dem Abspielen alter Köpfe (`relay.md`, „Zugangsschlüssel“, Grenzen a bis c).
      Die systemd-Unit startet nach `time-sync.target`; das gibt es nur, wenn der Zeitdienst es mitbringt. Prüfen:
      `timedatectl status` zeigt `System clock synchronized: yes`.
- [ ] **Proxy mit TLS und Limit je Adresse** (`deploy/nginx.conf.example` oder `deploy/Caddyfile.example`): TLS,
      Limit **nur** auf `/v1/stamp/` (5 je Minute je Adresse, Burst 3), Verbindungsgrenze, Lese-Frist 50 s im
      Einzelbetrieb (`RELAY_MAX_WAIT_MS` 30000 + 17 s + 3 s Reserve). Das Relay kennt keine Adressen: ohne diesen
      Proxy gibt es kein Limit je Adresse. Bei Caddy braucht das Limit ein Zusatzmodul, ohne es ist die Einrichtung unvollständig.
- [ ] **Relay nur hinter dem Proxy erreichbar.** Systemd: `RELAY_HOST=127.0.0.1` (Vorgabe). Container:
      `RELAY_HOST=0.0.0.0` im Container, der Port aber nur auf der Loopback-Adresse des Hosts veröffentlicht
      (`-p 127.0.0.1:8080:8080`). Von außen darf nur der Proxy-Port offen sein.
- [ ] **Schlüsseldatei lokal, nur der Betreiber darf sie schreiben.** Ort `/etc/zeitstempel/relay-keys.json`, Besitzer
      `root`, Modus `0640`, Gruppe des Relay-Benutzers; das Verzeichnis ebenso nicht für andere schreibbar. Sie enthält
      nur öffentliche Schlüssel, aber wer sie schreiben kann, kann einen eigenen Schlüssel eintragen und stempeln.
      Nie im Repository (die `.gitignore` hält `*keys*.json` heraus). Der Start warnt (`keyFileWritable`), wenn Gruppe
      oder Andere schreiben können: Warnung ernst nehmen, nicht übergehen.
- [ ] **Überwacher** (systemd oder Docker mit Neustartrichtlinie) startet das Relay auch nach Exit-Code 0 neu
      (`Restart=always`, Docker `--restart=always`). Sonst bleibt das Relay nach `restartAfter` aus.
- [ ] **Einstellungen:** `RELAY_SERVICES=freetsa`, `RELAY_KEYS_FILE`, `RELAY_ORIGINS` (genau die Herkunft der App),
      `RELAY_AUTH` nicht gesetzt, `RELAY_ALLOW_PLAIN_HTTP` nicht gesetzt (siehe `deploy/relay.env.example`).
- [ ] **Beobachtung** der Zähler und Alarmkriterien (unten) eingerichtet.
- [ ] **Der erste Lauf von Hand gegen FreeTSA** hat geklappt (nächster Abschnitt).

### Erstlauf von Hand

Vor dem Einrichten des Proxys, an einem Rechner mit Netz (die freien Dienste freundlich behandeln: höchstens eine
Anfrage je Dienst und Lauf, zwischen zwei Läufen mindestens eine Minute):

1. `npm install`, dann `npm run spike`: alle Dienste antworten, eigene Prüfung und OpenSSL stimmen überein
   (`manual_tests/01_dienste.md`, MT-01). Für den Pilot zählt die Zeile `freetsa`.
2. `npm run probe -- --service freetsa`: ein Stempel über ein Relay im selben Prozess, Zeile `freetsa: HTTP 200 …,
own verification of the returned token: OK` (MT-02).
3. Das Relay selbst starten (systemd oder Docker), `GET /health` über den Proxy abrufen (es prüft **keinen** Dienst,
   nur dass das Relay antwortet), dann mit einem Schlüssel der App **einen** Stempel holen
   (`npm run probe -- --service freetsa --relay https://relay.example`, `RELAY_PRIVATE_KEY` und `RELAY_KEY_ID` nur in der
   Umgebung, nie auf der Kommandozeile; `manual_tests/01_dienste.md`, MT-02 und MT-03).
4. In der nächsten Zeile `counts` im Protokoll stehen `stamped` ≥ 1 und kein `upstream-invalid`.

## Einrichtung in Kürze

**systemd:** Schritte im Kopf von `deploy/zeitstempel-relay.service`. Die Unit läuft als eigener Benutzer, mit
`ProtectSystem=strict`, `NoNewPrivileges=true`, nur lesbarem Programm- und Schlüsselpfad, `LimitNOFILE=4096` (höchstens
256 offene Verbindungen) und `TimeoutStopSec=15`. Letzteres ist größer als `shutdownHardMs` (10 s, `relay/limits.ts`):
das Relay beendet sich bei `SIGTERM` selbst, spätestens nach 10 s; erst danach darf `SIGKILL` kommen. Ändert sich
`shutdownHardMs`, ändert sich die Zahl in der Unit mit (ein Test hält beide zusammen).

**Docker:** Befehle im Kopf von `deploy/Dockerfile`. Das Image enthält nur `package.json`, `services.json`, `anchors/`,
`src/` und `relay/` (das Relay läuft ungebaut mit dem Type-Stripping von Node 24; es gibt keine Abhängigkeit zur
Laufzeit, also kein `npm install` im Image). Der Basis-Tag ist fest benannt, ein Digest ist **nicht** eingetragen: beim
ersten Bau den Digest des Tags nachsehen und festschreiben. Die Schlüsseldatei kommt als **Verzeichnis-Mount, nur lesbar**
(`-v /etc/zeitstempel:/etc/zeitstempel:ro`), nicht als Einzeldatei: eine atomar ersetzte Datei (neue Datei schreiben,
umbenennen) würde im Container bei einem Einzeldatei-Mount die alte bleiben. Zum Anhalten `docker stop -t 15`, damit
das Relay seine 10 s zum Beenden hat. Der Container läuft als Benutzer 10001; die Schlüsseldatei muss für ihn lesbar sein
(Gruppe 10001 oder Modus `0644`, nie für andere schreibbar).

## Zähler beobachten

Alle fünf Minuten schreibt das Relay eine Zeile `{"event":"counts",…}` ins Protokoll (stdout; systemd: `journalctl -u
zeitstempel-relay`; Docker: `docker logs`). Es sind **nur Summen**; Zähler erscheinen erst, wenn sie zum ersten Mal
zählen. Die Fehlerarten stehen unter `refused`. Bedeutung: `relay.md`, „Zähler“ und „Budgets und Zähler“.

| Zähler                                 | Normalwert             | Alarmkriterium                                                                                                                                                                                                        |
| -------------------------------------- | ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `refused.upstream-invalid`             | fehlt (0)              | **Jeder Anstieg.** Der Dienst liefert Token, die das Relay nicht annimmt: neue Zertifikatskette, veraltete Anker in `anchors/`, Uhr, ein Betrug auf der Strecke oder eine Schaltsekunde. Warnung, nicht nur eine Zahl |
| `refused.upstream-too-old`             | fehlt (0)              | **Jeder Anstieg:** rückdatierte Token (`genTime` außerhalb ±60 s)                                                                                                                                                     |
| `keyReloadFailed`                      | fehlt (0)              | **Jeder Anstieg:** die Schlüsseldatei ist ungültig, halb geschrieben oder verschwunden; der alte Satz bleibt aktiv, ein neuer oder entfernter Schlüssel wirkt **nicht**. Datei sofort prüfen                          |
| `keyFileWritable`                      | fehlt (0)              | **Jeder Anstieg:** die Datei ist für Gruppe oder Andere schreibbar. Rechte korrigieren, die Datei auf fremde Einträge prüfen                                                                                          |
| `refused.unauthorized`                 | klein                  | Dauerhaft hoch oder sprunghaft: Raten von Schlüsseln, falsche Uhr der App (±60 s, die Antwort trägt `Date`), ein Angriff auf die Anmeldung                                                                            |
| `refused.rate-limited`, `refused.busy` | selten                 | Dauerhaft: das Dienstbudget (FreeTSA: 12 je Minute für alle Besucher) reicht nicht oder ein Besucher füllt es; Proxy-Limit und App prüfen                                                                             |
| `stamped`                              | steigt mit der Nutzung | Bleibt 0 trotz Nutzung, oder `refused.upstream-failed` steigt: der Dienst ist nicht erreichbar                                                                                                                        |

Zusätzlich von außen: `GET /health` (über den Proxy) alle 30 bis 60 s. **`/health` prüft keinen Dienst**: es meldet
„gesund“, auch wenn FreeTSA ausfällt. Wer das wissen will, wertet `stamped` und `refused.upstream-failed` aus oder holt
selten einen Probestempel mit einem eigenen Schlüssel (nie öfter als das Dienstbudget erlaubt). Die Zahlen beginnen nach
jedem Neustart bei 0 (auch nach `restartAfter`); wer Anstiege auswertet, vergleicht innerhalb eines Prozesses.

## Schlüsselrotation

Das Relay liest die Schlüsseldatei alle 5 s neu und vergleicht den Inhalt (SHA-256), nicht die Änderungszeit
(`relay.md`, „Schlüsseldatei laufend lesen“). Ein neuer Schlüssel gilt ab dem Übernehmen, ein entfernter ist ab dann
sofort ungültig. **Kein Neustart nötig.** Eine ungültige Datei lässt den alten Satz aktiv (`keyReloadFailed`).

1. Neues Schlüsselpaar erzeugen (am Rechner des App-Betreibers, nicht auf dem Relay): `node scripts/make-key.ts <neue-kennung>`.
   Zeile 1 ist der **private** Schlüssel (gehört nur der App, nie in eine Datei neben dem Relay, nie ins Repository),
   Zeile 2 der Eintrag für die Schlüsseldatei. Kennung `[a-z][a-z0-9-]{0,31}`, **neu** (nicht die alte weiterverwenden).
2. Den Eintrag **zusätzlich** in die Schlüsseldatei schreiben (neue Datei schreiben, dann umbenennen, nie an Ort und
   Stelle bearbeiten, damit nie eine halbe Datei gelesen wird). Warten, bis das Relay sie gelesen hat (höchstens
   5 s), in der nächsten Zeile `counts` steht `keyReloads` um 1 höher und `keyReloadFailed` fehlt weiter.
3. Die **App umstellen** (neuer privater Schlüssel, neue Kennung) und ausrollen. Mit der App einen Stempel holen und
   prüfen, dass er ankommt. Alte und neue Kennung gelten in dieser Zeit nebeneinander.
4. Wenn keine App mehr den alten Schlüssel nutzt, den **alten Eintrag entfernen** (wieder atomar). Ab dem nächsten Lesen
   sind Anfragen mit der alten Kennung `401`.

## Notfall: ein Schlüssel wurde ausgelesen

Ein privater Schlüssel in einer Web-App ist für die Besucher der Seite lesbar (`relay.md`, „Zugangsschlüssel“): das
ist eine bekannte Grenze, keine Überraschung. Wurde er missbraucht oder verbreitet:

1. **Eintrag aus der Schlüsseldatei entfernen** (atomar ersetzen). Spätestens 5 s nach dem Speichern ist der Schlüssel
   ungültig; alle ehrlichen Besucher der App sind dann ebenfalls ausgesperrt, bis die App einen neuen Schlüssel hat.
2. Vorher oder gleichzeitig ein **neues Paar** erzeugen und die App darauf umstellen (Abschnitt Schlüsselrotation, Schritte 1 bis 3,
   mit gleichzeitigem Entfernen des alten Eintrags). Der neue Schlüssel steht in der Datei, bevor der alte verschwindet,
   wenn die Unterbrechung klein bleiben soll.
3. Wer den Schlüssel gesehen hat, kann bis zum Entfernen Stempel aus dem Budget der App ziehen; das Limit je Adresse am
   Proxy begrenzt den Schaden je Besucher (`relay.md`, „Betrieb hinter einem Reverse-Proxy“).
4. Gelöst ist nur dieser Schlüssel; wer die Datei schreiben konnte, kann weitere Einträge gemacht haben: Datei Zeile für
   Zeile prüfen, Besitzer und Rechte prüfen.

> **Wird mit der Schlüsseldatei v3 ergänzt.** Heute gilt: Ein Eintrag wird **entfernt**. **Die Liste vollständig zu
> leeren wirkt heute nicht** (die Datei mit leerer Liste gilt als ungültig, der alte Satz bleibt aktiv:
> `keyReloadFailed`). Mindestens ein anderer, gültiger Eintrag muss in der Datei bleiben; will man alle sperren, ersetzt
> man sie durch einen frischen Schlüssel, dessen privaten Teil niemand hat, oder hält das Relay an. Eine spätere
> Fassung der Schlüsseldatei (Sperrkennung `revoked`) ändert das; bis dahin gilt dieser Abschnitt nur in der
> beschriebenen Form.

## Neustart mit `restartAfter`

Die Schlüsseldatei darf auf oberster Ebene `"restartAfter": <Unix-Sekunden>` tragen (1000000000 bis 99999999999).
Liegt dieser Zeitpunkt nach dem Start des Prozesses und ist er erreicht, beendet sich das Relay **einmal** sauber:
Zeile `{"event":"restart-after"}`, Wartende bekommen `503 shutting-down`, **Exit-Code 0** (nach höchstens 10 s). Der
Überwacher startet es neu (`Restart=always`; `on-failure` würde es nach Exit 0 **nicht** neu starten). Der neue Prozess
startet nach `restartAfter` und beendet sich nicht erneut, auch wenn die Datei unverändert bleibt.

Wofür: ein Neustart nach einer Änderung der Einstellungen (`relay.env`), ohne dass der Betreiber zum Rechner muss. Für
Schlüssel ist er **nicht** nötig (das laufende Neulesen ist der Normalweg). Ein Neustart leert den Wiederholungsschutz
(Lücke bis zu 120 s) und die Zähler: nicht in Spitzenzeiten.

## Backup

Gesichert wird **nur die Schlüsseldatei** (und `relay.env`, ohne Zugangsdaten zu bezahlten Diensten im Klartext in
ein ungeschütztes Backup zu legen). Das Relay hält sonst **keine Daten**: keine Datenbank, keine Datei, die es
schreibt; Zähler, Wiederholungsspeicher und Budgets liegen nur im Speicher. Die privaten Schlüssel der Apps liegen
nicht beim Relay und gehören nicht in dieses Backup. Der Wiederaufbau ist: Repository holen (oder Image bauen),
`relay.env` und Schlüsseldatei einspielen, starten.

## Protokoll

Das Relay protokolliert **nichts, was eine Anfrage trägt**: keine Adresse, keinen Hash, kein Token, keine Kennung,
keine Signatur. Im Protokoll stehen die Startzeile (`"auth":"on"`, Dienste), die Zeile `counts` alle fünf Minuten,
Warnungen (Schlüsseldatei schreibbar oder ungültig beim Neulesen, ohne Inhalt) und `restart-after`. Der Betreiber darf
das nicht aufweichen: keine Zugriffsprotokolle des Proxys mit Adresse und Pfad länger als nötig aufbewahren (der Proxy
sieht Adresse und Zeit jeder Anfrage; das ist Sache des Betreibers, `relay.md`, „Was das Relay sieht“). Logs rotieren
(`journald` begrenzt von selbst, bei Docker `--log-opt max-size=10m --log-opt max-file=3`).

## Update

1. Vorher beachten: **Relay- und App-Stand gehören zusammen** (Kopfform `v2`, Kennungen der Dienste
   in `services.json`, Anker, Regeln der Prüfung). Eine App mit alten Ankern meldet `untrusted-chain`, ein Relay mit
   alten Ankern `upstream-invalid`.
2. Repository auf den gewünschten Stand bringen (oder Image neu bauen, mit neuem Tag; den alten Tag für den Rückweg behalten).
3. Tests laufen lassen (`npm test`) und, wenn möglich, den Erstlauf (oben) gegen FreeTSA wiederholen.
4. Neu starten: `systemctl restart zeitstempel-relay` beziehungsweise Container ersetzen. **Nie zwei Instanzen gleichzeitig**
   (erst die alte anhalten, dann die neue starten); eine kurze Unterbrechung ist hier der Preis, die App wiederholt
   einmal nach einer Pause.
5. In der nächsten Zeile `counts` prüfen: `stamped` steigt, kein `upstream-invalid`.
6. Rückweg: alten Stand starten (Tag oder `git checkout`). Die Schlüsseldatei bleibt unverändert.

## Was nicht zugesagt ist

- **Keine Verfügbarkeit.** Das Relay hängt von FreeTSA ab (freier Dienst, keine Zusage des Betreibers, 12 Anfragen je
  Minute für alle Besucher zusammen, `docs/dienste.md`) und von einem einzelnen Rechner ohne Ausfallsicherheit. Die
  App muss ohne Stempel arbeiten können und später nachstempeln.
- **Kein qualifizierter Stempel.** Die freien Dienste sind nicht qualifiziert im Sinn von eIDAS; ein Stempel belegt
  „dieser Hash bestand spätestens zur Zeit T“ mit begrenztem rechtlichem Gewicht (`docs/grenzen.md`).
- **Keine Sicherheitsprüfung durch einen Menschen**, keine Widerrufsprüfung der Zertifikate, kein Schutz vor einem
  ausgelesenen Schlüssel außer dem Sperren durch Entfernen (`SECURITY.md`, `docs/grenzen.md`).
- **Nicht veröffentlicht, nicht getaggt:** kein Paket auf npm, kein veröffentlichtes Image; Bau und Betrieb liegen
  beim Betreiber, und ohne Zustimmung des Projektinhabers wird nichts ausgerollt.
