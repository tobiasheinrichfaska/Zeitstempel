# Recherchestand (2026-11-24)

Dieses Dokument hält fest, was bei der Weiterentwicklung geklärt wurde, womit belegt und mit welcher Sicherheit. Es ist
**keine Rechtsberatung** und keine Zusage von Betreibern. Kennzeichnung: **gemessen** (selbst ausgeführt),
**Quelle** (öffentliche Seite gelesen), **Schätzung** (gerechnet, nicht gemessen), **Annahme**.

## 1. Zeitstempel-Dienste: Antwortzeit, Grenzen

- **Antwortzeit (gemessen, 2026-11-24, eine Anfrage je Dienst mit dem Hash eines kurzen Testtexts, `npm run spike`):**
  FreeTSA 308 ms, Sectigo 290 ms, DigiCert 104 ms (http), Certum 451 ms (http). Am 2026-11-23 waren es 697, 206, 398 und
  220 ms. Einzelmessungen aus einer Cloud-Umgebung, keine Statistik. Für den Nutzer dauert ein Stempel insgesamt etwa
  0,3 bis 1 s.
- **Grenzen der Dienste (Quelle, `docs/dienste.md`):** FreeTSA erlaubt „a maximum of one timestamping request per second
  per IP address“, auch kommerziell, ohne Zusage („best effort“). Sectigo bittet um 15 s Pause bei Skripten. DigiCert
  und Certum nennen keine Grenzen; bei Certum ist ein Vertrag wahrscheinlich nötig. Alle vier sind nicht qualifiziert.
- **Heutige Konfiguration:** `minIntervalMs` 15 000 je Dienst, also 4 Stempel pro Minute je Dienst für alle Nutzer
  zusammen (die Annahme 15 s ist vorsichtig, belegt ist bei FreeTSA 1 pro Sekunde). Ein Schlüssel kann mit 4 Anfragen
  pro Minute einen Dienst für alle sperren.

## 2. Datenverkehr und Kosten bei Bunny

- **Preise (Quelle, abgerufen 2026-11-24):** Datenverkehr (Egress) Europa und Nordamerika 0,01 $/GB, Asien und Ozeanien
  0,03 $, Südamerika 0,045 $, Naher Osten und Afrika 0,06 $; bei Magic Containers und beim CDN-Standard-Tarif gleich
  (<https://bunny.net/docs/magic-containers/pricing>, <https://bunny.net/docs/cdn/pricing>). Magic Containers: CPU 0,02 $
  je CPU-Stunde verbrauchter CPU-Zeit, RAM 0,005 $ je GB-Stunde in 64-MB-Blöcken plus variablem Systemaufschlag,
  Anycast-IPv4 2 $ im Monat. Zu Ingress, Freikontingenten und Monatsminimum steht auf diesen Seiten nichts.
- **Annahmen:** Volllast heißt 60 angenommene Anfragen pro Minute rund um die Uhr (`perMinuteTotal`), also 86 400 pro
  Tag und 2,59 Mio. in 30 Tagen. Antwort je Anfrage: Token base64url 6,2 KB (FreeTSA) bis 8,8 KB (Sectigo) laut
  Fixtures, dazu etwa 0,25 KB JSON und 0,45 KB Header, im Sammelbetrieb etwa 0,4 KB für den Beleg, dazu Preflight
  (OPTIONS) mit etwa 0,45 KB, wenn er nicht zwischengespeichert wird.
- **Ergebnis (Schätzung):** nur FreeTSA, Einzelstempel: etwa 17,9 GB im Monat, 0,18 $. Nur FreeTSA, Sammelbetrieb mit
  Preflight: etwa 20,1 GB, 0,20 $. Schlechtester Fall (Sectigo-große Token): etwa 26,8 GB, 0,27 $. Bei 600 pro Minute etwa
  2 $, bei 6 000 pro Minute etwa 20 $. Alles bei Verkehr aus Europa und Nordamerika; aus der teuersten Region das
  Sechsfache.
- **Eingehender Verkehr:** etwa 1 KB je Anfrage, rund 2,6 GB im Monat; ob Bunny ihn berechnet, steht auf den Seiten nicht.
- **Angriffsverkehr ist die eigentliche Kostenfrage:** abgelehnte Antworten (401, 429) sind etwa 0,45 KB. Ein Flood mit
  1 000 Anfragen pro Sekunde wären etwa 1,2 TB und etwa 12 $ im Monat. Ratenbegrenzung pro Adresse vor dem Relay ist
  Pflicht.
- **Container (Schätzung, nicht gemessen):** etwa 10 ms CPU je Anfrage, also etwa 7 CPU-Stunden und etwa 0,15 $ im
  Monat; 256 MB RAM etwa 0,93 $; mit Anycast-IP gut 3 $. Der echte Verbrauch ist nicht gemessen.

## 3. Sammelverfahren (Entscheidung: Merkle-Baum)

- **Idee:** Das Relay sammelt die Hashes eines Zeitfensters je externem Dienst, bildet daraus einen Baum und lässt nur
  die Wurzel stempeln. Jeder Einreicher bekommt das Token plus Pfad, Salz, Position und Größe.
- **Verschleierung:** Das Blatt ist `SHA-256(0x00 ‖ r ‖ Hash)` mit Zufallszahl `r` je Einreicher; die anderen Hashes im
  Pfad sind dadurch keinem Dokument zuzuordnen. Ein XOR statt eines Hashes wäre falsch (das Relay könnte den Wert frei
  wählen). Innere Knoten `SHA-256(0x01 ‖ links ‖ rechts)`, Form wie RFC 6962 (kein Verdoppeln des letzten Blatts),
  Blätter vor dem Bau zufällig gemischt, gestempelt wird `SHA-256("zeitstempel-batch-v1\n" ‖ n ‖ Wurzel)`.
- **Verglichen mit einer einfachen Verkettung aller verschleierten Hashes:** Die Verkettung ist einfacher, ihr Beleg
  wächst aber linear (32 Byte mal n, bei 128 Hashes 4 KB). Der Baum braucht nur log₂(n) Hashes (bei 128 etwa 250 Byte).
  Entschieden wurde der Baum.
- **Wirkung:** ein externer Stempel je Fenster statt je Anfrage (Kapazität unabhängig von der Nutzerzahl), der externe
  Dienst sieht nur den gestempelten Wert, die Zeitaussage „spätestens zu T“ bleibt (T liegt höchstens ein Fenster nach
  dem Eingang). Preis: bis zu Fensterlänge plus etwa 0,3 s Wartezeit, ein zustandsbehaftetes Relay, ein neues Format.
  Der Beleg ist kein Stempel auf den Hash selbst, hat also nicht dieselbe Beweiskraft wie ein direkter oder
  qualifizierter Stempel.

## 4. Eigene Zeitstempel am Relay

- **Eigener Dienst (RFC 3161) am Relay:** möglich, ohne Kapazitätsgrenze und ohne Dritte. Die Beweiskraft ist aber gering:
  eine Partei stempelt für sich selbst, wer den Schlüssel hat, kann jede Zeit stempeln. Dazu kämen Schlüsselverwahrung,
  Zeitquelle, Protokollierung und Rotation, und die Bibliothek kann bisher keine Token erzeugen.
- **Eigene signierte Quittung:** schnell und ohne externen Dienst, aber kein Zeitstempel im Sinne von RFC 3161 und mit
  denselben Einschränkungen. Nur als Zusatz sinnvoll.

## 5. PDF und Adobe Acrobat

- **Möglich (Kenntnisstand, nicht geprüft):** Ein Token lässt sich als Dokument-Zeitstempel (PAdES, `ETSI.RFC3161`)
  in eine PDF einbetten: inkrementelles Update mit Signaturfeld und Platzhalter für das Token (mindestens etwa 16 KB Hex),
  SHA-256 über die `ByteRange`-Bytes, Token vom Relay in den Platzhalter. Acrobat zeigt das als Dokumentzeitstempel an.
- **Nur im Einzelstempel-Betrieb:** Adobe vergleicht den Abdruck im Token mit dem Hash der `ByteRange`; ein Sammel-Token
  bestätigt die Baumwurzel und passt dazu nicht.
- **Keine Personenunterschrift:** Ein grüner Haken mit Namen braucht ein Signaturzertifikat, das Adobe kennt; das ist nicht
  Teil dieses Projekts.
- **Anzeige:** Ein grüner Haken setzt voraus, dass Adobe dem Zertifikat des Zeitstempel-Dienstes vertraut (Adobe-Liste,
  EU-Liste). FreeTSA steht dort nach meinem Kenntnisstand nicht (dann „Gültigkeit unbekannt“); bei den Code-Signing-
  Diensten ist unklar, ob ihre Zertifikate für diesen Zweck zählen; ein qualifizierter Dienst würde vertraut. Das ist
  nicht geprüft und müsste in Acrobat selbst getestet werden. Für lange Gültigkeit braucht es eingebettete Prüfdaten (LTV).
- **Aufwand:** PDF-Handling gehört in ein eigenes Modul oder in die App (die Bibliothek hat bewusst keine Abhängigkeiten).
  Prüfbar mit `pdfsig` (poppler) und `pyHanko`, nicht mit Adobe selbst.

## 6. Entwurf: zwei Schlüsselarten und zwei Betriebsarten (umgesetzt am 2026-11-24, siehe §6a und `docs/relay.md`)

Vorgabe des Eigentümers: Schlüsselart 1 normal, Schlüsselart 2 berechtigt zur alleinigen Signatur. Zeitfenster gelten je
externem Dienst. Ist ein Fenster voll (Höchstzahl oder Anfrage der Art 2), wartet der Rest.

- **Schlüsseldatei:** optionales Feld `"solo": true` je Eintrag (Standard `false`); strikter Leser; die Art gehört zur
  Relay-Konfiguration, nicht zur Anfrage.
- **Anforderung:** im signierten Anfragekörper `{"hash": "…", "mode": "solo"}`; der Körper ist über den Körper-Hash an die
  Signatur gebunden. Schlüsselart 1 mit `mode: "solo"` wird abgelehnt (403).
- **Planer je externem Dienst** in festen Plätzen im Abstand `minIntervalMs`; jeder Platz gehört genau einem externen
  Stempel. Wartet eine Solo-Anfrage, bekommt sie den nächsten Platz; danach folgt ein Platz für ein offenes Sammelfenster
  (abwechselnd, damit nichts verhungert). Ist ein Sammelfenster voll, schließt es sofort und wartet auf den nächsten
  Platz; neue Anfragen öffnen das nächste Fenster.
- **Allein im Fenster:** Hat ein Sammelfenster genau einen Teilnehmer, wird dessen Hash direkt gestempelt (ohne Baum, kein
  `batch`-Feld in der Antwort). So bekommt auch Schlüsselart 1 einen alleinigen Stempel, aber nur, wenn niemand sonst im
  Fenster war. Nebenwirkung: Die Antwortart verrät dem Einreicher grob, ob im Fenster noch jemand anfragte.
- **Wartegrenze („Sicherheitsfenster“):** Jede Anfrage hat eine höchste Wartezeit in der Warteschlange
  (`RELAY_MAX_WAIT_MS`); danach `503 busy` mit `Retry-After`. Die Warteschlange je Dienst ist begrenzt. Die 60 s der
  Anmeldung (Zeitfenster der Signatur) und die ±60 s der Frischeprüfung (um den Zeitpunkt der Anfrage an den Dienst)
  werden von der Wartezeit nicht berührt, denn sie werden bei Eingang beziehungsweise beim Senden an den Dienst
  gemessen. Eine Wartegrenze von 60 s ist technisch möglich; Client- und Proxy-Fristen müssten dann mindestens 77 s
  betragen (Wartegrenze plus 17 s). Empfehlung: Standard 30 s, höchstens 60 s.
- **Kapazität (Schätzung):** Mit FreeTSA und Plätzen alle 5 s sind es 12 externe Stempel pro Minute; bei abwechselnder
  Vergabe höchstens 6 Solo-Stempel pro Minute für alle Schlüssel der Art 2 zusammen; die Solo-Warteschlange wäre auf etwa
  6 begrenzt, eine Wartegrenze von 60 s trüge höchstens 12 wartende Stempel je Dienst.
- **Zusätzliche Grenzen:** eigene Anfragegrenze je Schlüssel der Art 2 für Solo (zum Beispiel 6 pro Minute).
- **Verhältnis zu PDF:** Die PDF-Zeitstempel brauchen den Solo-Betrieb (direkter Abdruck).
- **Offen:** Reihenfolge Solo gegen laufendes Sammelfenster (abwechselnd gegen Vorrang), Standardwerte der Wartegrenze und
  der Warteschlange, Antwortformat für beide Arten (Client muss mit und ohne `batch` umgehen).

## 7. Weitere freie Zeitstempel-Dienste

Eine Aussage „es gibt sicher keine anderen“ ist nicht belegbar. Die Recherche (nur Websuche und Seitenabrufe, keine Anfragen
an die Dienste; gesucht wurde je einmal auf Englisch, Koreanisch und Chinesisch, also nicht erschöpfend) ergab. Die Zitate
stammen aus der Zusammenfassung des Abrufwerkzeugs; vor einer Übernahme in `docs/dienste.md` am Original prüfen:

**Belegt (Betreiberseite gelesen):**

- **CNX (Kambodscha):** `https://free.tsa.cnx.net.kh/`. „available for evaluation, development, and general use without
  registration“ (<https://cnx.net.kh/time/tsa/>). Policy (<https://tsa.cnx.net.kh/policy.html>): „best-effort basis with no
  SLA“, Protokolle höchstens 30 Tage, Haftung für die Gratisstufe ausgeschlossen, keine Ratengrenze genannt, nicht
  qualifiziert, Policy-OID `1.3.6.1.4.1.66148.1.2.1`. Zwecke laut Policy unter anderem Dokumentenintegrität und
  Audit-Trail; „beliebige Hashes“ nicht ausdrücklich geregelt. Wurzel und Hash-Algorithmen nicht ermittelt. Der einzige belegt
  freie Dienst in Asien/Ozeanien, den die Recherche fand.
- **Open TSA (Nürnberg, 2026 gestartet):** `https://tsr.open-tsa.eu`, „free for everyone, forever“, „Not eIDAS-qualified“.
  Eigene Wurzel laut Seite noch in keinem Trust Store, eine Sub-CA unter HARICA für 2027 geplant. Betreiber anonym
  („Open TSA Project“), die Nutzungsbedingungen (`/terms/`) lieferten 404.
- **IdenTrust (USA):** `http://timestamp.identrust.com`, „free of charge as a complement to IdenTrust Digital Certificate
  offerings“, es gilt ein Timestamping Service Agreement (Text nicht gelesen). Nur http. Ob beliebige Hashes ohne
  Zertifikatsbezug erlaubt sind, ist unklar.
- **Nicht frei nutzbar (belegt):** Apple (Subscriber und Relying Parties „internal to Apple“), CESNET (Forschung und Bildung,
  registrierte Nutzer), DFN (Teilnehmer, nicht kommerziell; Quelle eine Hochschulseite), Codegic (nur zum Testen, nicht für
  Produktivsysteme).

**Hörensagen, unklar oder keine Betreiberseite gefunden:**

- Mahidol (Thailand) und WoTrus/MeSign (China) nur in Gists oder Sekundärquellen (MeSign-Test laut Sekundärquelle 20 Anfragen je IP
  und Tag); Thai ETDA nur auf Antrag (Kosten und Bedingungen unbekannt); SwissSign, SSL.com, GlobalSign, Entrust, Microsoft,
  BalTstamp: Gratisstatus oder Bedingungen für Dritte unklar; Safecreative und TU Graz laut Gist mit Fehlern; QuoVadis verlangt
  laut Sekundärquelle die Registrierung der Quell-IP; StartCom/WoSign laut Gists seit Jahren tot.
- **Keine Betreiberseite mit öffentlichem Endpunkt gefunden:** Cybertrust Japan, SECOM, KICA/KOSCOM, TWCA/Chunghwa, Actalis,
  eMudhra, außerdem nichts für Singapur, Hongkong, Australien und den Nahen Osten.

**Folgerung (Einschätzung):** Als zusätzliche freie Anbieter kommen am ehesten in Betracht: CNX (belegt frei, schriftliche Policy;
Risiken: kleiner Betreiber, kein SLA, Anker zu klären, vorher den Betreiber zur Nutzung durch ein Relay fragen), IdenTrust
(etabliert; nur http, Vertragstext zu lesen) und Open TSA (https, offene Quelle; sehr jung, anonym, eigene Wurzel, Bedingungen
nicht lesbar; nur als zusätzlicher, deutlich gekennzeichneter Dienst). Nicht geprüft sind Erreichbarkeit, gelieferte Kette und
Algorithmen (RSA-PSS und andere Hashes als SHA-256 lehnt die Bibliothek ab), Listenstatus bei Adobe und EU, und ob ein Relay,
das den Verkehr aller Nutzer bündelt, noch unter „general use“ fällt.

## 7a. Open TSA geprüft (2026-11-24)

Eine Testanfrage (Hash eines kurzen Testtexts) an `https://tsr.open-tsa.eu`: Granted, 2513 Bytes, 0,95 s; SHA-256,
SHA-384, SHA-512; Genauigkeit 1 s; Policy 1.3.6.1.4.1.59085.1.1; RSA-4096-Kette; Signer-Zertifikat gültig bis
2028-04-03. `openssl ts -verify` ist OK mit dem Open-CA-Root und den Zwischenzertifikaten als `-untrusted`. Das Token
enthält **nur das Signer-Zertifikat**; unsere Bibliothek holt nichts nach, deshalb `ok` nur mit dem
**Zwischenzertifikat als Anker**, mit dem Root allein `untrusted-chain`. Betreiber anonym, Bedingungen,
Datenschutzerklärung und Impressum liefern 404, keine genannte Ratengrenze; die Seite wirbt mit „qualifiziert", nennt
sich an anderer Stelle „Not eIDAS-qualified". Empfehlung: höchstens als zusätzlicher, als unqualifiziert gekennzeichneter
Dienst, nicht aufgenommen.

## 7b. Bezahlte und qualifizierte Dienste (Recherche, Seiten nur über Zusammenfassungen gelesen)

Vollständiger Bericht mit Quellen: nicht im Repo (Arbeitsstand). Eckdaten, vor einer Übernahme am Original zu prüfen:

- **SK ID Solutions (EE):** qualifiziert laut AGB, SHA-256 in der Anfrage, ECDSA P-256 oder RSA-4096, Zugang per
  Vertrag und IP-Freigabe (feste Austritts-IP nötig), Test kostenlos, protokolliert alle Token unbefristet.
- **GLOBALTRUST (AT):** 1000 Stempel 185 EUR/Jahr, 10 000 für 1700 EUR/Jahr; Endpunkt und Anmeldeart nicht öffentlich.
- **Lleida.net (ES):** ab 0,03 EUR je Stempel, Benutzername und Passwort, wirbt mit Adobe-Kompatibilität.
- **Disig (SK):** 1000 Stempel 62,50 EUR netto, Zugang per Zertifikat. **Sectigo `/qualified`:** gut dokumentiert, nur
  http, Preis und Anmeldeart unklar. Weitere (D-Trust, GlobalSign, Utimaco, Certum): Preise nicht öffentlich.
- **Nötig im Code:** je Dienst eine Anmeldeart in `services.json` (Basic, Bearer/API-Key, mTLS, IP-Freigabe),
  Geheimnisse nur aus der Umgebung, Basic nur über https. Ungeprüft: SHA-512-Signatur mit P-256 gegen unsere Regel
  „Signatur-OID passt zum `digestAlgorithm`", QC-Erweiterungen und EKU qualifizierter Zertifikate (echte Testtokens
  nötig). Adobe vertraut sehr wahrscheinlich Anbietern der EU-Vertrauensliste (Verzug bis rund 30 Tage), freien Diensten
  mit eigener Wurzel nicht.
- **Nicht belegt:** Weiterverkauf oder Bündelung über ein Relay, Ratengrenzen, SLA, AVV-Angebot, aktueller EU-Listeneintrag.

## 7c. Datenschutz-Einordnung des Hashes (keine Rechtsberatung)

Ein SHA-256-Hash ist nicht umkehrbar, aber bei erratbaren Inhalten (kurze Texte, bekannte Dokumente, kleine Auswahl)
durch Raten und Vergleichen bestätigbar; Personenbezug entsteht durch Verknüpfung (IP, Schlüssel, Zeit). Das Relay
loggt nichts aus Anfragen, hält nur Zähler und den Wiederholungsschutz im Arbeitsspeicher und speichert kein Token. Der
Zeitstempeldienst sieht die IP des Relays, nicht die des Nutzers; im Sammelbetrieb nur die Wurzel eines Baums mit
verblindeten Blättern. Bunny: IP-Logs werden komplett gekürzt (Entscheidung); die technische Durchleitung der IP bleibt,
ob dafür ein AVV nötig ist, ist eine Rechtsfrage. Apps mit erratbaren Inhalten sollten vor dem Hashen einen eigenen
Salt anhängen und aufbewahren.

## 6a. Entscheidungen zu den Schlüsselarten (2026-11-24)

1. Typ-2-Schlüssel (`"solo": true`) vergibt nur Tobias. 2. Ein Schlüssel gilt **pro Nutzergruppe**. 3. Typ 2 darf jeden
   Dienst nutzen. 4. Schlüssel werden ausgegeben und in der App im Browserspeicher abgelegt (für Nutzer dieses Browsers
   auslesbar): niedriges Solo-Limit je Schlüssel, schnelles Sperren. 5. Typ 1 mit Solo-Wunsch wird bedient, wenn das
   Fenster leer ist, sonst `403 solo-not-allowed`. 6. Gewartet wird nur im Mangelfall (`RELAY_MAX_WAIT_MS`, Vorgabe 30 s,
   höchstens 60 s). 7./8. wie vorgeschlagen. 9. Schlüsseldatei wird **laufend neu gelesen** (strenger Leser, bei ungültiger
   Datei bleibt die alte); zusätzlich `restartAfter` in der Datei: Das Relay beendet sich einmal, wenn
   `Startzeit < restartAfter <= jetzt` (ein Prozess-Überwacher startet es neu; das Relay schreibt nie in die Datei).
2. **Variante A:** keine Zahlen je Schlüssel im Betreiberlog; die Mengengrenze je Schlüssel im Arbeitsspeicher bleibt.

## 8. Offene Punkte

- Qualifizierter Dienst (Vertrag, Zugangsdaten), rechtliche Klärung der Nutzungsbedingungen, Datenschutzbewertung der
  Weitergabe von Hashes.
- Menschliche Sicherheitsprüfung, signierter Aufruf und CORS mit Authentifizierung in echten Browsern, menschlicher
  Abgleich der Anker.
- Image, Betrieb, Überwachung, Alarm und Notfallablauf; Schlüsselrotation.
