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

## 2. Betrieb und Kosten

Betrieb, Kosten und Datenverkehr: Begleitrepo (nicht öffentlich). Die technischen Grenzen der Dienste stehen in Abschnitt 1.

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

## 6. Entwurf: zwei Schlüsselarten und zwei Betriebsarten (umgesetzt am 2026-11-24, siehe `docs/relay.md`; Entscheidungen dazu: Begleitrepo)

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

## 7b. Bezahlte und qualifizierte Dienste

Preise, Anmeldearten und Bedingungen stehen im Begleitrepo (`docs/recherche/bezahlte-dienste.md`, nicht öffentlich). Die technischen Anforderungen an bezahlte Dienste (Zugangsdaten, nur https, Quelle `relay`, `client` oder `either`) stehen in `docs/relay.md`, Abschnitt „Zugangsdaten zu bezahlten Diensten“; nur gegen Stubs getestet.

## 7c. Datenschutz-Einordnung des Hashes

Die Einordnung mit Betreiberangaben, Hostern und Auftragsverarbeitung steht im Begleitrepo (nicht öffentlich). Was das Relay sieht und speichert: `docs/relay.md`, Abschnitt „Was das Relay sieht“.

## 8. Offene Punkte

- Menschliche Sicherheitsprüfung; Prüfung der Relay-Anmeldung in weiteren Browsern (Firefox, Safari); das Prüfskript der Anmeldung liegt nicht im Repo; menschlicher Abgleich der Anker.
- Schlüsselrotation (nicht gebaut).
- Qualifizierter Dienst, Betrieb, Verträge und rechtliche Fragen: Begleitrepo (nicht öffentlich).
