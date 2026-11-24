# Was die Prüfung kann und was nicht

Stand: 2026-11-24. Die Bibliothek prüft ein Zeitstempel-Token nach RFC 3161. Diese Seite sagt ehrlich, was
**nicht** geprüft wird und wo die Aussage endet.

## Was geprüft wird

1. Das Token ist strikt gelesen: DER mit bestimmter Länge, kürzeste Längenform, begrenzte Größe und Tiefe.
2. Der bestätigte Hash (SHA-256) ist genau der erwartete.
3. Die Nonce stimmt, wenn eine erwartet wird.
4. Der Hash des Inhalts stimmt mit dem signierten Attribut überein, der Inhaltstyp ist `TSTInfo`.
5. Das Attribut zum Zeitstempel-Zertifikat (`signingCertificate` oder `signingCertificateV2`) passt zum
   verwendeten Zertifikat. Im v2-Attribut (ESSCertIDv2) gilt der dort genannte Hash; **SHA-1 und eine unbekannte
   Hash-OID dort werden abgelehnt** (`unsupported-hash`), es gibt keinen stillen Rückfall auf SHA-256 (fehlt die
   Angabe ganz, gilt SHA-256, wie im RFC 5035). Nur das v1-Attribut (`signingCertificate`) rechnet mit SHA-1.
6. Die Signatur (RSA PKCS#1 v1.5 oder ECDSA P-256/P-384/P-521, mit SHA-256/384/512) stimmt. Nennt die
   Signatur-OID ihren Hash (z. B. `ecdsa-with-SHA384`, `sha256WithRSAEncryption`), muss er zum `digestAlgorithm`
   des Unterzeichner-Eintrags passen, sonst `signature-invalid` (wie bei `openssl ts -verify`: `signature failure`).
   Eine nackte OID (`rsaEncryption`, `id-ecPublicKey`) nimmt den Hash des `digestAlgorithm`.
7. Das Zeitstempel-Zertifikat erlaubt Zeitstempel (erweiterte Schlüsselverwendung mit genau dem einen Zweck
   `id-kp-timeStamping`, standardmäßig kritisch verlangt) und die Signatur-Verwendung. **Schlüsselverwendung
   (`keyUsage`):** verlangt wird nur, dass `digitalSignature` oder `nonRepudiation` gesetzt ist, wenn die
   Erweiterung vorhanden ist; **zusätzliche Bits** (z. B. `keyEncipherment`, `keyAgreement`, `keyCertSign`,
   `cRLSign`) neben `digitalSignature` werden angenommen. `openssl ts -verify` lehnt solche Zertifikate ab. Ob das
   verschärft werden soll, ist eine Entscheidung des Besitzers (derzeit nicht).
8. Alle Zertifikate der Kette waren **zur bestätigten Zeit** (`genTime`) gültig und, wenn die Option `at` gegeben
   ist, **zusätzlich zu `at`** (beides, `at` ersetzt die `genTime` nicht; mit `at` ist ein Zertifikat, das nur zu
   `at` gültig war, abgelehnt: `certificate-not-valid-at-time`), kein Zertifikat der Kette (Anker ausgenommen) trägt eine
   kritische, unbekannte Erweiterung, die Aussteller sind
   Zertifizierungsstellen und erlauben das Ausstellen von Zertifikaten, und die Kette endet bei einem der
   übergebenen Anker. **Ausnahme Anker:** Ein übergebener Anker ohne `basicConstraints` (X.509 v1, ohne
   Erweiterungen) darf als CA gelten (Entscheidung des Aufrufers, wie bei kritischen Erweiterungen und der
   erweiterten Schlüsselverwendung); ein Anker mit ausdrücklichem `cA=false` bleibt abgelehnt (`not-a-ca`), und
   ein Zwischenzertifikat ohne `basicConstraints` (kein Anker) ebenfalls.
9. Eine Zwischen-CA der Kette, die eine erweiterte Schlüsselverwendung trägt, muss `id-kp-timeStamping` oder
   `anyExtendedKeyUsage` enthalten (sonst `bad-eku`); ohne diese Erweiterung gilt keine Einschränkung. Der
   Anker ist ausgenommen (Entscheidung des Aufrufers).
10. **Das Feld `tsa` des TSTInfo** (RFC 3161 § 2.4.2: es muss einem der Namen des Zeitstempel-Zertifikats
    entsprechen; sonst `tsa-mismatch`). Fehlt das Feld (z. B. bei DigiCert), wird nichts verglichen. Ein
    `directoryName` gilt, wenn er das `subject` des Signierers ist (vereinfachter Namensvergleich wie oben) oder
    einem `directoryName` im `subjectAltName` entspricht. Jede andere Art (`dNSName`, `rfc822Name`, `URI`,
    `iPAddress`, `registeredID`, `otherName`, `x400Address`, `ediPartyName`) gilt nur, wenn das `subjectAltName`
    einen Eintrag **derselben Art** hat: bei `dNSName` mit gleichem Text (ASCII-Groß-/Kleinschreibung ohne
    Bedeutung, RFC 5280 § 7.2), bei allen anderen mit **denselben Bytes**. Aus dem `subject` wird sonst nichts
    abgeleitet (eine `emailAddress` im Namen zählt nicht als `rfc822Name`). Ein `tsa`, das kein `GeneralName` ist,
    ist `bad-tst-info`; ein nicht lesbares `subjectAltName`, das für den Vergleich gebraucht wird,
    `bad-certificate`. Die vier aufgezeichneten Antworten bestehen die Regel (FreeTSA, Sectigo und Certum setzen
    `tsa` als `directoryName` des Signierer-Subjects, DigiCert setzt es nicht; ein Test hält das fest).
11. **Der TSTInfo wird als Schema gelesen** (RFC 3161 § 2.4.2): Version, Richtlinie, `messageImprint`,
    Seriennummer, `genTime`, dann `accuracy`, `ordering`, `nonce`, `tsa` `[0]`, Erweiterungen `[1]`, jedes
    höchstens einmal, in dieser Reihenfolge, nichts Überzähliges (sonst `bad-tst-info`). `accuracy`: Sekunden,
    `[0]` Millisekunden, `[1]` Mikrosekunden, je höchstens einmal in dieser Reihenfolge, Milli- und Mikrosekunden
    1 bis 999. `ordering` FALSE ausdrücklich geschrieben ist `bad-tst-info` (DER schreibt den DEFAULT nicht). Die
    Erweiterungen `[1]` sind eine nicht leere Folge von `Extension` (Kennung, `critical` nur wenn TRUE, Wert); ihr
    Inhalt wird nicht beurteilt, auch eine kritische, unbekannte Erweiterung nicht (wie `openssl ts -verify`). Im
    `messageImprint` hat der Hash-Algorithmus höchstens einen Parameter, und der ist NULL.
12. **Mindestgröße von RSA-Schlüsseln (`minRsaBits`, Vorgabe 2048):** Das Zeitstempel-Zertifikat und jedes
    Zertifikat der Kette, das **kein übergebener Anker** ist, darf keinen RSA-Schlüssel mit weniger Bit im Modul
    haben (`weak-key`). Die Regel gilt vor der Signaturprüfung des Signierers (so hängt die Antwort nicht davon ab,
    ob die Plattform einen kleinen Schlüssel überhaupt importiert). `minRsaBits: 0` schaltet sie aus. Schlüssel
    anderer Art (ECDSA) sind nicht betroffen. Der Exponent wird nicht beurteilt.

Punkt 9 ist **strenger als `openssl ts -verify`**, der eine solche Zwischen-CA annimmt; die Regel folgt der
Praxis der Browser (Verschachtelung der erweiterten Schlüsselverwendung entlang der Kette). Eine Zwischen-CA nur
für Codesignatur oder nur für Server-Authentifizierung kann also keinen Zeitstempel-Signierer ausstellen.

**Strenger als `openssl ts -verify`** (jeweils eine falsche Ablehnung möglich, nie eine falsche Annahme):

- Punkt 9 (erweiterte Schlüsselverwendung einer Zwischen-CA, s. o.).
- **Punkt 12** (`weak-key`): openssl nimmt auch RSA-512 an (gemessen, 3.0.13).
- **TSTInfo (Punkt 11):** `ordering` FALSE ausdrücklich geschrieben, Milli-/Mikrosekunden 0 oder über 999, leere
  Erweiterungen `[1]`, `critical` FALSE ausdrücklich geschrieben und ein anderer Parameter als NULL beim
  Hash-Algorithmus des `messageImprint` lehnen wir ab, openssl nimmt sie an (gemessen).
- **Bruchteil in Zertifikatszeiten:** `notBefore` und `notAfter` mit Sekundenbruchteil gelten als ungültig gelesen
  (`bad-time`, s. „Zeiten“). Ob openssl sie liest, hängt von der Version ab; hier (OpenSSL 3.0.13) lehnen beide ab.
- **Nullen am Ende des Sekundenbruchteils in `genTime`** (z. B. `20260101000000.50Z`, `…00.000Z`): RFC 3161 § 2.4.2
  verbietet sie (Sekundenbruchteil ohne Nullen am Ende); diese Bibliothek folgt dem, openssl ist hier lockerer.
  Ein Dienst, der so stempelt, wird abgelehnt.

Die Namen von Ausstellern werden nach der vereinfachten Regel von RFC 5280 § 7.1 verglichen (nur zur **Auswahl** der
Kandidaten; entschieden wird durch die Signatur): Attributtypen (OID) genau; Werte als `UTF8String`,
`PrintableString`, `IA5String`, `TeletexString` oder `BMPString` gelesen, ASCII-Buchstaben ohne Beachtung der
Groß-/Kleinschreibung, Leerzeichen am Anfang und Ende entfernt, innere Folgen von Leerzeichen zu einem
zusammengefasst; ein unbekannter Werttyp wird bytegleich verglichen, ein nicht lesbarer Name insgesamt ebenfalls.
Das gilt für das `issuer`-Feld eines Zertifikats gegen das `subject` des Ausstellers und für den Aussteller im
Unterzeichner-Eintrag (`sid`) gegen das Zeitstempel-Zertifikat (bei der Form mit Aussteller und Seriennummer; der
Schlüsselbezeichner wird bytegleich verglichen, s. „Unterzeichner über `subjectKeyIdentifier`“). Eine lockerere Namensübereinstimmung macht die
Grenzen nicht leichter erreichbar: Ein Zwilling, der sich nur in der Schreibweise unterscheidet, zählt wie ein
namensgleicher gegen die 8 Kandidaten und die 64 Signaturprüfungen (Zwillinge ohne CA-Recht usw. kosten weiter nichts).

**Lockerer als `openssl ts -verify`** (eine falsche Annahme gegenüber openssl, die Entscheidung der Bibliothek
folgt dem RFC):

- **Zusätzliche `keyUsage`-Bits** des Signierers (Punkt 7, s. o.).
- **Gültigkeit inklusive:** Die Gültigkeit eines Zertifikats schließt `notBefore` und `notAfter` ein (RFC 5280
  § 4.1.2.5). Ist die Stempelzeit genau `notAfter`, gilt das Zertifikat noch; `openssl` 3.0.13 lehnt in diesem
  Fall ab.
- **`dNSName` im `tsa`-Feld:** Groß-/Kleinschreibung zählt nicht (RFC 5280 § 7.2); openssl vergleicht die Bytes und
  lehnt `TSA.Example.ORG` gegen `tsa.example.org` ab (gemessen). Eine Entscheidung nach dem RFC, ohne Folge für
  die Sicherheit (der Name steht im signierten Inhalt).
- **Nicht gelesene Felder:** `crls` im SignedData wird nur auf das Tag geprüft, nicht gelesen; Müll darin wird
  angenommen. Das hat keine Auswirkung auf die Entscheidung (`crls` sind nicht signiert und werden nicht benutzt),
  das Token ist dort aber verformbar. (Der TSTInfo wird seit Punkt 11 vollständig als Schema gelesen.)

Gegengeprüft wird mit `openssl ts -verify` an den aufgezeichneten Antworten von vier Diensten und beim
Schnelltest (`npm run spike`).

## Was NICHT geprüft wird

- **Frische (ohne `minGenTime`):** Ohne die Option `minGenTime` wird **nicht geprüft, wie alt das Token ist**. Die
  Bibliothek kennt keine eigene Zeitquelle und weiß nicht, wann die Anfrage ging. Ein Dienst (oder wer seinen
  Signierschlüssel hat, etwa nach Ablauf oder Diebstahl des Schlüssels) kann ein Token mit einer **rückdatierten**
  `genTime` ausstellen, solange sein Zertifikat zu dieser früheren Zeit gültig war; es besteht die Prüfung. Das
  Token behauptet dann „der Hash existierte schon 2021“, obwohl er heute gestempelt wurde. Dagegen hilft nur, den
  Zeitpunkt des Sendens zu merken und `minGenTime: new Date(gesendet − 60_000)` (zusammen mit `now`) zu übergeben;
  das Relay macht das für seine eigene Prüfung (`genTimeSlackMs`, `docs/relay.md`). Wer ein Token **später oder
  anderswo** prüft (ohne den Zeitpunkt des Sendens zu kennen), kann die Frische nicht prüfen. `now` allein fängt nur
  die Zukunft ab.
- **Sperrung (Revocation):** Es wird weder OCSP noch eine Sperrliste ausgewertet. Ein später gesperrtes
  Zertifikat erscheint weiterhin gültig. Die Prüfung gilt für die Zeit der Bestätigung; für Langzeitnachweise
  bräuchte man zusätzlich Sperrinformationen zum damaligen Zeitpunkt (Langzeit-Validierung, LTV).
- **Schaltsekunde:** Ein Token mit `genTime` `…60Z` (Sekunde 60, wie eine Schaltsekunde sie hätte) wird abgelehnt
  (`bad-time`), ebenso jede andere Sekunde über 59. Ein solches Token ist mit dieser Bibliothek **unprüfbar**. Das
  Relay antwortet dann `502 upstream-invalid` (Grund `bad-time`), und das Budget des Dienstes ist verbraucht (die
  Anfrage ging hinaus). Das ist bewusst so entschieden (keine Annahme eines Wertes, den `Date` nicht darstellen
  kann). Ob ein Dienst bei einer Schaltsekunde so stempelt, wurde nicht untersucht.
- **Namens- und Pfadbeschränkungen** der Zertifikate (NameConstraints, pathLenConstraint) werden nicht
  ausgewertet; die Länge der Kette ist begrenzt (höchstens 5 Zwischenzertifikate; `chainLength` höchstens 7, Anker eingerechnet).
- **Zertifikatsrichtlinien** (Policy-OIDs): Die Richtlinie des Tokens wird gemeldet, aber nicht gegen eine
  Erwartung geprüft.
- **Nicht unterstützt:** RSA-PSS, BER (nur DER), SHA-1 (nur als Zertifikats-Hash im Attribut `signingCertificate` (v1) angenommen; als Hash des Abdrucks oder der Signatur und überall sonst abgelehnt), andere
  Hashverfahren als SHA-256 für den Abdruck, Token ohne `certReq` (das Zeitstempel-Zertifikat muss im Token
  liegen). Das sind abgelehnte Fälle, keine stillen Annahmen.
- **Inhalt des TSTInfo und der Algorithmus-Kennungen:** Eine kritische, unbekannte Erweiterung in `TSTInfo`
  wird nicht abgelehnt (der Aufbau der Erweiterungen wird aber gelesen); die Parameter der
  `AlgorithmIdentifier` der Signatur werden nicht ausgewertet (die OID legt das Verfahren fest). Das RSA-Padding prüft nicht
  diese Bibliothek, sondern WebCrypto der Plattform (unter Node getestet, im Browser nicht).
- **Zeiten:** `genTime` wird auf Millisekunden **abgeschnitten** (nicht gerundet; gelesen werden bis zu 9
  Nachkommastellen). Ein `genTime` bis knapp unter 1 ms nach `notAfter` gilt deshalb noch als gültig, und das
  `genTime` als ISO-Text kann bis knapp unter 1 ms früher sein als im Token. Die Gültigkeit von Zertifikaten
  (`notBefore`, `notAfter`) wird dagegen **ohne Nachkommastellen** gelesen (RFC 5280 verbietet sie): ein Zertifikat mit
  Bruchteil in der Gültigkeit ist ungültig gelesen (`bad-time`): ein Anker macht die Eingabe ungültig, ein Zusatzzertifikat im Token wird übersprungen (s. „Bewusst streng“).
- **Die Anker selbst:** Wem man vertraut, entscheidet der Aufrufer. Die mitgelieferten Anker sind **Wurzeln**: Die
  Prüfung akzeptiert jedes Zeitstempel-Zertifikat unter ihnen, auch das einer anderen Stelle derselben Hierarchie.
  Eine engere Wahl (Zwischen-CA oder Signierer als Anker) trifft der Aufrufer selbst; kein Pinning im Paket. Die mitgelieferten Anker stammen aus
  einem Zertifikatspaket und der Seite von FreeTSA; ihre Fingerabdrücke (`docs/dienste.md`) wurden am
  2026-11-23 mit öffentlichen Betreiberseiten und dem System-Trust-Store abgeglichen (Netzabgleich, keine
  Rückfrage bei den Betreibern, keine menschliche Prüfung).

## Abgleich mit OpenSSL (Marktvergleich vom 2026-11-24, `openssl 3.0.13`)

Jede Zeile ist ein Unterschied oder eine Gemeinsamkeit mit `openssl ts -verify`, wie der Vergleichsbericht sie
nummeriert (F1 bis F20). „Gemessen“ heißt: ein eigener Fall in `tests/openssl.test.ts` lässt OpenSSL und diese
Bibliothek dasselbe Token beurteilen und hält beide Ausgänge fest (ein sichtbarer Skip ohne OpenSSL 3). Angaben ohne
„gemessen“ zu OpenSSL beruhen auf Kenntnis oder Quelltext und sind **nicht gemessen**. Das Ergebnis:
**behoben** (früher eine Lücke, jetzt ein Test), **bewusst anders** (Entscheidung, dokumentiert) oder **Lücke**
(offen, nicht gebaut). Eine falsche Annahme (ungültig als gültig) wurde nicht gefunden.

| Nr  | Fall                                                                                                                              | OpenSSL                                                                               | wir                                                                                                                | Einstufung                                                                                                                       |
| --- | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| F1  | `tsa` nennt einen fremden Namen                                                                                                   | lehnt ab (gemessen)                                                                   | `tsa-mismatch`                                                                                                     | **behoben**; alle `GeneralName`-Arten gemessen, `dNSName` mit anderer Schreibweise nehmen wir an, OpenSSL nicht (bewusst anders) |
| F2  | TSTInfo: Felder doppelt, vertauscht, Überzähliges, Accuracy-Teile doppelt oder vertauscht                                         | lehnt ab (gemessen)                                                                   | `bad-tst-info`                                                                                                     | **behoben**                                                                                                                      |
| F2  | `ordering` FALSE ausdrücklich, Erweiterungen `[1]` leer, `critical` FALSE ausdrücklich, Parameter des Hash-Algorithmus nicht NULL | nimmt an (gemessen)                                                                   | `bad-tst-info`                                                                                                     | bewusst strenger (DER, Schema)                                                                                                   |
| F15 | Accuracy Milli-/Mikrosekunden 0 oder 1000                                                                                         | nimmt an (gemessen)                                                                   | `bad-tst-info`                                                                                                     | **behoben**, bewusst strenger                                                                                                    |
| F3  | RSA-512 und RSA-1024 als Signierer oder Zwischen-CA                                                                               | nimmt an (gemessen)                                                                   | `weak-key` (Vorgabe `minRsaBits` 2048; Anker ausgenommen)                                                          | **behoben**, bewusst strenger; der Exponent (z. B. e = 3) wird nicht beurteilt (Lücke)                                           |
| F4  | Signierer mit `subjectKeyIdentifier` statt Aussteller und Seriennummer (SignerInfo Version 3)                                     | `ts -verify`: lehnt ab, kann die Form nicht lesen; `cms -verify`: nimmt an (gemessen) | nimmt an; Version und Form müssen zusammenpassen (`unsupported-version`), sonst wie F8                             | **behoben** (s. „Unterzeichner über `subjectKeyIdentifier`“); Unterschiede zu `cms -verify` gemessen, Tabelle dort               |
| F5  | `cmsAlgorithmProtection` (RFC 8933)                                                                                               | nicht gemessen                                                                        | Attribut wird nie gelesen; nur die Teilregel „benannte Signatur-OID gegen `digestAlgorithm`“ (`signature-invalid`) | Lücke (klein)                                                                                                                    |
| F6  | Signierer ist selbst eine CA (`cA` TRUE)                                                                                          | nimmt an (gemessen)                                                                   | nimmt an (gemessen)                                                                                                | Lücke, gleich                                                                                                                    |
| F7  | `pathLenConstraint`, Namensbeschränkungen                                                                                         | prüft                                                                                 | nicht ausgewertet (Kette höchstens 5 Zwischenzertifikate, kritische Namensbeschränkung ist `bad-certificate`)      | **Lücke, nicht gebaut** (s. „Was NICHT geprüft wird“)                                                                            |
| F8  | Zertifikat mit gleichem Aussteller und gleicher Seriennummer vor dem echten                                                       | lehnt ab (gemessen)                                                                   | `signing-certificate-mismatch` (nur Verfügbarkeit: das erste Treffer-Zertifikat wird genommen)                     | gleich; Verbesserung offen                                                                                                       |
| F9  | Token ohne eingebettete Zertifikate                                                                                               | unterstützt                                                                           | nicht unterstützt (`signer-certificate-missing`)                                                                   | bewusst anders                                                                                                                   |
| F10 | erwartete Policy / `reqPolicy`                                                                                                    | prüft                                                                                 | nur gemeldet                                                                                                       | Lücke                                                                                                                            |
| F11 | `signingTime` widerspricht `genTime`                                                                                              | –                                                                                     | `signingTime` wird nie gelesen                                                                                     | bewusst anders (kein Risiko, solange es nie ausgewertet wird)                                                                    |
| F12 | SignedData-Version 1, ein Byte Anhang, BER mit unbestimmter Länge                                                                 | nimmt an (gemessen)                                                                   | `unsupported-version`, `trailing-bytes`, `indefinite-length`                                                       | **bewusst strenger** (nur DER); Verfügbarkeitsrisiko bei einem Dienst, der so stempelt (von Hand nur vier Dienste gesammelt)     |
| F13 | `issuerSerial` im ESSCertID                                                                                                       | nicht gemessen                                                                        | nur der Hash wird verglichen                                                                                       | Lücke ohne Wirkung (der Hash bindet das Zertifikat)                                                                              |
| F14 | Seriennummer 0 oder 21 Oktette (Zertifikat), Seriennummer 0 (TSTInfo), Nonce 0                                                    | nimmt an (gemessen)                                                                   | nimmt an (gemessen)                                                                                                | gleich (Lücke gegen RFC 5280)                                                                                                    |
| F16 | Zertifikatszeit als GeneralizedTime vor 2050                                                                                      | nimmt an                                                                              | nimmt an                                                                                                           | bewusst locker                                                                                                                   |
| F17 | Zertifikatsform locker (v1 mit Erweiterungen, `[3]` an beliebiger Stelle u. ä.)                                                   | nicht gemessen                                                                        | nimmt an (nur Anker und mitgelieferte Zertifikate, vom CA signiert)                                                | bewusst locker                                                                                                                   |
| F18 | Brainpool, Ed25519, RSA-PSS, ML-DSA                                                                                               | Brainpool, Ed25519, RSA-PSS ja                                                        | `unsupported-signature`                                                                                            | **bewusst anders, nicht gebaut** (WebCrypto kennt Brainpool nicht); Beobachtungsliste                                            |
| F19 | `qcStatements` (qualifizierter Stempel)                                                                                           | –                                                                                     | nicht gelesen                                                                                                      | Lücke; erst mit einem qualifizierten Dienst, dann nur als Hinweis                                                                |
| F20 | Hash im Abdruck: nur SHA-256                                                                                                      | alle                                                                                  | nur SHA-256 (`unsupported-hash`)                                                                                   | bewusst anders                                                                                                                   |
| –   | `keyUsage` des Signierers mit zusätzlichen Bits                                                                                   | lehnt ab                                                                              | nimmt an                                                                                                           | bewusst locker (s. Punkt 7)                                                                                                      |
| –   | Gültigkeit inklusive `notAfter`                                                                                                   | lehnt ab (3.0.13)                                                                     | nimmt an                                                                                                           | bewusst locker                                                                                                                   |
| –   | Zwischen-CA mit fremder erweiterter Schlüsselverwendung                                                                           | nimmt an                                                                              | `bad-eku`                                                                                                          | bewusst strenger (Punkt 9)                                                                                                       |
| –   | Nullen am Ende des Sekundenbruchteils in `genTime`                                                                                | nimmt an                                                                              | `bad-time`                                                                                                         | bewusst strenger (RFC 3161)                                                                                                      |
| –   | `signedAttrs` nicht in DER-Reihenfolge, so signiert                                                                               | vermutlich lehnt ab (nicht gemessen)                                                  | prüft die empfangenen Bytes                                                                                        | bewusst anders, nicht gemessen                                                                                                   |

Bekannte Lücken, die **nicht** gebaut wurden (Entscheidung des Besitzers, solange kein Dienst sie braucht): die
Auswertung von `pathLenConstraint` und Namensbeschränkungen, Brainpool-Kurven und Ed25519 als Signatur. Gebaut seit
dem Vergleich: F4 (Signierer über `subjectKeyIdentifier`, `tests/ski-signer.test.ts`). Der Rest von F4, was nicht
gemessen ist: ein echter Dienst, der so stempelt (keiner der vier aufgezeichneten tut es; die Form ist nur mit eigenen
Token und mit einem von OpenSSL geschriebenen `cms`-Token geprüft, nicht mit einem Zeitstempeldienst).

### Unterzeichner über `subjectKeyIdentifier` (F4)

Der Unterzeichner-Eintrag (`SignerInfo`, RFC 5652 § 5.3) nennt das Zeitstempel-Zertifikat auf zwei Arten. Beide werden
gelesen; die Form hängt an der Versionsnummer des Eintrags:

| Version | Form (`sid`)                                                        | Auswahl des Zertifikats                                                             |
| ------- | ------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| 1       | `issuerAndSerialNumber` (SEQUENCE aus Aussteller und Seriennummer)  | wie bisher: das erste Zertifikat im Token mit passendem Aussteller und Seriennummer |
| 3       | `subjectKeyIdentifier` (`[0]` IMPLICIT OCTET STRING, einfache Form) | Zertifikate des Tokens mit gleichem Schlüsselbezeichner; dann die Regel unten       |

- **Zusammenpassen:** Version 3 mit `issuerAndSerialNumber` und Version 1 mit Schlüsselbezeichner sind
  `unsupported-version`, ebenso jede andere Versionsnummer (0, 2, 4 ...). Eine andere Form (verschachteltes `[0]`,
  `[1]`, universeller OCTET STRING, ...) ist `bad-structure`. Der Bezeichner hat 1 bis 64 Byte (`SKI_BYTES`),
  sonst `bad-structure`. **SignedData-Version:** bleibt für beide Formen genau 3. RFC 5652 § 5.1 verlangt 3, sobald ein
  Eintrag Version 3 hat **oder** der Inhaltstyp nicht `id-data` ist; der Inhalt eines Zeitstempels ist ein `TSTInfo`,
  also gilt 3 auch bei Version 1 des Eintrags (so schreiben es die vier aufgezeichneten Dienste).
- **Zertifikat:** Die Erweiterung `subjectKeyIdentifier` (2.5.29.14) eines Zertifikats muss ein OCTET STRING von 1 bis 64
  Byte im OCTET STRING der Erweiterung sein, ohne Rest; sonst ist das Zertifikat unlesbar (`bad-certificate` beim Lesen
  eines Ankers, im Token wird es übersprungen und nie Kandidat). Eine doppelte Erweiterung ist wie jede doppelte
  Erweiterung `bad-certificate`. Als kritisch markiert wird sie gelesen (RFC 5280 verlangt „nicht kritisch“ von der
  CA, schreibt dem Prüfer aber nichts vor; die Erweiterung steht schon in `KNOWN_EXTENSIONS`).
- **Kein Berechnen:** Ein Zertifikat ohne die Erweiterung hat keinen Bezeichner und wird von einem Eintrag mit
  Schlüsselbezeichner **nie** gefunden (`signer-certificate-missing`); er wird nicht aus dem Schlüssel berechnet (RFC 5280
  § 4.2.1.2, Verfahren 1 oder 2). Das ist Absicht: sonst hinge die Auswahl an einer Rechenvorschrift, die der Dienst
  nicht einhalten muss. OpenSSL macht es gleich (gemessen: `cms -sign -keyid` mit so einem Zertifikat bricht mit
  „certificate has no keyid“ ab, `cms -verify` findet es nicht).
- **Mehrere Treffer** (gleicher Bezeichner, z. B. ein Zertifikat mit anderem Schlüssel oder neu ausgestellt): Es zählt das
  Zertifikat, dessen Hash das signierte Attribut `signingCertificate(V2)` nennt; das Attribut bindet genau ein
  Zertifikat, also wird auch nur dieses auf Signatur geprüft (eine Signaturprüfung, kein Hängenbleiben an Zwillingen).
  Gesucht wird unter höchstens 16 Zertifikaten (`MAX_CERTIFICATES`), je ein Hash. Ist keines das genannte, gilt der
  Grund des ersten (`signing-certificate-mismatch`, `signing-certificate-missing` oder `unsupported-hash`). Bei Version 1
  bleibt es beim ersten Treffer (F8, unverändert). Kein Zertifikat mit dem Bezeichner: `signer-certificate-missing`.
- **Ergebnis:** `VerifiedTimestamp` ist unverändert. `readToken` gibt statt `issuer` und `serial` die Angabe
  `signer.sid` zurück (`kind` `issuerAndSerialNumber` mit `issuer`, `serial` oder `subjectKeyIdentifier` mit `ski`);
  `Certificate` hat das neue Feld `subjectKeyIdentifier` (Bytes oder `null`).

Abgleich mit OpenSSL 3.0.13 (`tests/openssl.test.ts`, gemessen mit gebauten Token und einem von `openssl cms -sign
-keyid` geschriebenen):

| Fall                                                           | `ts -verify`                                               | `cms -verify`                             | wir                              | Einstufung                                                         |
| -------------------------------------------------------------- | ---------------------------------------------------------- | ----------------------------------------- | -------------------------------- | ------------------------------------------------------------------ |
| Signierer über Bezeichner, Kette in Ordnung                    | lehnt ab (liest die Form nicht: `PKCS7_ISSUER_AND_SERIAL`) | nimmt an                                  | nimmt an                         | gleich wie CMS; `ts -verify` ist hier die Lücke von OpenSSL        |
| Bezeichner passt zu keinem Zertifikat                          | lehnt ab                                                   | lehnt ab                                  | `signer-certificate-missing`     | gleich                                                             |
| Zertifikat ohne Erweiterung, Bezeichner = SHA-1 des Schlüssels | lehnt ab                                                   | lehnt ab                                  | `signer-certificate-missing`     | gleich (nichts wird berechnet)                                     |
| zwei Zertifikate mit gleichem Bezeichner, das falsche zuerst   | lehnt ab                                                   | lehnt ab (nimmt das erste, kein Suchen)   | nimmt an (Hash aus dem Attribut) | bewusst anders, **besser**                                         |
| Version 3 mit `issuerAndSerialNumber`                          | nimmt an                                                   | nimmt an                                  | `unsupported-version`            | bewusst strenger (RFC 5652 § 5.3; OpenSSL liest die Version nicht) |
| Version 1 mit Bezeichner                                       | lehnt ab (Form)                                            | nimmt an                                  | `unsupported-version`            | bewusst strenger                                                   |
| Bezeichner im Eintrag mit 0 Byte                               | lehnt ab                                                   | lehnt ab                                  | `bad-structure`                  | gleich im Ausgang                                                  |
| Bezeichner mit 65 Byte (Eintrag und Zertifikat)                | lehnt ab                                                   | nimmt an                                  | `bad-structure`                  | bewusst strenger (Grenze 64 ist unsere, der RFC nennt keine)       |
| Erweiterung als kritisch markiert                              | lehnt ab (auch mit Version 1: gleiche Abweichung)          | lehnt ab („unhandled critical extension“) | nimmt an                         | bewusst locker (RFC 5280 verbietet das der CA, nicht dem Prüfer)   |

Nicht gemessen: ein Dienst im Netz, der so stempelt; die Größe des Bezeichners bei echten Zertifikaten (die
aufgezeichneten tragen 20 Byte); ob `ts -reply` von OpenSSL die Form schreiben kann (sein PKCS#7-Leser kennt nur Aussteller und Seriennummer, also
vermutlich nicht; nicht versucht).

## Verhalten bei Fehlern (fail-closed)

Ein Wert, der nicht zu den Prüfoptionen passt, ergibt `bad-options` statt einer still übersprungenen Prüfung:
`trust` muss ein Array sein (kein Text, kein `Set`, kein Objekt, nicht `undefined`); `options` selbst muss weggelassen oder ein **einfaches Objekt** sein (Prototyp `Object.prototype` oder `null`;
nicht `null`, keine Zahl, kein Text, keine Funktion, kein Array, keine Klasseninstanz, keine `Map`, kein `Date`,
kein `String`-Objekt). Eine Klasseninstanz oder eine `Map` wird also nie als „leere Optionen“ angenommen: die
Folge „Prüfung still aus“ ist ausdrücklich ausgeschlossen. `expectedNonce`
muss, wenn der Schlüssel vorhanden und nicht `undefined` ist, ein `Uint8Array` mit 1 bis 16 Byte sein (`null`,
`0`, `""`, `NaN`, `false`, ein leeres Array oder leere Bytes sind also Fehler und keine „keine Nonce“);
`requireCriticalEku` muss ein Wahrheitswert sein; `now`, `at` und `minGenTime` müssen **echte** `Date`-Objekte mit gültiger
Zeit sein (Prototyp genau `Date.prototype`, endlich, Betrag höchstens 8,64e15 ms; Unterklassen, Objekte, die
nur über `Symbol.toStringTag` ein Datum vortäuschen, und ein `Date` aus einem anderen Realm sind Fehler);
`maxSkewMs` muss eine Zahl ≥ 0 sein (`Infinity` erlaubt). Nur `undefined` zählt als „nicht angegeben“.
Unbekannte Schlüssel in `options` werden nicht geprüft.

Die Optionen werden **einmal** gelesen und als eingefrorener Schnappschuss benutzt (`now` und `at` als
Millisekunden, die Nonce als Kopie): Ein Getter, der beim zweiten Lesen etwas anderes antwortet, kann keine
Prüfung ausschalten; ein `Date` wird genau einmal mit dem eingebauten `Date.prototype.getTime` gelesen, eine
überschriebene Methode `getTime` am Objekt wird nie aufgerufen; ein Getter oder Proxy, der wirft, ergibt `bad-options`. Es zählen nur **eigene**
Eigenschaften; was über `Object.prototype` vererbt wurde (auch durch Prototype Pollution), wird ignoriert.

**Eingaben werden kopiert, nie iteriert:** `buildTimestampRequest` und `verifyTimestampToken` kopieren Hash,
Nonce und Token genau einmal in einen eigenen `ArrayBuffer`. Die Länge kommt vorher aus dem eingebauten
`length`-Getter der typisierten Arrays (nicht aus einer überschriebenen Eigenschaft) und wird gegen die Grenze
geprüft, bevor etwas angelegt oder kopiert wird (Token höchstens 262 144 Byte, sonst `too-large`; Nonce 1 bis 16,
Hash 32 Byte); kopiert wird mit `TypedArray.prototype.set`, nie über `Symbol.iterator` (ein überschriebener,
endloser Iterator wird nicht aufgerufen). Ein Token in einem `SharedArrayBuffer` ist deshalb gültig, und ein Puffer,
den der Aufrufer nach dem Aufruf leert oder ändert, ändert das Ergebnis nicht. `trust` wird über `length` und
Index gelesen (jeder Eintrag einmal, nie über den Iterator); mehr als 64 Einträge sind `bad-options`, geprüft
bevor ein Eintrag gelesen wird.

**Feindliche Proxys:** `buildTimestampRequest`, `verifyTimestampToken`, `equalBytes` und `signRelayRequest` lesen ihre Eingaben
höchstens einmal (der Prototyp eines Proxys wird je Argument höchstens einmal erfragt, auch beim Token; die Länge kommt aus dem
eingebauten Getter, den ein Proxy nie besteht: `equalBytes` vergleicht nur echte `Uint8Array`, ein Proxy ist immer `false`) und fangen jeden Wurf ab (ein `Proxy`, dessen `getPrototypeOf`- oder `get`-Falle wirft): Ergebnis ist ein Code
(`bad-hash`, `bad-nonce`, `bad-options`, `malformed`) bzw. `false`, nie eine Ausnahme oder ein abgelehntes
Versprechen. Das gilt auch für `signRelayRequest` (getestet: Proxy als Eingabe, Schlüssel und Körper, werfender
`globalThis.crypto`; Ergebnis ein Code); die Bausteine `readToken`, `parseCertificate` und
`parsePemCertificates` werfen einen `ReaderError`, die Byte-Schreiber (`toBase64`, `toBase64Url`, `toHex`) einen
`TypeError` (auch für einen Proxy, dessen Falle wirft: er ist kein echtes `Uint8Array`).

**Bytes aus einem anderen Realm** (iframe, Worker, `vm`): Ein `Uint8Array` von dort besteht den
`instanceof`-Test nicht und ergibt `bad-hash` bzw. `bad-options`. Der Aufrufer übergibt dann eine Kopie im
eigenen Realm: `new Uint8Array(x)`. Im Einzelnen: Ein Token aus einem anderen Realm ergibt `malformed`,
`expectedNonce` ergibt `bad-options`, die Nonce bei `buildTimestampRequest` ergibt `bad-nonce`.
`readTimestampResponse` und `readToken` prüfen kein `instanceof` und nehmen Bytes aus einem anderen Realm an.

**Reihenfolge der Eingabeprüfungen:** `verifyTimestampToken` prüft Hash, Token-Größe und -Typ, Optionen und
`trust` und liest dann erst das Token; diese Reihenfolge ist nicht zugesichert. Wer mehrere Eingaben falsch
übergibt, sieht irgendeinen der Codes.

Unerwartetes, das nicht eindeutig gelesen werden kann, wird abgelehnt und nie als gültig durchgelassen; die
Prüfung beantwortet im Zweifel mit einem Fehlercode.

Beim Aufbau der Kette werden alle brauchbaren Zertifikate mit passendem Namen und gültiger Signatur als
Aussteller probiert (begrenzt: Tiefe 6, das sind höchstens 5 Zwischenzertifikate und `chainLength` höchstens 7 mit dem Anker; höchstens 8 brauchbare Kandidaten je Schritt, höchstens 64
Signaturprüfungen für die ganze Suche, dazu die eine Prüfung der Signatur des Zeitstempel-Zertifikats; ein Token
trägt höchstens 16 Zertifikate). Die
billigen Prüfungen kommen vor der Signaturprüfung: Ein namensgleiches Zertifikat mit unbekannter kritischer
Erweiterung, abgelaufener Gültigkeit oder ohne CA-Recht (kein `keyCertSign`) zählt **weder** gegen die 8
Kandidaten **noch** gegen die 64 Signaturprüfungen. Ein Token mit dem echten Zwischenzertifikat und beliebig
vielen solchen Zwillingen (bis zur Grenze von 16 Zertifikaten im Token) bleibt also gültig. Es führt auch nie zu
einer Annahme, die ohne es nicht gälte, denn jeder Kandidat muss dieselben Prüfungen bestehen.

**Fehlergrund:** Er wird erst nach erfolgloser Gesamtsuche ermittelt, mit einem **eigenen** Budget von höchstens
4 zusätzlichen Signaturprüfungen; die Suche selbst gibt dafür nichts her, ein Zweig nimmt einem Geschwisterzweig
also nichts weg. Gemeldet wird der Grund des **ersten** gescheiterten Zweigs (Reihenfolge: Anker, dann die
Zertifikate im Token): bei lauter unbrauchbaren Kandidaten der Grund des ersten unter den ersten 4, der den
Schritt tatsächlich signiert hat; ein brauchbarer Kandidat, dessen Weiterführung scheitert, hat Vorrang. Ist die
Suche an einer Grenze gescheitert (ein brauchbarer Kandidat blieb wegen der 8 Kandidaten oder der 64
Signaturprüfungen ungeprüft, in **irgendeinem** Zweig, auch wenn ein anderer Zweig einen genaueren Grund hätte) oder
trägt keiner der geprüften unbrauchbaren Kandidaten die Signatur, lautet der Grund `untrusted-chain`, nicht ein
genauerer.

**Restproblem (Verfügbarkeit, nicht Sicherheit):** Das Feld `certificates` im Token ist nicht signiert. Wer
das Token verändern kann, darf Zertifikate hinzufügen, die gültig aussehen (CA, `keyCertSign`, gültig, gleicher
Name und Schlüssel wie das echte Zwischenzertifikat), aber nicht vom echten Aussteller signiert sind. Sie
werden nie angenommen, belegen aber Kandidatenplätze: 8 solche Zertifikate vor dem echten Zwischenzertifikat
verstecken es (`untrusted-chain`), und ein verzweigtes Geflecht aus ihnen (höchstens 16 Zertifikate im Token)
verbraucht die 64 Signaturprüfungen. Ein gültiges Token kann so unprüfbar gemacht werden, aber nie ein
ungültiges gültig. Wer das Token vor Veränderung schützt oder die Zwischenzertifikate selbst als Anker
übergibt, ist davon nicht betroffen.

**Selbstsigniertes Zeitstempel-Zertifikat:** Ist das Zertifikat des Signierers selbstsigniert und nicht selbst
einer der übergebenen Anker, ergibt das `untrusted-chain` (früher `not-a-ca`). Ist es als Anker übergeben,
gilt es.

## Bewusst streng

- **Negative Seriennummer:** Ein Zertifikat mit negativer Seriennummer (auch ein mitgegebener Anker) wird nicht
  gelesen. In einer Ankerliste macht das die ganze Liste ungültig (Grund `malformed`; ein Anker bleibt
  Eingabe des Aufrufers und wird streng gelesen). Das ist gewollt (RFC 5280 verlangt positive Seriennummern) und wird
  nicht aufgeweicht; ein solcher Anker muss vom Aufrufer ausgetauscht werden. Eine negative Seriennummer im
  Unterzeichner-Eintrag (`sid`) des Tokens macht das Token `malformed`.
- **Unlesbare Zusatzzertifikate im Token** (Lesefehler jeder Art: negative Seriennummer, EC mit ausdrücklichen
  Kurvenparametern, Bruchteil in der Gültigkeit, kaputte Struktur) lassen das Token **nicht** scheitern: Sie
  werden übersprungen, sind nie Kandidat und werden nur gezählt (`skippedCertificates` von `readToken`; sie zählen
  zur Grenze von 16 Zertifikaten). Ist das Zertifikat des Unterzeichners selbst unlesbar, fehlt es:
  `signer-certificate-missing`. Fehlt dadurch ein Zwischenzertifikat der Kette, ist der Grund `untrusted-chain` (die
  genauere Ursache, z. B. `bad-time`, wird dann nicht gemeldet). Anker und Unterzeichner-Eintrag bleiben streng.

## Langzeitaussage

Geprüft wird die Kette **zur `genTime`** des Tokens (und, wenn gegeben, zu `at`), nicht zum Zeitpunkt der Prüfung.
Das Ergebnis nennt dazu `signerNotBefore` und `signerNotAfter`, die Gültigkeit des Zeitstempel-Zertifikats. Daraus
folgt ehrlich:

- Ein Token bleibt nicht beliebig lange „bewiesen“. Ein Zeitstempel-Zertifikat hat eine begrenzte Gültigkeit (bei
  den aufgezeichneten Token reicht sie bis 2036 bis 2040); **nach `signerNotAfter` oder nach Kompromittierung des Signierschlüssels** (die
  hier nicht erkannt wird, es gibt keine Sperrprüfung) verfällt die Beweiskraft: Wer den Schlüssel hat, kann Token
  mit beliebiger früherer `genTime` ausstellen, und ein altes Token lässt sich von einem solchen nicht
  unterscheiden. Dass die Bibliothek ein altes Token später noch „annimmt“, ist **kein** Beweis, dass es damals
  echt war.
- „Geprüft wird später mit denselben Mitteln“ gilt nur so: die **Rechnung** lässt sich wiederholen (Hash, Signatur,
  Kette zur `genTime`); die **Aussage** wird mit der Zeit schwächer. Wer eine lange Frist braucht, muss
  **rechtzeitig neu stempeln** (vor `signerNotAfter`, den Hash oder das alte Token mit einem frischen Stempel
  überdecken) und **mehrere Dienste** stempeln, damit der Ausfall oder die Kompromittierung eines Dienstes nicht alles
  entwertet. Langzeit-Validierung (LTV, Sperrinformationen und Zeitstempel über die Kette) bietet diese Bibliothek
  nicht.
- Ein frisch ausgestelltes Token prüft man mit `minGenTime` (s. „Frische“ oben), solange man weiß, wann man es
  angefordert hat; später nicht mehr.

## Solo-Stempel (Schlüsselart 2)

Ein Stempel mit `mode: "solo"` ist ein **gewöhnlicher Einzelstempel auf den Hash** (ohne Baum, ohne `batch`): er wird mit
`verifyTimestampToken` geprüft und hat alle Grenzen dieses Dokuments, aber **nicht** die des Belegs im Sammelbetrieb. Ob
ein Schlüssel ihn verlangen darf, entscheidet allein die Schlüsseldatei des Relays; die Bibliothek kennt keine
Schlüsselarten (`docs/relay.md`, „Schlüsselarten und Solo-Stempel“). Ein Solo-Schlüssel in einer Web-App ist für die
Nutzer dieses Browsers auslesbar.

## Beleg im Sammelbetrieb: was er aussagt und was nicht

`verifyBatchedTimestamp` prüft einen Stempel, den das Relay im Sammelbetrieb für viele Hashes zugleich beim Dienst
geholt hat (`docs/relay.md`, „Sammelbetrieb“). Sie rechnet das Blatt `SHA-256(0x00 ‖ Salz ‖ Hash)`, folgt dem Pfad
nach RFC 9162 (§ 2.1.3.2) bis zur Wurzel, bildet `SHA-256("zeitstempel-batch-v1\n" ‖ uint32be(Blattzahl) ‖ Wurzel)` und
prüft das Token mit `verifyTimestampToken` gegen diesen Wert (gleiche Anker, gleiche Optionen, gleiches Ergebnis).
Alles aus „Was geprüft wird“ und „Was NICHT geprüft wird“ gilt unverändert für das Token.

**Der Beleg sagt:** Der Hash lag **in der Menge**, die ein Zeitstempel-Zertifikat unter dem Anker zu `genTime` gestempelt
hat. Die Bindung ist hart: Blatt und innere Knoten sind durch die Präfixe `0x00` und `0x01` getrennt, die Pfadlänge
muss genau zu `size` und `index` passen, und die Blattzahl steckt im gestempelten Wert. Ein Pfad, der nicht zur
gestempelten Wurzel führt, ein anderes Salz, ein anderer Hash, `index` oder `size` und ein Token eines anderen
Baumes werden abgelehnt (`imprint-mismatch`, bei unmöglicher Form `bad-batch`).

**Der Beleg sagt nicht:**

- **Kein Einzelstempel auf den Hash.** Wer einen Stempel gerade auf diesen Hash braucht, nimmt den Einzelbetrieb.
- **Nicht, wer sonst in der Menge war.** Das Relay kann weitere Blätter in den Baum legen, und die Prüfung kann das
  nicht sehen; sie zeigt nur, dass dieses Blatt darin steht. Zurückdatieren oder einen Hash nachträglich aus einem
  gestempelten Baum nehmen kann es nicht.
- **Nichts ohne den ganzen Beleg.** Salz, `index`, `size` und Pfad gehören mit dem Hash und dem Token zusammen aufbewahrt;
  das Salz ist nicht aus dem Token wiederherstellbar. Ohne sie lässt sich der Stempel für diesen Hash nicht nachweisen.
- **Dasselbe wie ein einzelnes Token sonst auch nicht:** nicht qualifiziert, keine Sperrprüfung, Frische nur mit
  `minGenTime`, Langzeitaussage begrenzt (siehe die Abschnitte oben).
- **Vertraulichkeit:** der Dienst sieht nur den gestempelten Wert, ein anderer Einreicher nur verschleierte Knoten (das
  Salz ist 256 Bit lang); das Relay sieht die Hashes und zieht die Salze (`docs/relay.md`).
- Die Grenzen der Form: `size` 1 bis 1024, Pfad höchstens 10 Elemente zu je 32 Byte, Salz 32 Byte, ein unbekanntes Feld
  ist ein Fehler. Eine Eingabe aus einem anderen Realm wird wie bei den anderen Funktionen abgelehnt (`bad-hash`, `malformed`).

## Was ein bestandener Test aussagt

„Ein Dienst, dessen Zertifikatskette bei einem übergebenen Anker endet, hat bestätigt: diesen Hash gab es
spätestens zur angegebenen Zeit.“ Mehr nicht. Genauer: **„Ein Zeitstempel-Zertifikat unter einem der Anker hat
diese Aussage signiert“**; welcher Betreiber dahinter steht, sagt die Prüfung nicht (der Anker bestimmt nur die
Wurzel, nicht den einzelnen Dienst). Die mitgelieferten Anker sind Wurzeln: auch das Zeitstempel-Zertifikat einer anderen Stelle derselben Hierarchie
besteht. „Dienst X bestätigt“ ist stärker als das Geprüfte. Wer enger vertrauen will, übergibt selbst eine
Zwischen-CA oder den Signierer als Anker (die Anker-Ausnahme erlaubt das). Und die Aussage über die **Zeit** gilt nur, wenn die Frische geprüft wurde
(`minGenTime`) und das Zertifikat nicht kompromittiert war (s. „Langzeitaussage“).

- Die **Zeit stammt vom Dienst.** Die Bibliothek kennt keine eigene Zeitquelle; nur die Prüfung „nicht in der
  Zukunft“ (`now`) und, wenn der Aufrufer sie gibt, „nicht älter als“ (`minGenTime`) fangen grobe Abweichungen ab.
- Freie Dienste sind **nicht qualifiziert** (eIDAS). Der rechtliche Beweiswert ist begrenzt (siehe
  `docs/dienste.md`).
- Die Bibliothek prüft **nicht, was gestempelt wurde**: Sie bekommt nur den Hash. Dass der Hash zu den
  richtigen Daten gehört, muss die Anwendung sicherstellen.
- Mehrere Dienste für denselben Hash zu stempeln erhöht die Sicherheit gegen den Ausfall oder das Fehlverhalten
  eines Dienstes, wird hier aber nicht automatisch gemacht.

## Browser

Die Bibliothek verwendet nur Standard-Schnittstellen (WebCrypto, `Uint8Array`, `TextDecoder`), und ein
Wächter-Test sorgt dafür, dass im Kern keine Node-Importe stehen. Am 2026-11-23 lief sie zusätzlich in
**Headless-Chromium 157** (`node scripts/browser-check.mjs`): die vier aufgezeichneten Token wurden akzeptiert
(Signierer ECDSA P-384 bei FreeTSA, RSA-4096 bei den anderen), ein falscher Hash, ein falscher Anker und
veränderte Bytes wurden abgelehnt. Diese Prüfung lief ohne die Relay-Authentifizierung (`signRelayRequest`); sonst ist die Bibliothek im Browser nicht getestet. **Nicht geprüft:** Firefox, Safari, mobile Browser, `signRelayRequest` und der Aufruf des Relays mit Kopf. Auf einer Seite über
einfaches `http` (nicht `localhost`) fehlt `crypto.subtle`; die Prüfung antwortet dann `unsupported-signature`.
