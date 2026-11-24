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

Punkt 9 ist **strenger als `openssl ts -verify`**, der eine solche Zwischen-CA annimmt; die Regel folgt der
Praxis der Browser (Verschachtelung der erweiterten Schlüsselverwendung entlang der Kette). Eine Zwischen-CA nur
für Codesignatur oder nur für Server-Authentifizierung kann also keinen Zeitstempel-Signierer ausstellen.

**Strenger als `openssl ts -verify`** (jeweils eine falsche Ablehnung möglich, nie eine falsche Annahme):

- Punkt 9 (erweiterte Schlüsselverwendung einer Zwischen-CA, s. o.).
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
Unterzeichner-Eintrag (`sid`) gegen das Zeitstempel-Zertifikat. Eine lockerere Namensübereinstimmung macht die
Grenzen nicht leichter erreichbar: Ein Zwilling, der sich nur in der Schreibweise unterscheidet, zählt wie ein
namensgleicher gegen die 8 Kandidaten und die 64 Signaturprüfungen (Zwillinge ohne CA-Recht usw. kosten weiter nichts).

**Lockerer als `openssl ts -verify`** (eine falsche Annahme gegenüber openssl, die Entscheidung der Bibliothek
folgt dem RFC):

- **Zusätzliche `keyUsage`-Bits** des Signierers (Punkt 7, s. o.).
- **Gültigkeit inklusive:** Die Gültigkeit eines Zertifikats schließt `notBefore` und `notAfter` ein (RFC 5280
  § 4.1.2.5). Ist die Stempelzeit genau `notAfter`, gilt das Zertifikat noch; `openssl` 3.0.13 lehnt in diesem
  Fall ab.
- **Nicht gelesene Felder:** `crls` im SignedData und der Inhalt der TSTInfo-Felder `[0]` (`tsa`) und `[1]`
  (Erweiterungen) werden nur auf das Tag geprüft, nicht gelesen; Müll darin wird angenommen. Das hat keine
  Auswirkung auf die Entscheidung (`crls` sind nicht signiert und werden nicht benutzt, die Felder werden nicht
  ausgewertet), das Token ist dort aber verformbar.

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
  wird nicht abgelehnt; das Feld `tsa` wird nicht gegen den Namen des Signierers geprüft; der Wertebereich von
  `accuracy` (Sekunden, Milli-, Mikrosekunden) wird nicht auf die Grenzen aus RFC 3161 geprüft; die Parameter der
  `AlgorithmIdentifier` werden nicht ausgewertet (die OID legt das Verfahren fest). Das RSA-Padding prüft nicht
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
