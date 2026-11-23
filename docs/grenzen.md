# Was die Prüfung kann und was nicht

Stand: 2026-11-23. Die Bibliothek prüft ein Zeitstempel-Token nach RFC 3161. Diese Seite sagt ehrlich, was
**nicht** geprüft wird und wo die Aussage endet.

## Was geprüft wird

1. Das Token ist strikt gelesen: DER mit bestimmter Länge, kürzeste Längenform, begrenzte Größe und Tiefe.
2. Der bestätigte Hash (SHA-256) ist genau der erwartete.
3. Die Nonce stimmt, wenn eine erwartet wird.
4. Der Hash des Inhalts stimmt mit dem signierten Attribut überein, der Inhaltstyp ist `TSTInfo`.
5. Das Attribut zum Zeitstempel-Zertifikat (`signingCertificate` oder `signingCertificateV2`) passt zum
   verwendeten Zertifikat.
6. Die Signatur (RSA PKCS#1 v1.5 oder ECDSA P-256/P-384/P-521, mit SHA-256/384/512) stimmt.
7. Das Zeitstempel-Zertifikat erlaubt Zeitstempel (erweiterte Schlüsselverwendung, standardmäßig kritisch
   verlangt) und die Signatur-Verwendung.
8. Alle Zertifikate der Kette waren **zur bestätigten Zeit** gültig, die Aussteller sind
   Zertifizierungsstellen und erlauben das Ausstellen von Zertifikaten, und die Kette endet bei einem der
   übergebenen Anker.

Gegengeprüft wird mit `openssl ts -verify` an den aufgezeichneten Antworten von vier Diensten und beim
Schnelltest (`npm run spike`).

## Was NICHT geprüft wird

- **Sperrung (Revocation):** Es wird weder OCSP noch eine Sperrliste ausgewertet. Ein später gesperrtes
  Zertifikat erscheint weiterhin gültig. Die Prüfung gilt für die Zeit der Bestätigung; für Langzeitnachweise
  bräuchte man zusätzlich Sperrinformationen zum damaligen Zeitpunkt (Langzeit-Validierung, LTV).
- **Namens- und Pfadbeschränkungen** der Zertifikate (NameConstraints, pathLenConstraint) werden nicht
  ausgewertet; die Länge der Kette ist begrenzt (6).
- **Zertifikatsrichtlinien** (Policy-OIDs): Die Richtlinie des Tokens wird gemeldet, aber nicht gegen eine
  Erwartung geprüft.
- **Nicht unterstützt:** RSA-PSS, SHA-1 als Hash des Abdrucks oder der Signatur, BER (nur DER), andere
  Hashverfahren als SHA-256 für den Abdruck, Token ohne `certReq` (das Zeitstempel-Zertifikat muss im Token
  liegen). Das sind abgelehnte Fälle, keine stillen Annahmen.
- **Die Anker selbst:** Wem man vertraut, entscheidet der Aufrufer. Die mitgelieferten Anker stammen aus
  einem Zertifikatspaket und der Seite von FreeTSA; ihre Fingerabdrücke sind in `docs/dienste.md`
  aufgeführt, aber nicht mit den Betreibern abgeglichen.

## Was ein bestandener Test aussagt

„Ein Dienst, dessen Zertifikatskette bei einem übergebenen Anker endet, hat bestätigt: diesen Hash gab es
spätestens zur angegebenen Zeit.“ Mehr nicht.

- Die **Zeit stammt vom Dienst.** Die Bibliothek kennt keine eigene Zeitquelle; nur die Prüfung „nicht in der
  Zukunft“ (mit einer vom Aufrufer gelieferten Uhr) fängt grobe Abweichungen ab.
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
veränderte Bytes wurden abgelehnt. **Nicht geprüft:** Firefox, Safari, mobile Browser. Auf einer Seite über
einfaches `http` (nicht `localhost`) fehlt `crypto.subtle`; die Prüfung antwortet dann `unsupported-signature`.
