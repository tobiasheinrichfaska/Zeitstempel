# Zeitstempel-Dienste

Stand: 2026-11-23. Alle Zahlen sind **gemessen** (`npm run spike`, `npm run probe`), von einem Rechner in
Deutschland aus, mit dem SHA-256 eines kurzen Testtexts. Jeder Dienst bekam je Lauf **eine** Anfrage.

## Messung

| Dienst                       | Adresse                         | Übertragung  | Antwortzeit            | Kette (Zertifikate bis Anker) | Eigene Prüfung | openssl `ts -verify` |
| ---------------------------- | ------------------------------- | ------------ | ---------------------- | ----------------------------- | -------------- | -------------------- |
| FreeTSA                      | `https://freetsa.org/tsr`       | https        | 697 ms (Probe: 738 ms) | 2                             | OK             | OK                   |
| Sectigo Public Time Stamping | `https://timestamp.sectigo.com` | https        | 206 ms                 | 4                             | OK             | OK                   |
| DigiCert Timestamp           | `http://timestamp.digicert.com` | **nur http** | 398 ms                 | 3                             | OK             | OK                   |
| Certum Timestamp             | `http://time.certum.pl`         | **nur http** | 220 ms                 | 3                             | OK             | OK                   |

- DigiCert über `https://` lief in einen Timeout (8 bis 15 s), Certum über `https://` kam nicht zustande
  (Verbindungsfehler). Beide werden deshalb über `http://` angesprochen. Das Token ist signiert; `http`
  schützt nicht die Echtheit, aber die Vertraulichkeit der Anfrage (nur ein Hash) geht verloren. Das Relay
  verwendet solche Dienste nur, wenn `RELAY_ALLOW_PLAIN_HTTP=1` gesetzt ist.
- Die Antwortzeiten sind einzelne Messungen, keine Statistik und kein Versprechen der Dienste.
- Die Zeit in den Token stimmte bei allen vier Diensten auf die Sekunde mit der Zeit der Anfrage überein.

## Vertrauensanker

Die Anker liegen als Dateien unter `anchors/`; **wer ihnen vertraut, entscheidet der Betreiber** (die
Bibliothek bekommt sie als Parameter). Herkunft und Fingerabdruck (SHA-256):

| Datei                             | Herkunft                                                                    | Fingerabdruck                                                                                   | gültig bis |
| --------------------------------- | --------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | ---------- |
| `freetsa-root.pem`                | `https://freetsa.org/files/cacert.pem`                                      | A6:37:9E:7C:EC:C0:5F:AA:3C:BF:07:60:13:D7:45:E3:27:BB:BA:A3:8C:0B:9A:F2:24:69:D4:70:1D:18:AA:BC | 2041-03-07 |
| `usertrust-rsa.pem`               | Zertifikatspaket von Git for Windows (Stand 2026-11-23), Wurzel von Sectigo | E7:93:C9:B0:2F:D8:AA:13:E2:1C:31:22:8A:CC:B0:81:19:64:3B:74:9C:89:89:64:B1:74:6D:46:C3:D4:CB:D2 | 2038-01-18 |
| `digicert-trusted-root-g4.pem`    | dasselbe Paket                                                              | 55:2F:7B:DC:F1:A7:AF:9E:6C:E6:72:01:7F:4F:12:AB:F7:72:40:C7:8E:76:1A:C2:03:D1:D9:D2:0A:C8:99:88 | 2038-01-15 |
| `certum-trusted-network-ca-2.pem` | dasselbe Paket                                                              | B6:76:F2:ED:DA:E8:77:5C:D3:6C:B0:F6:3C:D1:D4:60:39:61:F4:9E:62:65:BA:01:3A:2F:03:07:B6:D0:B8:04 | 2046-10-06 |

**Abgleich (2026-11-23):** Die Fingerabdrücke (`openssl x509 -fingerprint -sha256`, über das DER-Zertifikat) wurden
mit öffentlichen Betreiberseiten und dem System-Trust-Store abgeglichen (Netzabgleich, keine Rückfrage bei den
Betreibern, keine menschliche Prüfung). Ergebnis je Anker:

| Anker                             | Quelle des Abgleichs                                                                                                  | Ergebnis                                                                               | Gültig bis | Vorbehalt                                                                                                                                                           |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `freetsa-root.pem`                | `https://freetsa.org/files/cacert.pem` und Seite `https://freetsa.org/index_en.php`                                   | Datei bytegleich; der SHA-256 auf der Seite passt zur Datei                            | 2041-03-07 | Seite und Datei vom selben Betreiber (keine unabhängige Zweitquelle); der Seitenwert ist der Hash der PEM-Datei, nicht des Zertifikats; nicht im System-Trust-Store |
| `usertrust-rsa.pem`               | `http://crt.sectigo.com/USERTrustRSACertificationAuthority.crt` (Link der Sectigo-Seite); System-Trust-Store          | Fingerabdruck des Downloads und des Stores gleich                                      | 2038-01-18 | Download nur über http; Sectigo nennt keinen Fingerabdruck im Text                                                                                                  |
| `digicert-trusted-root-g4.pem`    | `https://knowledge.digicert.com/general-information/digicert-trusted-root-authority-certificates`; System-Trust-Store | SHA-256 und SHA-1 der Betreiberseite und des Stores gleich                             | 2038-01-15 | Seitenwerte über ein Abrufwerkzeug gelesen (SHA-256 dort wörtlich)                                                                                                  |
| `certum-trusted-network-ca-2.pem` | `https://repository.certum.pl/ctnca2.cer`; System-Trust-Store; SHA-1 gegen Mozilla-Bugzilla                           | Fingerabdruck des Downloads und des Stores gleich; SHA-1 gleich der Angabe bei Mozilla | 2046-10-06 | nur der Download aus dem Betreiber-Repository ist die Betreiberquelle                                                                                               |

Der System-Trust-Store ist das Mozilla-Bundle von Debian (`ca-certificates`); CCADB wurde nicht direkt abgerufen.
Alle vier Anker sind selbstsigniert, RSA 4096 und über zehn Jahre gültig. Offen bleibt der Abgleich durch einen
Menschen und die Rückfrage bei den Betreibern, bevor die Anker für echte Nachweise benutzt werden.
FreeTSA stellte am 2026-03-16 auf ein neues Zeitstempel-Zertifikat mit ECDSA P-384 um (laut ihrer Seite);
das alte ist abgelaufen. Die Prüfung nutzt immer das Zertifikat aus dem Token.

## Nutzungsbedingungen (Stand 2026-11-23)

**Nicht rechtlich geprüft, Betreiber nicht gefragt.** Gelesen wurden nur öffentlich abrufbare Seiten (am
2026-11-23); gesendet wurde nichts an die Dienste außer den Testanfragen. Das ist keine Rechtsberatung und keine
Zusage der Betreiber.

| Dienst   | Beliebige Hashes (nicht nur Code-Signing)? | Ratenlimit (öffentlich)               | Verfügbarkeit / Haftung                                  | Rechtswirkung               |
| -------- | ------------------------------------------ | ------------------------------------- | -------------------------------------------------------- | --------------------------- |
| FreeTSA  | erlaubt, auch kommerziell                  | 1 Anfrage/s je IP                     | "best-effort", kein SLA                                  | nicht geregelt              |
| Sectigo  | unklar (Seite beschreibt nur Code-Signing) | Bitte um 15 s Pause zwischen Anfragen | nichts für den freien Endpunkt                           | eIDAS nur über `/qualified` |
| DigiCert | unklar (keine Bedingungen gefunden)        | keines genannt                        | nichts genannt                                           | nicht geregelt              |
| Certum   | unklar, wahrscheinlich vertragspflichtig   | keines genannt                        | 24/7 gegenüber Vertragskunden zugesagt; Haftung begrenzt | nicht geregelt              |

- **FreeTSA** (`https://freetsa.org/freetsa.html`): "a maximum of one timestamping request per second per IP
  address is permitted"; "Timestamps issued by FreeTSA may be used for commercial purposes"; "provided on a
  best-effort basis, without any guarantee of availability". Gespeichert werden nur IP-Adressen (Missbrauchs-
  erkennung), keine Hashes. Mehr Last gegen Spende (eigene Instanz). Nicht geregelt: Haftung, Rechtswirkung.
  **Das Relay ist eine einzige IP: das Limit gilt für alle Nutzer des Relays zusammen.** Das Intervall von 15 s in
  `services.json` ist strenger als nötig (belegt wären 1 s, besser mit Reserve); geändert wurde es hier nicht.
- **Sectigo** (`https://www.sectigo.com/resource-library/time-stamping-server`, Seite von 2018): bittet um
  "a delay of 15 seconds or more" zwischen Anfragen; beschreibt nur Code-Signing, ohne Nutzung für anderes zu
  verbieten; für eIDAS verweist sie auf `/qualified`, der freie Endpunkt ist also nicht qualifiziert. Ausdrückliche
  Bedingungen, Verfügbarkeit oder Haftung für den freien Endpunkt fanden wir nicht (Relying Party Agreement und
  TSPPS nicht gelesen).
- **DigiCert** (`https://knowledge.digicert.com/general-information/rfc3161-compliant-time-stamp-authority-server`):
  nennt die Adresse ohne jede Bedingung (nur Signieren mit Authenticode); in der Rechtsablage steht keine
  Zeitstempel-Richtlinie. Nutzung außerhalb des Code-Signings ist weder erlaubt noch verboten dokumentiert.
- **Certum** (Politik des Zeitstempeldienstes v1.7, polnisch, von uns übersetzt): nennt als Einsatz auch
  archivierte Daten und Transaktionen, befreit aber nur Microsoft Authenticode von Lizenzgebühr und
  Vertragspflicht und kündigt gegenüber Nutzern ohne passenden Vertrag Schadensersatzforderungen an; Haftung
  höchstens 20 000 zł. Daher ist für andere Nutzung wahrscheinlich ein Vertrag nötig. Die allgemeinen
  Bedingungen (Anhang 1) und die Zertifizierungsrichtlinie wurden nicht gelesen.
- **Alle vier** sind nicht qualifiziert.
- Geprüft und **nicht aufgenommen**: `timestamp.apple.com` (Code-Signierung für Apple-Entwickler),
  `zeitstempel.dfn.de` (Dienst des DFN-Vereins für dessen Nutzerkreis); beide antworteten, ihre Bedingungen
  passen aber nicht. `timestamp.globalsign.com` und `tsa.mesign.com` antworteten mit 403,
  `tsa.swisssign.net` mit einer Weiterleitung.

### Empfehlung (Entscheidung beim Betreiber)

**FreeTSA ist der einzige Dienst mit ausdrücklich erlaubter allgemeiner Nutzung** (auch kommerziell, mit dem
Limit von 1 Anfrage/s je IP). Sectigo, DigiCert und Certum nur nach Rückfrage beim Betreiber und nicht für den
Dauerbetrieb einer Anwendung.

### Offene Fragen an die Betreiber

- **FreeTSA:** Wie lange bleiben Zertifikate und Token prüfbar? Ist die Bündelung mehrerer Apps über eine
  Relay-IP gewollt? Was gilt bei Haftung und Rechtswirkung?
- **Sectigo:** Darf der freie Endpunkt für beliebige Hash-Zeitstempel genutzt werden? Gilt die 15-s-Pause je IP
  oder insgesamt? Gibt es eine Verfügbarkeits- oder Haftungsregelung? Gilt das Relying Party Agreement dafür?
- **DigiCert:** Ist Nutzung außerhalb des Code-Signings erlaubt? Gibt es Limits? Warum nur http? Gelten
  Relying Party Agreement und Limited Warranty für diese Token?
- **Certum:** Ist `time.certum.pl` für beliebige Hash-Zeitstempel ohne Vertrag nutzbar? Gibt es ein Ratenlimit?
  Was steht in Anhang 1 und in der Zertifizierungsrichtlinie? Warum kein https?

## Was ein Nachweis damit wert ist

Alle vier Dienste sind **nicht qualifiziert** im Sinne der eIDAS-Verordnung. Ein solcher Zeitstempel zeigt
technisch, dass ein Hash zu dem Zeitpunkt existierte, den der Dienst bestätigt. Seinen **rechtlichen
Beweiswert** (insbesondere die Vermutung der Richtigkeit, die ein qualifizierter Zeitstempel hat) hat er
nicht; das ist eine Frage für die Rechtsberatung, nicht für diesen Code.

## Vorlage für einen qualifizierten Dienst

Ein qualifizierter Zeitstempeldienst ist ein **Vertrag** mit einem Vertrauensdiensteanbieter (Zugang,
Preis, Bedingungen) und braucht meist eine Anmeldung (Benutzer und Passwort oder Zertifikat). Davon liegt
**nichts** in diesem Repo. Der Eintrag in `services.json` sähe so aus (Platzhalter, nicht lauffähig):

```json
{
  "id": "mein-dienst",
  "name": "Name des Anbieters",
  "url": "https://tsa.example/rfc3161",
  "hash": "sha256",
  "anchors": ["anchors/anbieter-wurzel.pem"],
  "qualified": true,
  "minIntervalMs": 1000,
  "intendedUse": "Vertragsgegenstand laut Vertrag",
  "terms": "Vertrag Nr. … (nicht im Repo)"
}
```

Offen: Das Relay kann **keine Anmeldung** gegenüber dem Dienst. Sie müsste aus der Umgebung des Betreibers
kommen (nie aus dem Repo) und ist ein eigener Schritt, wenn ein Vertrag besteht.

## Selbst nachmessen

```bash
npm run spike                       # eine Anfrage je Dienst, Tabelle wie oben
npm run probe -- --service freetsa  # eine Anfrage über das Relay (im selben Prozess)
```
