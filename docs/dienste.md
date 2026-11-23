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

Die Fingerabdrücke sollte ein Mensch gegen die Veröffentlichung des jeweiligen Betreibers abgleichen,
bevor die Anker für echte Nachweise benutzt werden (das ist hier nicht geschehen).
FreeTSA stellte am 2026-03-16 auf ein neues Zeitstempel-Zertifikat mit ECDSA P-384 um (laut ihrer Seite);
das alte ist abgelaufen. Die Prüfung nutzt immer das Zertifikat aus dem Token.

## Nutzungsbedingungen (ehrlich: nicht geklärt)

- **FreeTSA:** Die Seite verweist auf eine Nutzungsrichtlinie, die am 2026-11-23 nicht abrufbar war, und
  bittet, den Dienst nicht zu missbrauchen. Das Intervall von 15 s im Relay ist eine vorsichtige Annahme.
  Keine Zusage zu Verfügbarkeit oder rechtlicher Wirkung.
- **Sectigo, DigiCert:** Öffentliche Dienste, gedacht für das Zeitstempeln von **signiertem Code**.
  Andere Nutzung ist nicht ausdrücklich angeboten; die Bedingungen wurden nicht geprüft. Für den
  Dauerbetrieb einer Anwendung ist das **nicht** vertretbar, ohne vorher den Betreiber zu fragen.
- **Certum:** Öffentlicher Dienst einer Zertifizierungsstelle, Umfang hier nicht dokumentiert.
- Geprüft und **nicht aufgenommen**: `timestamp.apple.com` (Code-Signierung für Apple-Entwickler),
  `zeitstempel.dfn.de` (Dienst des DFN-Vereins für dessen Nutzerkreis); beide antworteten, ihre Bedingungen
  passen aber nicht. `timestamp.globalsign.com` und `tsa.mesign.com` antworteten mit 403,
  `tsa.swisssign.net` mit einer Weiterleitung.

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
