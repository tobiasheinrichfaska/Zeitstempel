# Client

`zeitstempel/client` ist der fertige Client für ein Relay (`docs/relay.md`): Er signiert die Anfrage, sendet sie, liest die
Antwort, **prüft das Token selbst** und gibt nur dann einen **Beleg** (`evidence` Fassung 1) zurück. Der Beleg ist ein
festes, versioniertes JSON-Format und lässt sich später ohne das Relay und ohne Netz prüfen (`verifyEvidence`).

- **Zweiter Einstiegspunkt:** `import { createRelayClient, verifyEvidence } from 'zeitstempel/client'`. Der Haupteinstieg
  `zeitstempel` kennt ihn nicht und bleibt frei von `fetch`.
- Browser und Node, nur Standard-APIs (`fetch`, WebCrypto, `AbortSignal`): kein `node:`, kein `Buffer`, kein `process`
  (Wächter-Test und ESLint). `fetch`, Uhr und Zufall sind Parameter.
- Wie im Kern **wirft nichts**: Fehler sind Codes (`{ ok: false, reason }`). Status 0.1.0: nicht veröffentlicht, nicht
  von einem Menschen sicherheitsgeprüft; getestet unter Node gegen ein echtes Relay mit Stub-Dienst und im Browser nur in
  headless Chromium (Abschnitt „Im Browser getestet“; Firefox und Safari nicht).

## Schnellstart

```ts
import {
  createRelayClient,
  readEvidence,
  serializeEvidence,
  verifyEvidence,
} from 'zeitstempel/client';

const client = createRelayClient({
  relayUrl: 'https://relay.example',
  audience: 'https://relay.example', // genau die RELAY_AUDIENCE des Relays
  keyId: 'app-1', // Kennung aus der Schlüsseldatei des Relays
  privateKey, // PKCS#8-Bytes (Uint8Array) oder ein CryptoKey (darf nicht extrahierbar sein)
  trust: [ankerPem], // die Vertrauensanker (PEM-Texte): die Entscheidung der App
  services: ['freetsa', 'sectigo'], // Reihenfolge der Vorliebe; der zweite ist der Failover
});
if (!client.ok) throw new Error(client.reason);

const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', daten)); // 32 Byte
const stamped = await client.value.stamp(hash);
if (!stamped.ok) throw new Error(stamped.reason); // kein Beleg, nichts gestempelt
const text = serializeEvidence(stamped.value); // kanonischer JSON-Text zum Aufbewahren
if (!text.ok) throw new Error(text.reason);
await speichern(text.value);

// später, ohne Relay und ohne Netz:
const checked = await verifyEvidence(await laden(), hash, { trust: [ankerPem] });
if (checked.ok) console.log(checked.value.genTime); // der Hash existierte spätestens zu dieser Zeit
```

`stamped.value` ist der Beleg (ein einfaches Objekt); `serializeEvidence` macht daraus den Text, `readEvidence` liest
Text oder Objekt streng zurück. Dieses Beispiel läuft als Test (`tests/client.test.ts`, „the readme example“).

## Optionen von `createRelayClient`

Jede Option wird einmal gelesen und kopiert (ein Getter, ein Proxy, der wirft, eine Klasseninstanz oder ein unbekanntes Feld
ist `bad-options`). Die Fabrik macht keinen Netzaufruf und signiert noch nichts.

| Option              | Pflicht | Bedeutung                                                                                                                                                                                                 |
| ------------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `relayUrl`          | ja      | Ursprung des Relays, `https://relay.example`: kein Pfad, keine Abfrage, keine Zugangsdaten; `http` nur für `localhost`, `127.x.x.x`, `[::1]` (sonst `bad-options`)                                        |
| `audience`          | ja      | Die `RELAY_AUDIENCE` des Relays (druckbares ASCII ohne Leerzeichen, 1 bis 128 Zeichen)                                                                                                                    |
| `keyId`             | ja      | Schlüsselkennung (`[a-z][a-z0-9-]{0,31}`), sonst `bad-key-id`                                                                                                                                             |
| `privateKey`        | ja      | `Uint8Array` (PKCS#8, ECDSA P-256, 1 bis 256 Byte, wird kopiert) oder `CryptoKey`; sonst `bad-key`. Ob die Bytes wirklich einen P-256-Schlüssel ergeben, zeigt erst das Signieren (`bad-key` aus `stamp`) |
| `trust`             | ja      | Liste von 1 bis 64 PEM-Texten (`readServices` und `anchors/*.pem` des Dienstes liefern sie); ein Eintrag, der kein PEM ist: `bad-pem`                                                                     |
| `services`          | ja      | 1 bis 16 verschiedene Dienstkennungen in der Reihenfolge der Vorliebe                                                                                                                                     |
| `fetch`             | nein    | Vorgabe: das `fetch` der Umgebung. Der Client braucht davon `status`, `headers.get` und `text()`; er übergibt `redirect: 'error'`, `credentials: 'omit'`, `cache: 'no-store'`                             |
| `now`               | nein    | Uhr in Unix-Millisekunden, Vorgabe `Date.now`; liefert sie keine endliche Zahl, ist `stamp` `bad-options`                                                                                                 |
| `random`            | nein    | `(länge) => Uint8Array` für das `jti` (16 Byte), Vorgabe `crypto.getRandomValues`; wird bei **jedem** Versuch neu aufgerufen                                                                              |
| `timeoutMs`         | nein    | Gesamtfrist eines `stamp`-Aufrufs, 1000 bis 600000 ms, Vorgabe **130000**                                                                                                                                 |
| `maxAttempts`       | nein    | Sendungen je Dienst bei `429` und `503 busy`, 1 bis 10, Vorgabe 3                                                                                                                                         |
| `minGenTimeSlackMs` | nein    | Toleranz unter der Sendezeit, 0 bis 3600000 ms, Vorgabe 60000                                                                                                                                             |
| `maxClockOffsetMs`  | nein    | Größter Uhrversatz, den die App aus dem `Date` des Relays übernimmt, 0 bis 86400000 ms, Vorgabe 65000                                                                                                     |

`trust` sind **PEM-Texte** wie überall in der Bibliothek (`verifyTimestampToken`), nicht DER-Bytes.

## `stamp(hash, options?)`

`hash` ist der SHA-256 (32 Byte, `Uint8Array` dieses Realms, sonst `bad-hash`). `options`: `mode` (`'normal'` oder `'solo'`),
`signal` (`AbortSignal`), `service` (nur dieser Dienst, **kein** Failover; muss in `services` stehen).

Ablauf je Versuch: Kopf mit `signRelayRequest` signieren (neues `jti`, Zeit der — gegebenenfalls korrigierten — Uhr),
`POST /v1/stamp/<dienst>` mit `{"hash": "…"}` (bei `solo` zusätzlich `"mode": "solo"`, sonst nie), Antwort lesen:

1. `200`: Token und (bei `batch`) Beleg prüfen, **immer** mit `minGenTime` = Sendezeit − `minGenTimeSlackMs` und `now` = Uhr beim
   Empfang, gegen `trust`. Ein Token **für den Einzelstempel** wird mit `verifyTimestampToken` geprüft, eines mit `batch` mit
   `verifyBatchedTimestamp`. Eine `expectedNonce` gibt es nicht: die Nonce wählt das Relay, die Bindung an den Hash prüft
   `imprint-mismatch`. Besteht die Prüfung nicht, ist das Ergebnis der Code der Bibliothek (`untrusted-chain`, `time-too-old`,
   `imprint-mismatch`, …), **ohne Beleg und ohne Failover** (ein Token, das nicht besteht, ist kein Grund für einen anderen
   Dienst). Das `service` der Antwort muss der gefragte Dienst sein, sonst `bad-response`.
2. Alles andere siehe Fehlerbehandlung.

## Fehlerbehandlung

Fehler sind `{ ok: false, reason, detail?, status?, code? }`. `reason` ist ein Code der Bibliothek (Tabelle in
`docs/data-model.html`) oder einer der folgenden:

| `reason`        | Bedeutung                                                                                                                                                   |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `network-error` | `fetch` ist bei jedem versuchten Dienst fehlgeschlagen (keine Antwort)                                                                                      |
| `timeout`       | `timeoutMs` ist abgelaufen                                                                                                                                  |
| `aborted`       | das `signal` des Aufrufers hat abgebrochen (auch während des Wartens auf `Retry-After`)                                                                     |
| `relay-error`   | das Relay hat mit einem Fehler geantwortet: `status` (HTTP) und `code` (sein `error`, etwa `solo-not-allowed`); bei `502` steht dessen `reason` in `detail` |
| `bad-response`  | eine `200`-Antwort, die keine Antwort des Relays ist (kein JSON, falsche Form, andere Dienstkennung, Token nicht base64url, zu groß)                        |

Was der Client tut (`docs/relay.md`, Tabelle der Fehlercodes):

| Antwort                                                                                                                  | Verhalten                                                                                                                                                                                                                                             |
| ------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Netzfehler, `500`, `502`, `503` (nicht `busy`), `504`                                                                    | **Failover:** der nächste Dienst aus `services` (neue Signatur, neues `jti`). Sind alle durch, kommt der letzte Fehler zurück                                                                                                                         |
| `429`, `503` mit `busy`                                                                                                  | `Retry-After` abwarten (Sekunden, höchstens `timeoutMs`; fehlt er, 1 s), dann neu signieren und senden, **höchstens `maxAttempts` Sendungen je Dienst**, dann der Fehler. Würde das Warten die Gesamtfrist überschreiten, kommt der Fehler **sofort** |
| `401`                                                                                                                    | **Uhrabgleich**, einmal (nächster Abschnitt); bleibt es `401`, ist es der Schlüssel, die Kennung oder die Audience: Fehler, **kein Failover**                                                                                                         |
| `400`, `403` (`solo-not-allowed`, `service-not-allowed`, `origin-not-allowed`), `404`, `413`, `415` und alles Unbekannte | Fehler, **kein Failover** und keine Wiederholung: ein anderer Dienst ändert daran nichts                                                                                                                                                              |

`403 solo-not-allowed` heißt: der Schlüssel ist von der Art 1; `stamp(hash, { mode: 'solo' })` braucht einen Schlüssel der Art 2.
Der Client versteckt das nicht hinter einem normalen Stempel: ein `solo` ohne Solo-Beleg wäre eine andere Aussage. Antwortet ein
Relay auf `mode: 'solo'` mit einem Sammelbeleg (`batch`), ist das `bad-response` (`detail: 'mode'`); wer `mode` nicht angibt, wertet
`kind` des Belegs aus.

## Uhrabgleich

Das Relay verlangt, dass `ts` des Kopfes höchstens ±60 s von seiner Uhr abweicht. Bei `401` liest der Client den Kopf `Date` der
Antwort (das Relay gibt ihn auch bei `401` frei), bildet `versatz = Date − Uhr der App`, signiert **genau einmal** mit der
korrigierten Uhr neu und sendet. Genau einmal je `stamp`-Aufruf, nicht endlos; die Korrektur zählt nicht als Versuch von
`maxAttempts`. Hat die korrigierte Anfrage dann Erfolg (keine `401` mehr), **merkt der Client den Versatz** für die folgenden
Aufrufe; bleibt auch sie `401`, wird er verworfen.

**Grenze:** nur Versätze bis `maxClockOffsetMs` (Vorgabe 65 s, knapp über dem Fenster von ±60 s des Relays; ein ehrliches Relay braucht nicht mehr) werden übernommen. Grund: die korrigierte Uhr bestimmt auch
`minGenTime`; ein Relay, das ein falsches `Date` schickt, könnte sonst die Frischeprüfung beliebig verschieben und ein
rückdatiertes Token durchlassen. Mit der Grenze kann es sie höchstens um den Versatz plus `minGenTimeSlackMs` verschieben.
Eine Uhr, die um mehr abweicht, bleibt `401` (ein Wert für `maxClockOffsetMs` erlaubt mehr; wer ihn erhöht, vertraut dem `Date`
des Relays so weit). `receivedAtMs` im Beleg ist die korrigierte Uhr.

## Fristen

`timeoutMs` ist die Gesamtfrist **eines** `stamp`-Aufrufs über alle Versuche, Wartezeiten und Dienste. Die Vorgabe **130000 ms**
ist die sichere Obergrenze aus `docs/relay.md` („Latenz und Fristen“). Die Formel für **einen** Versuch ab Sendebeginn:

- **Einzelbetrieb:** `RELAY_MAX_WAIT_MS` + 17 s (Vorgabe 30 + 17 = 47 s)
- **Sammelbetrieb:** `RELAY_MAX_WAIT_MS` + Fenster + Kette + 17 s (Fenster = `RELAY_BATCH_MS`; Kette = `minIntervalMs` des Dienstes bei
  `RELAY_BATCH_MAX` über 60, sonst bis 60 s). Beispiele mit der Vorgabe 30 s: FreeTSA 30 + 5 + 5 + 17 = 57 s, ein 15-s-Dienst
  30 + 15 + 15 + 17 = 77 s, kleiner `RELAY_BATCH_MAX` bis 30 + 15 + 60 + 17 = 122 s
- **Solo:** `RELAY_MAX_WAIT_MS` + 17 s

Dazu kommt jeweils die Reserve für den Proxy (3 s). `timeoutMs` ist **keine** Frist je Dienst: hängt der erste Dienst bis zum
Ende der Gesamtfrist, bleibt für den Failover nichts. Wer mit Failover rechnet, setzt `timeoutMs` auf **mindestens die Summe
der Versuche**, die er zulassen will (Obergrenze 600000 ms), oder nutzt kürzere Relay-Einstellungen.

## Belegformat `evidence` v1

JSON-fähig (keine Funktionen, keine Bytes: base64url-Text), feste Feldreihenfolge im kanonischen Text:

```json
{
  "v": 1,
  "kind": "single",
  "service": "freetsa",
  "hash": "<base64url, SHA-256, 32 Byte>",
  "hashAlg": "sha256",
  "receivedAtMs": 1795000000000,
  "token": "<base64url, DER des TimeStampToken>",
  "policy": "1.2.3.4.1",
  "genTime": "2026-11-23T13:05:56.000Z",
  "signerNotAfter": "2035-04-11T00:00:00.000Z"
}
```

Bei `"kind": "batch"` steht nach `token` das Feld `batch` (`{ "v": 1, "size", "index", "salt", "path": [...] }`, **genau** die Form
der Relay-Antwort; `docs/relay.md`, „Antwort“), bei `single` darf es nicht stehen.

| Feld             | Regel                                                                                                          |
| ---------------- | -------------------------------------------------------------------------------------------------------------- |
| `v`              | genau die Zahl 1                                                                                               |
| `kind`           | `single` (das Token deckt den Hash; auch ein Solo-Stempel) oder `batch` (das Token deckt einen Baum)           |
| `service`        | Kennung wie in `services.json`                                                                                 |
| `hash`           | base64url, genau 32 Byte, nur die eine kanonische Schreibweise                                                 |
| `hashAlg`        | `sha256`                                                                                                       |
| `receivedAtMs`   | ganze Zahl, Millisekunden (1e11 bis unter 1e15): die Uhr der App beim Empfang; **nur eine Notiz**, kein Beweis |
| `token`          | base64url (**nicht** base64: so liefert es das Relay), 1 bis 262144 Byte                                       |
| `batch`          | nur bei `kind: batch`                                                                                          |
| `policy`         | optional, OID-Text, höchstens 128 Zeichen                                                                      |
| `genTime`        | ISO 8601 UTC mit Millisekunden; die Zeit aus der Prüfung beim Stempeln, **nicht** die Angabe des Relays        |
| `signerNotAfter` | optional, ISO 8601 UTC: Ende der Gültigkeit des Zeitstempel-Zertifikats, zum rechtzeitigen Neustempeln         |

`readEvidence(eingabe)` liest ein Objekt oder einen JSON-Text (höchstens 500000 Zeichen) streng in eine **frische Kopie**: jedes
Feld einmal über seinen Descriptor (ein Getter wird nie ausgeführt, ein werfender Proxy ist `bad-evidence`), unbekannte Felder,
eine andere Fassung als 1 und jede Verletzung der Tabelle sind `bad-evidence`, `detail` nennt das Feld. `serializeEvidence(beleg)`
schreibt den kanonischen Text (liest die Eingabe zuerst so); gleicher Beleg, gleicher Text, und `readEvidence` des Textes gibt
den Beleg zurück. Die Felder `policy`, `genTime`, `signerNotAfter` wiederholen nur, was die Prüfung ergab; `verifyEvidence`
vergleicht sie mit dem Ergebnis der neuen Prüfung.

## Prüfung später: `verifyEvidence`

```ts
const r = await verifyEvidence(beleg /* Objekt oder Text */, hash, {
  trust: [ankerPem],
  minGenTime, // wenn der Beleg nicht älter sein darf als …
  expectedPolicy: '1.2.3.4.1', // optional
  crls: [crlDer], // optional: Sperrlisten (DER), die die App selbst geholt hat; ohne sie keine Sperrprüfung
});
```

Reihenfolge: Optionen (`bad-options`; erlaubt sind `trust` und die Optionen von `VerifyOptions` außer `expectedNonce`, auch `crls`: Sperrlisten, die die App selbst liefert, Einzelheiten und Grenzen in `docs/grenzen.md` Punkt 16; ein Beleg mit `kind: batch` reicht sie ebenso an `verifyBatchedTimestamp` weiter) → Form
(`bad-evidence`) → der Hash des Belegs gegen den **übergebenen** Hash (`evidence-hash-mismatch`) → das Token
(`verifyTimestampToken`, bei `kind: batch` `verifyBatchedTimestamp`: alle bekannten Codes, bei einem Beleg für einen anderen Hash im
Baum `imprint-mismatch`) → Abgleich von `genTime`, `policy`, `signerNotAfter` (`bad-evidence`, wenn eines abweicht). Das Ergebnis trägt
die Werte der Prüfung (`VerifiedTimestamp`, bei `batch` `{ size, index }`) und, **ungeprüft**, die Angaben des Belegs `kind`, `service`
und `receivedAtMs`: das Token bindet weder die Dienstkennung noch die Empfangszeit, wer sie fälscht, ändert nur diese Notizen
(`kind` dagegen entscheidet über die Art der Prüfung und fällt bei einer falschen Angabe durch). Kein Netz, kein Relay.
Die **Frische** prüft nur, wer `minGenTime` angibt; die Aussage wird schwächer, wenn das Zeitstempel-Zertifikat abläuft oder sein
Schlüssel kompromittiert wird (`docs/grenzen.md`, „Langzeitaussage“): rechtzeitig neu stempeln, mehrere Dienste nutzen.

## Erneuerungskette: `renew` und `renewals`

Ein Beleg verliert Beweiskraft, wenn das Zeitstempel-Zertifikat abläuft oder sein Schlüssel kompromittiert wird (`signerNotAfter`,
`docs/grenzen.md`, „Langzeitaussage“). Die Abhilfe ist die **Erneuerungskette**: **vor** diesem Zeitpunkt wird der ganze Beleg neu gestempelt.
`client.renew(beleg)` stempelt dazu nicht den Hash, sondern `renewalImprint` (Bibliothek, `docs/data-model.html`):

```
imprint(i) = SHA-256( "zeitstempel-renewal-v1\n" ‖ SHA-256(Token des Glieds i-1) ‖ Stand(i-1) )
Stand(0) = der gestempelte Hash,  Stand(i) = imprint(i)
```

Glied 0 ist der ursprüngliche Stempel über den Hash, Glied i > 0 stempelt `imprint(i)`. Jeder Wert bindet damit den Hash, **alle** Token davor und
seinen unmittelbaren Vorgänger (feste Längen, nichts wird ausgelegt). Die Kette sagt: „dieser Hash existierte spätestens zu T0, und der Stempel
T0 existierte spätestens zu T1, und …“. Der Dienst sieht nur einen Hash, wie immer.

```ts
const erneuert = await client.renew(beleg); // beleg: Objekt oder Text; optionen wie bei stamp (mode, signal, service)
if (!erneuert.ok) throw new Error(erneuert.reason);
const text = serializeEvidence(erneuert.value); // der neue Beleg ersetzt den alten
const r = await verifyEvidence(erneuert.value, hash, { trust: [ankerPem] });
if (r.ok)
  console.log(
    r.value.genTime,
    r.value.renewalLinks,
    r.value.weakestLink,
    r.value.lastSignerNotAfter,
  );
```

**Format.** Der Beleg bekommt das **optionale** Feld `renewals` (Liste von 1 bis 63 Gliedern, ältestes zuerst, kanonisch das letzte Feld). Ein Glied
hat `kind, service, receivedAtMs, token, batch, policy, genTime, signerNotAfter` mit den Regeln der gleichnamigen Felder (Abschnitt „Belegformat“),
**keinen** eigenen `hash` (er folgt aus der Kette: ein gespeicherter könnte nur widersprechen), kein `v`. `readEvidence` liest streng: eine leere
Liste, ein unbekanntes Feld, ein `hash` im Glied sind `bad-evidence` (`detail` etwa `renewals[1].token`). Belege **ohne** `renewals` bleiben
unverändert gültig, les- und schreibbar (gleicher Text, gleiche Ergebnisse von `verifyEvidence`). Die Fassung bleibt 1: ein älterer Leser lehnt ein
unbekanntes Feld ab, statt die Kette zu übergehen.

**Ablauf von `renew`.** (1) Beleg streng lesen. (2) Die Kette **jetzt** prüfen (`now` und `at` = Uhr des Clients): ein Beleg, dessen Zertifikat
schon abgelaufen ist oder der sonst nicht besteht, wird **nicht** erneuert (der Fehlercode der Prüfung, nichts gesendet). (3) `renewalImprint`
über das Relay stempeln, mit allen Regeln von `stamp` (Pflicht-`minGenTime`, Uhrabgleich, `Retry-After`, Failover, jedes Token wird selbst geprüft;
es kann ein Einzelstempel oder ein Sammelbeleg sein). (4) Das Glied anhängen und die **ganze** neue Kette noch einmal prüfen: nur dann wird der Beleg
zurückgegeben (eine Erneuerung, die vor dem vorigen Stempel liegt, wäre `bad-renewal`). Mehr als 64 Glieder: `bad-renewal`. Der alte Beleg wird nicht
verändert.

**Prüfung.** `verifyEvidence` prüft bei vorhandenem `renewals` die Kette mit `verifyRenewalChain`: jedes Glied mit `verifyTimestampToken` (bei `batch`
`verifyBatchedTimestamp`) gegen seinen Wert, die Zertifikate eines Glieds **zur Zeit des nächsten Glieds** (`at`; beim letzten Glied zu `at`, sonst
`now`, sonst nur zur eigenen `genTime`), die Zeiten nicht fallend, `crls` je Glied durchgereicht, `minGenTime` nur für Glied 0, jede andere Option für
jedes Glied (`expectedNonce` gibt es nicht). Danach werden `genTime`, `policy`, `signerNotAfter` jedes Glieds mit der Prüfung verglichen
(`bad-evidence`, `detail` `renewals[i].feld`). Das Ergebnis trägt die Werte des **ursprünglichen** Stempels (`genTime`: der Hash lag spätestens dann vor) und
zusätzlich `renewalLinks` (Zahl der Erneuerungen), `weakestLink` (`{ index, marginMs }`: das Glied, dessen Zertifikat bei seiner Erneuerung am kürzesten
noch galt, also `signerNotAfter` minus Zeit des Nachfolgers; `null` ohne Erneuerung), `lastGenTime` und `lastSignerNotAfter` (**vor diesem Zeitpunkt**
wieder erneuern). Fehler tragen `detail` `link i` (die Nummer des ersten schlechten Glieds von vorn). Ein Glied, dessen Zertifikat zur Zeit der Erneuerung nicht
mehr galt, ist `renewal-too-late`; ein gesperrtes `revoked`; ein vertauschtes, doppeltes, fehlendes Glied oder eines, das einen anderen Vorgänger bindet,
`imprint-mismatch`; fallende Zeiten `bad-renewal` (`detail` `order i`).

**Wann erneuern.** Empfehlung: wenn `lastSignerNotAfter` in weniger als **30 Tagen** liegt (und bei Bedarf früher, wenn der Dienst sein Zertifikat ersichtlich
wechselt). Der Abstand zwischen `signerNotAfter` und der Erneuerung steht als `marginMs` je Glied im Ergebnis; ein Glied mit kleinem Abstand ist das
schwächste. Wer mehrere Dienste nutzt, erneuert über einen **anderen** Dienst als den des letzten Glieds (`service`): fällt ein Dienst oder sein Schlüssel
aus, hängt nicht die ganze Kette daran. Die Kette wird nicht von selbst erneuert; das Anwendungsprogramm entscheidet Zeitpunkt und Dienst.

**Ehrliche Grenzen.**

- Die Kette ist **so stark wie das schwächste Glied, soweit es rechtzeitig erneuert wurde**: jedes Glied muss zur Zeit seiner Erneuerung noch gültig gewesen
  sein, und die Aussage über die Zeit von Glied i + 1 stützt sich auf die Ehrlichkeit seines Dienstes **zu jenem Zeitpunkt**. Ein Dienst, der damals schon
  falsche Zeiten ausstellte, wird durch die Kette nicht entlarvt.
- Es bleibt die **Annahme**, dass die Dienste ihre Zeit wahrheitsgemäß angeben und ihre Schlüssel bis zur Erneuerung nicht an Dritte gingen. Ein Glied sagt „spätestens zu T“, nie „genau“.
- `crls` gehen unverändert an jedes Glied, und jede Liste muss zur jeweiligen Prüfzeit gültig sein (`thisUpdate` ≤ Zeit ≤ `nextUpdate`; die Zeit ist `at`, also
  die der Erneuerung, beim letzten Glied `now`): **eine** Liste von heute passt nur zum letzten Glied, ältere Glieder ergeben `bad-crl`. Wer Sperrlisten mit einer
  längeren Kette braucht, bewahrt die Listen der damaligen Zeit auf; sie sind nicht Teil des Belegs.
- `minGenTime` gilt nur für das erste Glied (die Frische der Erneuerungen sichert `renew` beim Stempeln); `expectedPolicy` gilt für **jedes** Glied (bei Diensten mit
  verschiedenen Richtlinien eine Liste übergeben).
- Der Beleg eines Baumstempels (`batch`) gehört nicht in den Wert der nächsten Erneuerung: die Wurzel im Token legt ihn fest.
- Der Beleg wächst mit jedem Glied (ein Token mit Zertifikaten hat rund 5 bis 8 KB); der Text ist auf 500000 Zeichen begrenzt, das reicht für etwa 50 Glieder.
- Kein rechtlicher Wert: die freien Dienste sind nicht qualifiziert (`docs/dienste.md`), eine Kette macht daraus keinen qualifizierten Zeitstempel und ist kein Evidence Record nach RFC 4998 / 6283 (der Export als solcher ist offen, `docs/weiterarbeit.md`).
- Nur unter Node gegen ein echtes Relay mit Stub-Dienst und gegen aufgezeichnete Token getestet, einzelne Glieder gegen `openssl ts -verify -attime`; **nicht** im Browser (`scripts/browser-check.mjs` kennt `renew` noch nicht) und mit keinem echten Dienst.

## Failover

Reihenfolge von `services`. Ein Dienst fällt aus der Reihe (Netzfehler, `500`, `502`, `503` außer `busy`, `504`), dann kommt der
nächste, mit neuer Signatur. Wer genau einen Dienst will, übergibt `service` (kein Failover). Einen Failover nach `400`, `401`
(nach der Korrektur), `403`, `413` oder `415` gibt es **nie**. Alle Dienste laufen über dasselbe Relay: das Relay selbst ist keine
Redundanz.

## Sicherheit

- **Der Schlüssel im Browser ist lesbar.** Ein privater Schlüssel in einer Web-App (ein Schlüssel im Browserspeicher, im Quelltext oder im Speicher) kann von
  den Besuchern der Seite gelesen werden; er hält andere Apps und Skripte fern, nicht die Nutzer der Seite. Mit einem nicht
  extrahierbaren `CryptoKey` (`crypto.subtle.importKey('pkcs8', bytes, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])`)
  wird er nicht lesbar, aber wer den Code der Seite ausführen kann, kann ihn **benutzen**. Für einen Schlüssel der Art 2 (Solo)
  gilt das besonders (`docs/relay.md`, „Warnung: Solo-Schlüssel im Browser“). Der Client kopiert die Schlüsselbytes beim Anlegen
  und hält sie nur im Speicher; er schreibt nichts in den Browserspeicher.
- **Vertrauen ist die Entscheidung der App** (`trust`). Der Client prüft jedes Token selbst, auch wenn das Relay es schon geprüft hat;
  ein Relay, das lügt, kann damit keinen Beleg erzeugen, den die App nicht selbst prüfen könnte.
- **Frische ist Pflicht** und hängt an der Uhr der App (und dem `Date` des Relays, begrenzt durch `maxClockOffsetMs`).
- Der Client sendet nur den Hash (und `mode`), nie Daten; `redirect: 'error'`, keine Cookies; kein Wort davon geht ins Protokoll
  (der Client protokolliert nichts). Keine Zugangsdaten für bezahlte Dienste (`upstream`): der Client kennt sie nicht.
- Nicht geprüft: Sperrung (außer in `verifyEvidence` mit selbst gelieferten Sperrlisten über `crls`; `stamp` und das Relay prüfen keine Sperrung, und auch mit Listen bleibt eine Sperrung nach der `genTime` ohne `keyCompromise` ohne Wirkung, `docs/grenzen.md` Punkt 16), die Aussage über Zeit vor dem Stempel, ob der Dienst qualifiziert ist (`docs/grenzen.md`, `docs/dienste.md`).

## Im Browser getestet

`node scripts/browser-check.mjs` (Teil C, nach `npm run build`) lädt `dist/client` in headless Chromium 157 über eine eigene Seite
und ruft echte Relays (Einzel- und Sammelbetrieb, Schlüsseldatei, Audience; Stub-Dienst) auf. Seite und Relay liegen auf
verschiedenen Ports von `127.0.0.1`: andere Origin (CORS mit Vorabfrage), aber dieselbe Site, damit ein Cookie der Seite bei
`credentials: 'include'` gesendet würde (eine Kontrollanfrage beweist das). Geprüft, 30 Prüfungen, alle bestanden:

- `stamp` im Einzelbetrieb (Schlüssel als Bytes): Beleg, `verifyEvidence`, `serializeEvidence`/`readEvidence` gleicher Text, derselbe
  Beleg prüft auch unter Node; falscher Hash `evidence-hash-mismatch`, veränderter Token und falscher Anker abgewiesen.
- Schlüssel als nicht extrahierbarer `CryptoKey` (erzeugt und aus PKCS#8-Bytes importiert).
- Sammelbetrieb (drei parallele Belege `batch`, ein Token, verschiedene Indizes, auch unter Node geprüft); Solo mit Schlüssel der Art 2
  (`kind: single`, kein `batch`); Solo mit Art 1: `relay-error` 403 `solo-not-allowed`.
- Uhrabgleich über eine Überschreibung von `Date.now` der Seite: ±30 s ohne Korrektur, ±62 s mit genau einer `401` und Korrektur
  (der Versatz wird gemerkt: zweiter Aufruf ohne `401`), ±70 s `relay-error` 401 ohne Wiederholung (Grenze 65 s).
- `Retry-After` bei `429` (mit `maxAttempts: 1` sofort der Fehler, sonst Warten und Erfolg), Abbruch per `AbortSignal` beim Warten, bei
  einer langsamen Antwort und schon vor dem Senden (dann wird nichts gesendet).
- Failover: der erste Dienst liefert `502`, der zweite stempelt; mit `service` kein Failover.
- Keine Cookies, kein `Authorization` in allen Anfragen des Clients; Origin der Seite in jeder Anfrage, Vorabfragen beobachtet.

Nicht geprüft: Firefox und Safari, ein echter Dienst, ein Relay hinter einem Proxy, Dauer über die kurzen Fenster des Tests hinaus.

## Grenzen und offene Punkte

- Unter Node getestet (echtes Relay mit Stub-Dienst, Fake-Relay für Fehlerantworten) und im Browser nur in headless Chromium
  (nächster Abschnitt); Firefox und Safari wurden nicht ausgeführt.
- `receivedAtMs` ist die Uhr der App und kein Beweis. Ein Beleg beweist nur: dieser Hash lag zu `genTime` vor (bei `batch`: er war
  in der Menge, die der Dienst gestempelt hat; `docs/relay.md`, „Was der Beleg sagt, und was nicht“).
- Keine eigene Wiederholung bei `500` auf demselben Dienst und keine Frist je Dienst.
- Der Versatz der Uhr wird gemerkt, sobald das Relay den korrigierten Kopf nicht mehr mit `401` abweist, auch wenn danach etwas
  anderes (`429`, `502`) folgt; ein ehrliches Relay heilt das mit der nächsten `401`.
- Die Vorgabe `timeoutMs` (130 s) deckt den Sammelbetrieb nur, solange `RELAY_MAX_WAIT_MS` + Fenster + Kette + 17 s darunter bleiben
  (Fenster und Kette von je 60 s ergeben 167 s); wer so fährt, setzt `timeoutMs` höher, der Client kennt die Einstellung des Relays nicht.
- Die Zukunftstoleranz des Tokens ist die der Bibliothek (`maxSkewMs` 5 Minuten, das Relay selbst lässt 60 s zu): die `genTime` eines
  Belegs kann bis zu 5 Minuten nach der Uhr der App liegen; die Aussage „spätestens zu T“ wird dadurch schwächer, nie falsch.
- `random` wird nur auf die Länge geprüft: ein Zufallsgeber, der immer dasselbe liefert, macht jeden Kopf zur Wiederholung (das Relay
  weist das zweite ab); das schadet nur der eigenen App.
- Die Zugangsdaten bezahlter Dienste (`upstream`) kann der Client nicht senden.
