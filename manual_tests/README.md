# Manuelle Tests — Zeitstempel

Es gibt keine Oberfläche. Die manuellen Tests sind Befehle im Terminal, die **das Netz** und die **echten
Dienste** brauchen und deshalb nicht in die automatische Prüfung gehören (die läuft ohne Netz).

## Vorbereitung

1. Node 24 und die Pakete: `npm install` im Projektordner.
2. Internetzugang. Es werden nur Hashes kurzer Testtexte gesendet, keine Daten.
3. Pro Dienst höchstens eine Anfrage je Lauf; zwischen zwei Läufen mindestens eine Minute warten (die freien
   Dienste sind freundlich zu behandeln).

## Dateien

| Datei           | Inhalt                                                                   |
| --------------- | ------------------------------------------------------------------------ |
| `01_dienste.md` | Dienste erreichbar und Antworten gültig; Relay gegen einen echten Dienst |

## Ohne Netz: `node scripts/browser-check.mjs`

Prüft Bibliothek und Relay-Schnittstelle in Headless-Chromium; erwartet werden sechs Zeilen `OK`.
Voraussetzungen:

- Node 24 und `npm install` (`vite` baut das Bündel; es kommt als Abhängigkeit von `vitest` mit und ist deshalb
  keine eigene Abhängigkeit des Projekts).
- Playwright (Version 1.5x oder neuer; getestet mit 1.63) mit installiertem Chromium (`npx playwright install
chromium`). Playwright ist **keine** Abhängigkeit des Projekts: so installieren, dass `require('playwright')` es
  findet (`node_modules` neben dem Projekt oder `NODE_PATH`).
- Kein Schlüssel nötig: das Relay im Skript läuft mit abgeschalteter Anmeldung (`keys: 'off'`, wie
  `RELAY_AUTH=off`, nur auf 127.0.0.1). Die Prüfung deckt also `signRelayRequest` und den signierten Kopf im
  Browser **nicht** ab.
