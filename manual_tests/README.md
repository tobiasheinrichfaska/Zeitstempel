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

Ohne Netz: `node scripts/browser-check.mjs` prüft Bibliothek und Relay-Schnittstelle in Headless-Chromium
(braucht Playwright mit installiertem Chromium; erwartet sechs Zeilen `OK`).
