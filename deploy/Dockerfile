# Zeitstempel-Relay: Image für den Pilot (ein Relay, Einzelbetrieb).
# NICHT GEBAUT UND NICHT GESTARTET: in der Umgebung, in der diese Vorlage entstand, lief kein Docker-Daemon.
# Geprüft nur statisch (tests/ops-templates.test.ts). Erster Bau und Lauf: docs/betrieb.md, Abschnitt "Pilot-Prüfliste".
#
# Bauen (aus der Wurzel des Repositorys; die Ignorierliste ist deploy/Dockerfile.dockerignore, BuildKit nimmt sie
# neben der Dockerfile-Datei):
#   docker build -f deploy/Dockerfile -t zeitstempel-relay:0.1.0 .
#
# Starten (Beispiel; die Schlüsseldatei liegt auf dem Host in /etc/zeitstempel/relay-keys.json):
#   docker run -d --name zeitstempel-relay --restart=always --read-only --cap-drop=ALL \
#     --security-opt=no-new-privileges --env-file deploy/relay.env \
#     -p 127.0.0.1:8080:8080 -v /etc/zeitstempel:/etc/zeitstempel:ro zeitstempel-relay:0.1.0
# Das VERZEICHNIS wird eingehängt, nicht die Datei: das Relay liest die Datei alle 5 s neu, und eine atomar ersetzte
# Datei (neue Datei schreiben, umbenennen) bliebe bei einem Einzeldatei-Mount im Container die alte.
#
# Das Relay hat keine Abhängigkeit zur Laufzeit: kein "npm install", kein Bau. Es läuft ungebaut mit dem Type-Stripping
# von Node 24 (relay/*.ts importiert src/*.ts und liest services.json und anchors/*.pem relativ zum Wurzelordner).

# Fester Tag (Patch-Stand). Nicht gegen die Registry geprüft; ein Digest ist hier absichtlich nicht eingetragen: den
# Digest des gewählten Tags beim ersten Bau selbst nachsehen und mit --build-arg NODE_IMAGE=node:<tag>@sha256:<digest> setzen.
ARG NODE_IMAGE=node:24.22.3-bookworm-slim
FROM ${NODE_IMAGE}

# Fester Benutzer ohne Anmeldung und ohne Heimatordner (die Nummer ist für Mounts und für Orchestrierer bekannt).
RUN groupadd --system --gid 10001 zeitstempel \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin zeitstempel

WORKDIR /app

# Genau das, was das Relay zur Laufzeit liest. package.json: "type": "module" (sonst liest Node die .ts-Dateien nicht
# als ES-Module). Gehört alles root und ist für den Relay-Benutzer nur lesbar. Kein "COPY . ." und keine Geheimnisse.
COPY package.json services.json ./
COPY anchors ./anchors
COPY src ./src
COPY relay ./relay

# Keine Geheimnisse im Image. Die Schlüsseldatei (öffentliche Schlüssel) kommt als Mount; die Einstellungen kommen
# aus der Umgebung (--env-file). RELAY_SERVICES ist Pflicht und hier absichtlich nicht gesetzt: das Relay bricht ohne ab.
# RELAY_HOST=0.0.0.0: im Container ist 127.0.0.1 von außen nicht erreichbar; den Port nur auf dem Host an die
# Loopback-Adresse binden (-p 127.0.0.1:8080:8080) und ein Proxy davor setzen.
ENV NODE_ENV=production \
    PORT=8080 \
    RELAY_HOST=0.0.0.0 \
    RELAY_KEYS_FILE=/etc/zeitstempel/relay-keys.json

USER 10001:10001
EXPOSE 8080

# SIGTERM beendet das Relay sauber (spätestens nach 10 s, relay/limits.ts shutdownHardMs); Docker wartet vor dem
# SIGKILL standardmäßig 10 s: beim Anhalten mit "docker stop -t 15" mehr Zeit lassen.
STOPSIGNAL SIGTERM

# /health prüft keinen Dienst, nur dass das Relay antwortet (docs/relay.md). Mit Node, ohne curl. Exec-Form.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||'8080')+'/health',{signal:AbortSignal.timeout(4000)}).then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]

# Exec-Form, kein Shell-Wrapper: node ist PID 1 und bekommt SIGTERM selbst (das Relay hat einen eigenen Handler).
ENTRYPOINT ["node", "relay/main.ts"]
