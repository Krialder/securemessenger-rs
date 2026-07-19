# Compose-Stack

Der ganze Verbund in Containern: PostgreSQL, MinIO und die sechs Dienste,
gesundheitsgeprüft und in der richtigen Reihenfolge gestartet. Der Stack läuft
im PRODUKTIONSMODUS (`SM_ENV=production`): fehlende Pflicht-Konfiguration
bricht den Start ab, statt still auf In-Memory auszuweichen.
`restart: unless-stopped` fängt einen Container-Ausfall ab.

## Starten

```
scripts\sm.ps1                # Docker sicherstellen, .env erzeugen, up -d --build
scripts\sm.ps1 -Web           # zusaetzlich der Web-Client (Port 3000)
scripts\sm.ps1 -Sso           # zusaetzlich Keycloak (Port 8090)
scripts\sm.ps1 -Calls         # zusaetzlich coturn fuer 1:1-Anrufe (F2)
scripts\sm.ps1 -Stop          # herunterfahren (Daten bleiben)
scripts\sm.ps1 -Reset         # vorher die Daten-Volumes loeschen
```

Oder direkt mit Docker aus dem Projekt-Root (die `.env` muss dann schon
existieren, Vorlage `.env.example`):

```
docker compose up -d --build
docker compose --profile web --profile sso up -d --build
docker compose down          # stoppen, Daten bleiben
docker compose down -v       # stoppen und Daten (Volumes) loeschen
```

Der Wrapper `scripts\sm.ps1` nutzt die Docker-Selbstheilung aus
lib-checks.ps1:

- Ein abgestürzter Daemon wird wiederbelebt.
- Der Model Runner (Ursache der Windows-Abstürze) bleibt aus.
- Der Entwicklungs-Container `sm-postgres` (Test-Datenbanken) wird gestoppt,
  damit der Stack-postgres Port 5432 bekommt.

## Geheimnisse (.env)

Alle Schlüssel und Passwörter kommen aus einer lokalen `.env` im
Projekt-Root (nicht eingecheckt; Formate wie in deploy/k8s/SECRETS.md).
`scripts\sm.ps1` erzeugt sie beim ersten Start mit starken Zufallswerten und
lässt eine vorhandene unangetastet. Wichtig: die KT-Schlüssel signieren das
Transparenz-Log; wer die `.env` löscht und neu erzeugt, muss auch die
Daten-Volumes löschen (`-Reset`), sonst scheitert der kt-Dienst am
Integritäts-Check seines eigenen Logs.

## Ports (Host)

| Dienst        | Port |
|---------------|------|
| identity      | 8080 |
| directory     | 8081 |
| delivery      | 8082 |
| kt            | 8083 |
| media         | 8084 |
| integrations  | 8085 |
| PostgreSQL    | 5432 |
| MinIO API     | 9000 (Zugangsdaten in der `.env`) |
| Keycloak      | 8090 (Profil sso, Admin-Passwort in der `.env`) |
| Web-Client    | 3000 (Profil web) |

## Aufbau

- **Ein Image, sechs Dienste.** `deploy/compose/Dockerfile` baut alle sechs
  Binaries in EINEM cargo-Release-Lauf; jeder Container startet dasselbe Image
  und wählt sein Binary über `SM_SERVICE`. Das spart fünf komplette
  Release-Builds gegenüber dem per-Dienst-Image (`deploy/docker/Dockerfile`,
  das für CI und Kubernetes bleibt, wo je Dienst ein schlankes Image gewollt
  ist). curl steckt nur in diesem Compose-Image, für den `/ready`-Healthcheck.
- **Reihenfolge über Healthchecks.** `depends_on: condition: service_healthy`
  lässt directory/delivery/integrations/media erst starten, wenn identity und
  PostgreSQL wirklich bereit sind (nicht nur gestartet).
- **PostgreSQL** legt beim ersten Start eine Datenbank je Dienst an, plus
  eine für Keycloak (`postgres-init/01-create-databases.sql`, nur bei
  leerem Volume; nach Änderungen dort `docker compose down -v`).
- **MinIO** hält die Medien-Blobs; `minio-init` legt den `media`-Bucket an.
- **Keycloak** (Profil sso) läuft im Produktionsmodus (`start`) gegen die
  eigene PostgreSQL-Datenbank; HTTP nur, weil lokal die TLS-Edge fehlt. Der
  Realm-Import bringt keine Nutzer und kein Client-Secret mit (siehe
  deploy/keycloak/README.md).

Die restriktive Kubernetes-Härtung (securityContext, NetworkPolicies, PDBs)
prüfen die echten Manifeste: `deploy\kind\up.ps1` fährt sie lokal auf
einem kind-Cluster.
