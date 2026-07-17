# Lokaler Compose-Stack

Der ganze Backend-Verbund in Containern, als robuster Gegenpart zum schnellen
nativen Start (`scripts\sm.ps1`). Ein Befehl bringt PostgreSQL, MinIO und die
sechs Dienste gesundheits-geprueft und in der richtigen Reihenfolge hoch;
`restart: unless-stopped` faengt einen Container-Ausfall ab.

## Starten

```
scripts\sm.ps1 -Compose            # Docker sicherstellen, dann up -d --build
scripts\sm.ps1 -Compose -Web       # zusaetzlich der Web-Client (Port 3000)
scripts\sm.ps1 -Compose -Sso       # zusaetzlich Keycloak (Port 8090)
scripts\sm.ps1 -Compose -Stop      # herunterfahren (Daten bleiben)
```

Oder direkt mit Docker aus dem Projekt-Root:

```
docker compose up -d --build
docker compose --profile web --profile sso up -d --build
docker compose down          # stoppen, Daten bleiben
docker compose down -v       # stoppen und Daten (Volumes) loeschen
```

Der Wrapper `-Compose` nutzt dieselbe Docker-Selbstheilung wie der native
Start: ein abgestuerzter Daemon wird wiederbelebt, der Model Runner (Ursache
der Windows-Abstuerze) bleibt aus, und der native `sm-postgres` wird gestoppt,
damit der Compose-postgres Port 5432 bekommt.

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
| MinIO API     | 9000 |
| MinIO Konsole | 9001 (minioadmin/minioadmin) |
| Keycloak      | 8090 (Profil sso) |
| Web-Client    | 3000 (Profil web) |

## Aufbau

- **Ein Image, sechs Dienste.** `deploy/compose/Dockerfile` baut alle sechs
  Binaries in EINEM cargo-Release-Lauf; jeder Container startet dasselbe Image
  und waehlt sein Binary ueber `SM_SERVICE`. Das spart fuenf komplette
  Release-Builds gegenueber dem per-Dienst-Image (`deploy/docker/Dockerfile`,
  das fuer CI und Kubernetes bleibt, wo je Dienst ein schlankes Image gewollt
  ist). curl steckt nur in diesem Compose-Image, fuer den `/ready`-Healthcheck.
- **Reihenfolge ueber Healthchecks.** `depends_on: condition: service_healthy`
  laesst directory/delivery/integrations/media erst starten, wenn identity und
  PostgreSQL wirklich bereit sind (nicht nur gestartet).
- **PostgreSQL** legt beim ersten Start eine Datenbank je Dienst an
  (`postgres-init/01-create-databases.sql`, nur bei leerem Volume).
- **MinIO** haelt die Medien-Blobs; `minio-init` legt den `media`-Bucket an.
- **Schluessel** sind die deterministischen DEMO-Werte wie im nativen Start,
  NUR fuer lokal. In echt kommen sie aus einem Secret-Store.

Der Compose-Stack laeuft im Entwicklungsmodus (kein `SM_ENV=production`); die
Produktions-Fail-Fast-Pfade und die restriktive Haertung pruefen die
Kubernetes-Manifeste (`deploy/k8s`, lokal ueber `deploy/k8s/kind`).
