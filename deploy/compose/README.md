# Compose-Stack

Der ganze Verbund in Containern: PostgreSQL, MinIO und die sechs Dienste,
gesundheits-geprueft, in der richtigen Reihenfolge und im PRODUKTIONSMODUS
(`SM_ENV=production`: fehlende Pflicht-Konfiguration bricht den Start ab,
statt still auf In-Memory auszuweichen); `restart: unless-stopped` faengt
einen Container-Ausfall ab.

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
lib-checks.ps1: ein abgestuerzter Daemon wird wiederbelebt, der Model Runner
(Ursache der Windows-Abstuerze) bleibt aus, und der Entwicklungs-Container
`sm-postgres` (Test-Datenbanken) wird gestoppt, damit der Stack-postgres
Port 5432 bekommt.

## Geheimnisse (.env)

Alle Schluessel und Passwoerter kommen aus einer lokalen `.env` im
Projekt-Root (nicht eingecheckt; Formate wie in deploy/k8s/SECRETS.md).
`scripts\sm.ps1` erzeugt sie beim ersten Start mit starken Zufallswerten und
laesst eine vorhandene unangetastet. Wichtig: die KT-Schluessel signieren das
Transparenz-Log; wer die `.env` loescht und neu erzeugt, muss auch die
Daten-Volumes loeschen (`-Reset`), sonst scheitert der kt-Dienst am
Integritaets-Check seines eigenen Logs.

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
  und waehlt sein Binary ueber `SM_SERVICE`. Das spart fuenf komplette
  Release-Builds gegenueber dem per-Dienst-Image (`deploy/docker/Dockerfile`,
  das fuer CI und Kubernetes bleibt, wo je Dienst ein schlankes Image gewollt
  ist). curl steckt nur in diesem Compose-Image, fuer den `/ready`-Healthcheck.
- **Reihenfolge ueber Healthchecks.** `depends_on: condition: service_healthy`
  laesst directory/delivery/integrations/media erst starten, wenn identity und
  PostgreSQL wirklich bereit sind (nicht nur gestartet).
- **PostgreSQL** legt beim ersten Start eine Datenbank je Dienst an, plus
  eine fuer Keycloak (`postgres-init/01-create-databases.sql`, nur bei
  leerem Volume; nach Aenderungen dort `docker compose down -v`).
- **MinIO** haelt die Medien-Blobs; `minio-init` legt den `media`-Bucket an.
- **Keycloak** (Profil sso) laeuft im Produktionsmodus (`start`) gegen die
  eigene PostgreSQL-Datenbank; HTTP nur, weil lokal die TLS-Edge fehlt. Der
  Realm-Import bringt keine Nutzer und kein Client-Secret mit (siehe
  deploy/keycloak/README.md).

Die restriktive Kubernetes-Haertung (securityContext, NetworkPolicies, PDBs)
pruefen die echten Manifeste: `deploy\kind\up.ps1` faehrt sie lokal auf
einem kind-Cluster.
