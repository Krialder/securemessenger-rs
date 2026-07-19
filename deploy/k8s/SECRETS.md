# Benötigte Secrets für den Cluster

`kubectl apply -k deploy/k8s` bringt die Dienste, aber NICHT die Secrets:
die gehören nicht ins Git. Ohne sie starten die Pods nicht (die
Deployments referenzieren sie per `secretKeyRef`). In der echten Umgebung
liefert sie ein Secret-Store über ExternalSecret/SealedSecret; die
folgende Liste ist der Vertrag, den der Betrieb erfüllt. Für einen
Test-Cluster kann man sie von Hand anlegen (`kubectl -n securemessenger
create secret generic ...`).

Deterministische 32-Byte-Seeds (Base64) erzeugt man z. B. mit
`head -c 32 /dev/urandom | base64`.

## Datenbank-Verbindungen (je Dienst eine)

| Secret | Key | Inhalt |
|--------|-----|--------|
| `identity-db` | `url` | `postgres://user:pass@host:5432/identity` |
| `directory-db` | `url` | `postgres://.../directory` |
| `delivery-db` | `url` | `postgres://.../delivery` |
| `integrations-db` | `url` | `postgres://.../integrations` |
| `kt-db` | `url` | `postgres://.../kt` |

## Dienst-zu-Dienst

| Secret | Key | Inhalt |
|--------|-----|--------|
| `internal-token` | `token` | Shared Secret der `/internal`-Routen (langer Zufallsstring), dasselbe für alle Dienste |

## identity: Krypto-Schlüssel (sonst sind reife Features still aus)

| Secret | Key | Inhalt |
|--------|-----|--------|
| `identity-keys` | `sealed-sender-trust-root` | Base64-32-Byte-Seed, Trust-Root der Sealed-Sender-Zertifikate |
| `identity-keys` | `cds-oprf-key` | Base64-32-Byte-Seed, OPRF-Schlüssel für Contact Discovery |

## kt: Transparenz-Log-Schlüssel (müssen Neustarts überleben)

| Secret | Key | Inhalt |
|--------|-----|--------|
| `kt-keys` | `signing` | Base64-32-Byte-Seed, Ed25519-Signaturschlüssel der KT-Wurzeln |
| `kt-keys` | `vrf` | Base64-32-Byte-Seed, VRF-Schlüssel |

## integrations: Webhook-Signatur

| Secret | Key | Inhalt |
|--------|-----|--------|
| `integrations-webhook` | `signing-key` | Base64-32-Byte-Seed, Ed25519-Signaturschlüssel der Präsenz-Webhooks (stabil, sonst wechselt der öffentliche Schlüssel je Replik/Neustart) |

## delivery: Web-Push (VAPID)

| Secret | Key | Inhalt |
|--------|-----|--------|
| `delivery-push` | `vapid-private-key` | P-256-Privatschlüssel als base64url ohne Padding (32 Byte). Weckt geschlossene Browser bei neuen Nachrichten. OPTIONAL: fehlt das Secret, läuft Web-Push still als Noop (der Chat-Kern hängt nicht daran). Stabil halten, sonst wechselt der öffentliche Schlüssel und alle bestehenden Browser-Abos werden ungültig. |

## delivery + coturn: 1:1-Anrufe (F2, TURN)

| Secret | Key | Inhalt |
|--------|-----|--------|
| `delivery-turn` | `shared-secret` | Zufälliges Geheimnis (use-auth-secret), DASSELBE für delivery und coturn. delivery gibt daraus kurzlebige TURN-Zugangsdaten aus, coturn prüft sie. OPTIONAL: fehlt das Secret, sind Anrufe aus. |
| `delivery-turn` | `urls` | Komma-Liste der ICE-Server, die der Client bekommt, z. B. `stun:turn.example:3478,turn:turn.example:3478?transport=udp`. In echt die ÖFFENTLICH erreichbare Adresse des coturn-Servers. |

## media: Objektspeicher (S3/MinIO)

| Secret | Key | Inhalt |
|--------|-----|--------|
| `media-s3` | `access-key` | S3-Access-Key-ID (wird als `AWS_ACCESS_KEY_ID` erwartet) |
| `media-s3` | `secret-key` | S3-Secret-Access-Key |

## Keycloak (SSO)

| Secret | Key | Inhalt |
|--------|-----|--------|
| `keycloak-db` | `url` / `username` / `password` | eigene PostgreSQL-Datenbank für Keycloak |
| `keycloak-admin` | `username` / `password` | Bootstrap-Admin der Keycloak-Konsole |
