# Benoetigte Secrets fuer den Cluster

`kubectl apply -k deploy/k8s` bringt die Dienste, aber NICHT die Secrets:
die gehoeren nicht ins Git. Ohne sie starten die Pods nicht (die
Deployments referenzieren sie per `secretKeyRef`). In der echten Umgebung
liefert sie ein Secret-Store ueber ExternalSecret/SealedSecret; die
folgende Liste ist der Vertrag, den der Betrieb erfuellt. Fuer einen
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
| `internal-token` | `token` | Shared Secret der `/internal`-Routen (langer Zufallsstring), dasselbe fuer alle Dienste |

## identity: Krypto-Schluessel (sonst sind reife Features still aus)

| Secret | Key | Inhalt |
|--------|-----|--------|
| `identity-keys` | `sealed-sender-trust-root` | Base64-32-Byte-Seed, Trust-Root der Sealed-Sender-Zertifikate |
| `identity-keys` | `cds-oprf-key` | Base64-32-Byte-Seed, OPRF-Schluessel fuer Contact Discovery |

## kt: Transparenz-Log-Schluessel (muessen Neustarts ueberleben)

| Secret | Key | Inhalt |
|--------|-----|--------|
| `kt-keys` | `signing` | Base64-32-Byte-Seed, Ed25519-Signaturschluessel der KT-Wurzeln |
| `kt-keys` | `vrf` | Base64-32-Byte-Seed, VRF-Schluessel |

## integrations: Webhook-Signatur

| Secret | Key | Inhalt |
|--------|-----|--------|
| `integrations-webhook` | `signing-key` | Base64-32-Byte-Seed, Ed25519-Signaturschluessel der Praesenz-Webhooks (stabil, sonst wechselt der oeffentliche Schluessel je Replik/Neustart) |

## media: Objektspeicher (S3/MinIO)

| Secret | Key | Inhalt |
|--------|-----|--------|
| `media-s3` | `access-key` | S3-Access-Key-ID (wird als `AWS_ACCESS_KEY_ID` erwartet) |
| `media-s3` | `secret-key` | S3-Secret-Access-Key |

## Keycloak (SSO)

| Secret | Key | Inhalt |
|--------|-----|--------|
| `keycloak-db` | `url` / `username` / `password` | eigene PostgreSQL-Datenbank fuer Keycloak |
| `keycloak-admin` | `username` / `password` | Bootstrap-Admin der Keycloak-Konsole |
