# Keycloak-Realm fuer SSO (F060)

Dieser Ordner macht das Keycloak-Deployment-Skelett scharf: er liefert einen versionierten Realm-Export, den Keycloak beim Start importiert. Damit koennen Fremdprojekte (etwa AzubiOS) die Anmeldung an den SecureMessenger delegieren (Single Sign-on), ohne dass jedes Projekt eine eigene Nutzerverwaltung baut. Der Entwurf und die Begruendungen stehen in [ADR-0011](../../dokumentation/entscheidungen/0011-sso-keycloak-realm.md).

Wichtig zur Abgrenzung: dieses SSO ist die **Anmelde-Identitaet** (wer bin ich als Nutzer), getrennt von der **kryptografischen Identitaet** des Messengers (die Geraeteschluessel, die Ende-zu-Ende verschluesseln). Keycloak sieht nie private Schluessel oder Chat-Inhalte. Und der Maschine-zu-Maschine-Fluss der Integrations-API (`POST /integrations/token`, Client Credentials) ist etwas anderes als dieser Nutzer-Login: der eine ist Server-zu-Server, der andere meldet einen Menschen an.

## Was der Realm enthaelt

- **Realm `securemessenger`**: `sslRequired: external` (HTTP nur fuer localhost, sonst TLS-Pflicht), Selbstregistrierung aus (Konten werden bereitgestellt), Access-Token-Laufzeit 5 Minuten, SSO-Sitzung 10 Stunden.
- **Client `azubios`** (vertraulich): fuer ein serverseitiges Fremdprojekt. Authorization Code Flow mit Client-Secret und PKCE (S256), kein Implicit, kein Direct Access (ROPC), keine Service-Accounts.
- **Client `azubios-spa`** (oeffentlich): fuer eine Browser-App ohne Secret. Authorization Code Flow mit PKCE (Pflicht). So kann ein Fremdprojekt server- oder browserseitig anbinden, ganz wie es gebaut ist.
- **Demo-Nutzer `azubi-demo`** (Passwort `azubi-demo-passwort`): nur fuer die Vorfuehrung des Login-Flusses.

Die Werte `secret` und das Demo-Passwort im Export sind **ausschliesslich fuer die lokale Vorfuehrung**. In jeder echten Umgebung kommen Client-Secrets und Nutzer-Konten aus einem Secret-Store bzw. der Nutzerverwaltung, nie aus einer eingecheckten Datei.

## Lokal starten und ausprobieren

Keycloak 26.2 im Entwicklungsmodus, Realm direkt importiert (Port 8090, weil 8080 der identity-Dienst belegt):

```bash
docker run -d --name sm-keycloak -p 8090:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin-demo-passwort \
  -v "$(pwd)/deploy/keycloak:/opt/keycloak/data/import:ro" \
  quay.io/keycloak/keycloak:26.2 start-dev --import-realm
```

Unter Windows/Git-Bash, wo der Volume-Mount-Pfad zickt, stattdessen die Datei hineinkopieren:

```bash
docker create --name sm-keycloak -p 8090:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin-demo-passwort \
  quay.io/keycloak/keycloak:26.2 start-dev --import-realm
docker cp deploy/keycloak/realm-securemessenger.json \
  sm-keycloak:/opt/keycloak/data/import/realm-securemessenger.json
docker start sm-keycloak
```

Danach:

- **Discovery** (die OIDC-Bibliothek des Fremdprojekts liest hier alle Endpunkte): `http://localhost:8090/realms/securemessenger/.well-known/openid-configuration`
- **Admin-Konsole**: `http://localhost:8090/admin/` (admin / admin-demo-passwort)
- **Login-Seite des Clients**: der Authorization-Code-Fluss beginnt am `authorization_endpoint` aus der Discovery, mit `client_id=azubios`, `redirect_uri`, `scope=openid`, `code_challenge` (PKCE).

## Im Cluster (Kubernetes)

`deploy/k8s/keycloak.yaml` importiert denselben Export: der Realm liegt als ConfigMap `keycloak-realm` vor, ist unter `/opt/keycloak/data/import` gemountet, und der Start-Args ist `["start", "--import-realm"]`. Die ConfigMap erzeugt **kustomize** beim `kubectl apply -k deploy/k8s`: der `configMapGenerator` in diesem Ordner (`deploy/keycloak/kustomization.yaml`) liest die Export-Datei, und `deploy/k8s` zieht ihn als Basis ein (`disableNameSuffixHash`, damit der Name stabil `keycloak-realm` bleibt, den keycloak.yaml namentlich referenziert). Nur wer OHNE kustomize deployt, legt die ConfigMap von Hand an (`kubectl create configmap keycloak-realm --from-file=deploy/keycloak/realm-securemessenger.json`). Image-Tag, Hostname und die echten Secrets (DB, Admin) setzt weiterhin die Pipeline.

**Wichtig, erst-Import-Semantik:** `start --import-realm` importiert einen Realm nur, wenn er in der (persistenten) Keycloak-Datenbank noch NICHT existiert (Strategie IGNORE_EXISTING). Auf einer frischen Datenbank greift der Import einmal; danach aendert ein bearbeiteter Export den laufenden Realm NICHT mehr, auch nicht bei einem Pod-Neustart. Wer den Realm im Cluster nachtraeglich aendern will, importiert ihn ueber einen eigenen Einmal-Job (`kc.sh import --override true`) neu, statt sich auf `--import-realm` beim Start zu verlassen. Und weil beide Repliken beim Erst-Start denselben Import fahren, koennen sie sich auf einer leeren Datenbank ins Gehege kommen (eine Replik meldet "Realm existiert schon" und startet neu, bis IGNORE_EXISTING greift); der saubere Weg fuer echte Hochverfuegbarkeit ist ebenfalls der Einmal-Job (dann starten die Repliken OHNE `--import-realm`). Fuer den Erst-Aufbau ist die heutige Form ausreichend; beide Punkte stehen als offen in [ADR-0011](../../dokumentation/entscheidungen/0011-sso-keycloak-realm.md).
