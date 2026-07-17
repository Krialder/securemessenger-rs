# Keycloak-Realm fuer SSO (F060)

Dieser Ordner macht das Keycloak-Deployment-Skelett scharf: er liefert einen versionierten Realm-Export, den Keycloak beim Start importiert. Damit koennen Fremdprojekte (etwa AzubiOS) die Anmeldung an den SecureMessenger delegieren (Single Sign-on), ohne dass jedes Projekt eine eigene Nutzerverwaltung baut. Der Entwurf und die Begruendungen stehen in [ADR-0011](../../dokumentation/entscheidungen/0011-sso-keycloak-realm.md).

Wichtig zur Abgrenzung: dieses SSO ist die **Anmelde-Identitaet** (wer bin ich als Nutzer), getrennt von der **kryptografischen Identitaet** des Messengers (die Geraeteschluessel, die Ende-zu-Ende verschluesseln). Keycloak sieht nie private Schluessel oder Chat-Inhalte. Und der Maschine-zu-Maschine-Fluss der Integrations-API (`POST /integrations/token`, Client Credentials) ist etwas anderes als dieser Nutzer-Login: der eine ist Server-zu-Server, der andere meldet einen Menschen an.

## Was der Realm enthaelt

- **Realm `securemessenger`**: `sslRequired: external` (HTTP nur fuer localhost, sonst TLS-Pflicht), Selbstregistrierung aus (Konten werden bereitgestellt), Access-Token-Laufzeit 5 Minuten, SSO-Sitzung 10 Stunden.
- **Client `azubios`** (vertraulich): fuer ein serverseitiges Fremdprojekt. Authorization Code Flow mit Client-Secret und PKCE (S256), kein Implicit, kein Direct Access (ROPC), keine Service-Accounts.
- **Client `azubios-spa`** (oeffentlich): fuer eine Browser-App ohne Secret. Authorization Code Flow mit PKCE (Pflicht). So kann ein Fremdprojekt server- oder browserseitig anbinden, ganz wie es gebaut ist.

Der Export enthaelt bewusst **keine Nutzer und kein Client-Secret**: Keycloak erzeugt das Secret des vertraulichen Clients beim Import selbst (nachlesen in der Admin-Konsole unter Clients -> azubios -> Credentials, oder dort rotieren), und Nutzer-Konten legt der Betreiber in der Admin-Konsole an bzw. bindet eine Nutzer-Foederation an. So liegt kein Geheimnis und kein Konto in einer eingecheckten Datei.

## Lokal starten und ausprobieren

Ueber das `sso`-Profil des Compose-Stacks (Port 8090, weil 8080 der identity-Dienst belegt; das Admin-Passwort kommt aus der lokalen `.env`, siehe deploy/compose/README.md):

```powershell
scripts\sm.ps1 -Sso
```

Danach:

- **Discovery** (die OIDC-Bibliothek des Fremdprojekts liest hier alle Endpunkte): `http://localhost:8090/realms/securemessenger/.well-known/openid-configuration`
- **Admin-Konsole**: `http://localhost:8090/admin/` (Zugangsdaten aus der `.env`)
- **Nutzer anlegen**: Admin-Konsole -> Users -> Create user (der Export bringt bewusst keine mit)
- **Client-Secret nachlesen**: Clients -> `azubios` -> Credentials
- **Login-Seite des Clients**: der Authorization-Code-Fluss beginnt am `authorization_endpoint` aus der Discovery, mit `client_id=azubios`, `redirect_uri`, `scope=openid`, `code_challenge` (PKCE).

## Im Cluster (Kubernetes)

`deploy/k8s/keycloak.yaml` importiert denselben Export: der Realm liegt als ConfigMap `keycloak-realm` vor, ist unter `/opt/keycloak/data/import` gemountet, und der Start-Args ist `["start", "--import-realm"]`. Die ConfigMap erzeugt **kustomize** beim `kubectl apply -k deploy/k8s`: der `configMapGenerator` in diesem Ordner (`deploy/keycloak/kustomization.yaml`) liest die Export-Datei, und `deploy/k8s` zieht ihn als Basis ein (`disableNameSuffixHash`, damit der Name stabil `keycloak-realm` bleibt, den keycloak.yaml namentlich referenziert). Nur wer OHNE kustomize deployt, legt die ConfigMap von Hand an (`kubectl create configmap keycloak-realm --from-file=deploy/keycloak/realm-securemessenger.json`). Image-Tag, Hostname und die echten Secrets (DB, Admin) setzt weiterhin die Pipeline.

**Wichtig, erst-Import-Semantik:** `start --import-realm` importiert einen Realm nur, wenn er in der (persistenten) Keycloak-Datenbank noch NICHT existiert (Strategie IGNORE_EXISTING). Auf einer frischen Datenbank greift der Import einmal; danach aendert ein bearbeiteter Export den laufenden Realm NICHT mehr, auch nicht bei einem Pod-Neustart. Wer den Realm im Cluster nachtraeglich aendern will, importiert ihn ueber einen eigenen Einmal-Job (`kc.sh import --override true`) neu, statt sich auf `--import-realm` beim Start zu verlassen. Und weil beide Repliken beim Erst-Start denselben Import fahren, koennen sie sich auf einer leeren Datenbank ins Gehege kommen (eine Replik meldet "Realm existiert schon" und startet neu, bis IGNORE_EXISTING greift); der saubere Weg fuer echte Hochverfuegbarkeit ist ebenfalls der Einmal-Job (dann starten die Repliken OHNE `--import-realm`). Fuer den Erst-Aufbau ist die heutige Form ausreichend; beide Punkte stehen als offen in [ADR-0011](../../dokumentation/entscheidungen/0011-sso-keycloak-realm.md).
