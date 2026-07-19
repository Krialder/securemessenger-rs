# Keycloak-Realm für SSO (F060)

Dieser Ordner macht das Keycloak-Deployment-Skelett scharf: er liefert einen versionierten Realm-Export, den Keycloak beim Start importiert. Damit können Fremdprojekte (etwa AzubiOS) die Anmeldung an den SecureMessenger delegieren (Single Sign-on), ohne dass jedes Projekt eine eigene Nutzerverwaltung baut. Der Entwurf und die Begründungen stehen in [ADR-0011](../../dokumentation/entscheidungen/0011-sso-keycloak-realm.md).

Wichtig zur Abgrenzung: dieses SSO ist die **Anmelde-Identität** (wer bin ich als Nutzer), getrennt von der **kryptografischen Identität** des Messengers (die Geräteschlüssel, die Ende-zu-Ende verschlüsseln). Keycloak sieht nie private Schlüssel oder Chat-Inhalte. Und der Maschine-zu-Maschine-Fluss der Integrations-API (`POST /integrations/token`, Client Credentials) ist etwas anderes als dieser Nutzer-Login: der eine ist Server-zu-Server, der andere meldet einen Menschen an.

## Was der Realm enthält

- **Realm `securemessenger`**: `sslRequired: external` (HTTP nur für localhost, sonst TLS-Pflicht), Selbstregistrierung aus (Konten werden bereitgestellt), Access-Token-Laufzeit 5 Minuten, SSO-Sitzung 10 Stunden.
- **Client `azubios`** (vertraulich): für ein serverseitiges Fremdprojekt. Authorization Code Flow mit Client-Secret und PKCE (S256), kein Implicit, kein Direct Access (ROPC), keine Service-Accounts.
- **Client `azubios-spa`** (öffentlich): für eine Browser-App ohne Secret. Authorization Code Flow mit PKCE (Pflicht). So kann ein Fremdprojekt server- oder browserseitig anbinden, ganz wie es gebaut ist.

Der Export enthält bewusst **keine Nutzer und kein Client-Secret**, damit kein Geheimnis und kein Konto in einer eingecheckten Datei liegt:

- Das Secret des vertraulichen Clients erzeugt Keycloak beim Import selbst (nachlesen in der Admin-Konsole unter Clients -> azubios -> Credentials, oder dort rotieren).
- Nutzer-Konten legt der Betreiber in der Admin-Konsole an bzw. bindet eine Nutzer-Föderation an.

## Lokal starten und ausprobieren

Über das `sso`-Profil des Compose-Stacks (Port 8090, weil 8080 der identity-Dienst belegt; das Admin-Passwort kommt aus der lokalen `.env`, siehe deploy/compose/README.md):

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

`deploy/k8s/keycloak.yaml` importiert denselben Export:

- Der Realm liegt als ConfigMap `keycloak-realm` vor, gemountet unter `/opt/keycloak/data/import`.
- Die Start-Args sind `["start", "--import-realm"]`.
- Die ConfigMap erzeugt **kustomize** beim `kubectl apply -k deploy/k8s`: der `configMapGenerator` in diesem Ordner (`deploy/keycloak/kustomization.yaml`) liest die Export-Datei, und `deploy/k8s` zieht ihn als Basis ein (`disableNameSuffixHash`, damit der Name stabil `keycloak-realm` bleibt, den keycloak.yaml namentlich referenziert).

Nur wer OHNE kustomize deployt, legt die ConfigMap von Hand an:

```
kubectl create configmap keycloak-realm --from-file=deploy/keycloak/realm-securemessenger.json
```

Image-Tag, Hostname und die echten Secrets (DB, Admin) setzt weiterhin die Pipeline.

**Wichtig, erst-Import-Semantik:** `start --import-realm` importiert einen Realm nur, wenn er in der (persistenten) Keycloak-Datenbank noch NICHT existiert (Strategie IGNORE_EXISTING). Daraus folgen zwei offene Punkte, die auch in [ADR-0011](../../dokumentation/entscheidungen/0011-sso-keycloak-realm.md) stehen:

- **Ein bearbeiteter Export ändert nichts mehr.** Auf einer frischen Datenbank greift der Import einmal; danach ändert er den laufenden Realm nicht mehr, auch nicht bei einem Pod-Neustart. Wer den Realm im Cluster nachträglich ändern will, importiert ihn über einen eigenen Einmal-Job (`kc.sh import --override true`) neu, statt sich auf `--import-realm` beim Start zu verlassen.
- **Beide Repliken importieren gleichzeitig.** Weil sie beim Erst-Start denselben Import fahren, können sie sich auf einer leeren Datenbank ins Gehege kommen: eine Replik meldet "Realm existiert schon" und startet neu, bis IGNORE_EXISTING greift. Der saubere Weg für echte Hochverfügbarkeit ist ebenfalls der Einmal-Job, dann starten die Repliken OHNE `--import-realm`.

Für den Erst-Aufbau ist die heutige Form ausreichend.
