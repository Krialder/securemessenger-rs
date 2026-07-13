# 0011: SSO ueber einen Keycloak-Realm fuer Fremdprojekte

**Status:** akzeptiert (macht das Keycloak-Skelett aus ADR-0004/pflichtenheft.md 5.2 scharf; F060)

## Kontext

Der SecureMessenger soll das Fundament fuer weitere Ausbildungsprojekte sein (etwa AzubiOS). Ein wiederkehrender Bedarf einer Werkzeug-Suite ist ein gemeinsamer Login: ein Nutzer meldet sich einmal an und nutzt mehrere Werkzeuge, statt in jedem ein eigenes Konto zu fuehren. Bisher lag Keycloak nur als Deployment-Skelett vor (deploy/k8s/keycloak.yaml): kein Realm, kein Client, keine Discovery, nichts, woran ein Fremdprojekt anbinden koennte.

Die Leitplanke steht schon in pflichtenheft.md 5.2 ("kein Eigenbau bei Sicherheit") und in architektur.md: SSO laeuft ueber einen gehaerteten Standard-OIDC-Provider (Keycloak), **getrennt von der kryptografischen Identitaet** des Messengers. Zwei Dinge sind hier bewusst verschieden und duerfen nicht vermengt werden:

- Die **Anmelde-Identitaet** (wer ist der Mensch): das leistet Keycloak per OpenID Connect. Sie sagt einem Fremdprojekt, wer angemeldet ist.
- Die **kryptografische Identitaet** (die Geraeteschluessel, die Ende-zu-Ende verschluesseln): die bleibt im Client und in identity/KT, und Keycloak sieht sie nie.

Und getrennt von beidem bleibt der **Maschine-zu-Maschine-Fluss** der Integrations-API (`POST /integrations/token`, Client Credentials, ADR-frei in services/integrations): der ist Server-zu-Server und kein Nutzer-Login.

## Entscheidung

Keycloak wird als OIDC-Provider mit einem **versionierten Realm-Export** scharf gemacht, den Keycloak beim Start importiert. Der Export ist die einzige Quelle der Wahrheit fuer die Realm-Konfiguration; lokal und im Cluster wird derselbe importiert.

1. **Realm `securemessenger`** (deploy/keycloak/realm-securemessenger.json). Sichere Vorgaben: `sslRequired: external` (HTTP nur fuer localhost, sonst TLS-Pflicht), Selbstregistrierung aus (Konten werden bereitgestellt, kein offener Zulauf, konsistent mit der PoW-Bremse der Messenger-Registrierung), Access-Token 5 Minuten, SSO-Sitzung 10 Stunden.

2. **Zwei Client-Typen, damit ein Fremdprojekt so anbindet, wie es gebaut ist.**
   - `azubios` (vertraulich): fuer ein serverseitiges Projekt. Authorization Code Flow mit Client-Secret UND PKCE (S256).
   - `azubios-spa` (oeffentlich): fuer eine Browser-App ohne Secret. Authorization Code Flow mit PKCE (Pflicht, weil ein oeffentlicher Client kein Secret geheim halten kann).
   Beide: kein Implicit Flow (veraltet, Token im URL-Fragment), kein Direct Access Grant (ROPC, das Passwort liefe durch das Fremdprojekt, was SSO gerade vermeiden soll), keine Service-Accounts (dafuer ist die Integrations-API da).

3. **Import statt Klick.** Der Realm liegt als Datei im Repo und wird per `--import-realm` geladen (lokal per docker-Volume/`docker cp`, im Cluster per ConfigMap-Mount). So ist die Konfiguration nachvollziehbar, versioniert und reproduzierbar, nicht in einer Admin-Oberflaeche zusammengeklickt und undokumentiert.

4. **Discovery ist der Anbindungspunkt.** Ein Fremdprojekt braucht nur die Discovery-URL `{host}/realms/securemessenger/.well-known/openid-configuration`; jede OIDC-Bibliothek liest daraus Authorization-, Token- und JWKS-Endpunkt. Keine handgepflegte Endpunkt-Liste.

## Konsequenzen

Ein Fremdprojekt bindet mit einer Standard-OIDC-Bibliothek an (kein Sonderprotokoll), server- oder browserseitig, und delegiert die Anmeldung vollstaendig: es bekommt die Anmelde-Identitaet (Subject, Name, E-Mail nach Freigabe), aber nie private Schluessel oder Lesezugriff auf Chat-Inhalte. Der Realm-Export ist versioniert, ein Review sieht die Sicherheitsvorgaben (Flows, Laufzeiten, TLS) an einer Stelle.

Bewusst offen und ehrlich abgegrenzt:

- Die Werte im Export (`secret` des Clients, Passwort des Demo-Nutzers) sind **nur fuer die lokale Vorfuehrung**. In jeder echten Umgebung kommen Client-Secrets und Nutzer-Konten aus einem Secret-Store bzw. der Nutzerverwaltung, nie aus einer eingecheckten Datei; die Pipeline setzt Image-Tag, Hostname und die echten Secrets (ADR-0004, keycloak.yaml).
- Wie die **Anmelde-Identitaet mit der kryptografischen Identitaet zusammenspielt** (ob und wie ein per SSO angemeldeter Nutzer sein Messenger-Geraet koppelt), ist bewusst nicht Teil dieser Etappe: die beiden bleiben getrennt (architektur.md), eine Verknuepfung waere ein eigener Entwurf.
- **Produktionshaertung** (Brute-Force-Schutz, E-Mail-Verifikation, MFA/WebAuthn, Realm-Schluesselrotation, echte Nutzer-Foederation aus einem Verzeichnis) ist Betriebssache und steht aus; der Realm setzt sichere Grundvorgaben, ersetzt aber kein Keycloak-Haertungs-Review.
- Die **Hochverfuegbarkeit** (zwei Repliken, NF060) und die eigene Keycloak-Datenbank stehen im Deployment (keycloak.yaml), sind aber nicht Teil des lokalen Entwicklungslaufs (dort start-dev mit interner H2).
- Der **Import greift nur einmal** (`start --import-realm`, Strategie IGNORE_EXISTING): auf einer frischen Datenbank wird der Realm importiert, ein spaeter geaenderter Export aendert den laufenden Cluster-Realm NICHT mehr, auch nicht bei einem Pod-Neustart. Nachtraegliche Aenderungen brauchen einen eigenen Einmal-Job (`kc.sh import --override true`). Fuer den Erst-Aufbau ist die heutige Form ausreichend; der Job ist die Produktions-Verfeinerung.
- Der **Erst-Import ist nicht replikensicher**: beide Repliken fahren beim Start denselben `--import-realm` gegen dieselbe Datenbank, auf einer leeren Datenbank koennen sie sich ins Gehege kommen (eine Replik startet neu, bis der Realm existiert). Das ist ein transienter Erst-Start-Effekt (IGNORE_EXISTING heilt ihn), untergraebt aber kurz genau die HA, fuer die die zwei Repliken da sind. Der saubere Weg ist auch hier der Einmal-Import-Job, danach starten die Repliken ohne `--import-realm`.
