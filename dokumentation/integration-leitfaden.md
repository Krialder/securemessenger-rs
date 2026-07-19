# Integrations-Leitfaden für Fremdprojekte

Ein anderes Ausbildungsprojekt (etwa AzubiOS) bindet den SecureMessenger ein, ohne den eigenen Stack zu ändern. Der konsumentenseitige Weg steht hier Schritt für Schritt, mit Beispielen.

Dazu gehören:

- [integration-beispiele.md](integration-beispiele.md): fertige Schnipsel in Python, JavaScript und PHP, dazu ein Weg, einen typisierten Client zu generieren.
- [openapi-integrations.yaml](openapi-integrations.yaml): die maschinenlesbare Form der öffentlichen Endpunkte.
- `services/integrations/src/api.rs`: die Handler, die letzte Quelle der Wahrheit.

## Was der Kern anbietet, und was nicht

- **Benachrichtigungen (notify):** ein markierter Maschinen-Hinweis an einen Nutzer, mit minimalem Inhalt (Mandant und Titel). Das ist ausdrücklich KEIN Ende-zu-Ende-Chat: der Absender ist ein Server, die Details holt der Nutzer im Fremdprojekt.
- **Präsenz (presence):** ob ein Nutzer gerade online ist (ein Bit, keine Geräte-Auflösung).
- **Single Sign-on (OIDC):** deine Nutzer melden sich am SecureMessenger an und sind damit im Fremdprojekt angemeldet. Der Provider ist Keycloak mit einem versionierten, importierbaren Realm (lokal verifiziert); der volle Fluss steht im Abschnitt "SSO/OIDC" unten.
- **Nicht angeboten:** Lesezugriff auf Chat-Inhalte. Nachrichten sind Ende-zu-Ende verschlüsselt, der Server (und damit ein Fremdprojekt) sieht nur Chiffretext. Das ist Absicht und ändert sich nicht.

## Basis-URL

Alle öffentlichen Endpunkte hängen unter einer vom Betreiber gesetzten Basis-URL. Im Repo steht der Platzhalter `https://api.messenger.intern` (deploy/k8s/ingress.yaml, Host `api.`). Der Betreiber nennt dir die echte URL; im Text unten steht `$BASE` dafür.

## Schritt 1: Mandant werden

Jedes Fremdprojekt ist ein eigener Mandant mit eigenem Token und eigenem Rate-Limit. Die Anlage ist **betriebsintern**, kein Self-Service: der Betreiber legt den Mandanten über die interne Route `POST /internal/tenants` an (nur im Cluster-Netz erreichbar, per Shared Secret, im Ingress nicht exponiert). Du bekommst vom Betreiber zurück:

- `client_id` (gleich dem Mandanten-Namen, z. B. `azubios`),
- `client_secret` (genau EINMAL sichtbar; danach existiert nur der Argon2id-Hash, verloren heißt neu anlegen lassen),
- die zugeteilten Scopes (`notify`, `presence`) und das Rate-Limit (Requests pro Minute, Vorgabe 60).

Bewahre das `client_secret` wie ein Passwort auf.

Führst du die interne Anlage-Route als Betreiber selbst aus, braucht der Aufruf den Header `x-internal-token: <Shared Secret>` und diesen Body:

```json
{ "name": "azubios", "scopes": ["notify", "presence"], "rate_limit": 60 }
```

## Schritt 2: Ein Token holen (OAuth2 Client Credentials)

Der Token-Endpunkt ist ein standardkonformer OAuth2-Client-Credentials-Grant (RFC 6749), deshalb bindet jede OAuth2-Bibliothek deiner Sprache an (Python `authlib`/`requests-oauthlib`, PHP `league/oauth2-client`, Go, JS):

- Token-URL: `$BASE/integrations/token`
- Format: `application/x-www-form-urlencoded`
- Pflichtfeld: `grant_type=client_credentials`
- Zugangsdaten: entweder als Body-Felder oder im HTTP-Basic-Header

Das ist ein Maschine-zu-Maschine-Fluss, kein Nutzer-Login; das `client_secret` gehört nie in einen Browser.

Zugangsdaten im Body (`client_secret_post`):

```bash
curl -sS -X POST "$BASE/integrations/token" \
  -d 'grant_type=client_credentials' \
  -d 'client_id=azubios' \
  -d 'client_secret=<geheim>'
```

Oder per HTTP-Basic (`client_secret_basic`, was viele Bibliotheken als Vorgabe nutzen):

```bash
curl -sS -X POST "$BASE/integrations/token" \
  -u 'azubios:<geheim>' \
  -d 'grant_type=client_credentials'
```

Antwort (200):

```json
{ "access_token": "…", "token_type": "Bearer", "expires_in": 3600, "scope": "notify presence" }
```

**Scope verengen.** Mit `-d 'scope=notify'` fragst du ein bewusst enges Token an. Das ausgestellte Token trägt dann genau diese Rechte und nichts darüber hinaus (Least Privilege): so stellst du je Einsatzort ein eigenes, minimales Token aus, statt überall das Voll-Token zu verteilen.

- Der angefragte Scope muss eine Teilmenge der Mandanten-Rechte sein, sonst `400 invalid_scope`.
- Ohne `scope` bekommst du die vollen Mandanten-Rechte.
- Das gewährte `scope` steht in der Antwort.

**Fehler beim Token-Tausch.** Sie folgen dem OAuth2-Schema `{ "error": "...", "error_description": "..." }`:

- `401 invalid_client`: falsche Zugangsdaten oder gesperrter Mandant. Beide antworten identisch, die Antwort verrät also nicht, ob es den Mandanten gibt.
- `400 unsupported_grant_type`: falscher `grant_type`.

Hole ein frisches Token, bevor das alte abläuft; ein abgelaufenes Token liefert bei den API-Aufrufen `401 invalid_token`.

## Schritt 3: Benachrichtigen

Braucht den Scope `notify`. Der Pfad-Mandant muss zu deinem Token passen.

```bash
curl -sS -X POST "$BASE/integrations/azubios/notify" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"handle":"alice","title":"Neue Aufgabe faellig"}'
```

Antwort (200):

```json
{ "devices": 2, "connected": 1 }
```

- `devices` ist die gültige Gerätemenge des Kontos, `connected` davon gerade verbunden (nur informativ; nicht verbundene Geräte verpassen den Hinweis, das ist Hinweis-Semantik).
- Der Titel ist auf 1 bis 200 Zeichen begrenzt.
- Ein Konto ohne gültige Geräte liefert `200` mit `devices: 0`, kein Fehler.

## Schritt 4: Präsenz abfragen

Braucht den Scope `presence`.

```bash
curl -sS "$BASE/integrations/azubios/presence/alice" \
  -H "Authorization: Bearer $TOKEN"
```

Antwort (200):

```json
{ "handle": "alice", "online": true }
```

`online` ist `true`, sobald irgendein Gerät des Kontos verbunden ist.

## Fehlercodes und Rate-Limit

Fehler kommen als JSON `{ "code": "...", "message": "..." }`. Entscheide anhand von `code`, nicht anhand von `message`.

| Status | code | Bedeutung |
|--------|------|-----------|
| 400 | `invalid_title` | Titel leer oder über 200 Zeichen |
| 401 | `invalid_token` | Token fehlt, ist ungültig oder abgelaufen |
| 401 | `invalid_client` | Client-ID oder Secret falsch, oder Mandant gesperrt (nur beim Token-Tausch) |
| 403 | `tenant_mismatch` | Token gehört zu einem anderen Mandanten als im Pfad |
| 403 | `missing_scope` | Dem Mandanten fehlt der nötige Scope |
| 404 | `unknown_user` | Der Nutzer-Handle ist unbekannt |
| 429 | (Rate-Limit) | Zu viele Requests; der Header `Retry-After` nennt die Wartezeit in Sekunden |

Bei `429` warte die im `Retry-After` genannte Zeit ab, statt sofort erneut zu senden. Das Limit gilt je Mandant (Vorgabe 60/min).

## Öffentlich für Integratoren vs. betriebsintern

- **Öffentlich (stabiler Vertrag):** `POST /integrations/token`, `POST /integrations/{tenant}/notify`, `GET /integrations/{tenant}/presence/{handle}`. Nur diese drei sind für Fremdprojekte gedacht und im Ingress erreichbar.
- **Betriebsintern (nicht für Integratoren):** `POST /internal/tenants` (Mandanten-Anlage) und alle übrigen `/internal/*`-Routen der Dienste. Sie sind nur im Cluster-Netz erreichbar, per Shared Secret, und tauchen im Ingress bewusst nicht auf.

## SSO/OIDC (Nutzer-Login delegieren)

Neben dem Maschine-zu-Maschine-Zugriff kannst du die **Anmeldung deiner Nutzer** an den SecureMessenger delegieren (Single Sign-on über OpenID Connect): ein Nutzer meldet sich einmal an und nutzt mehrere Werkzeuge, statt in jedem ein eigenes Konto zu führen. Das Fremdprojekt bekommt die Anmelde-Identität (wer ist der Mensch), aber nie private Schlüssel oder Lesezugriff auf Chat-Inhalte.

Zur Abgrenzung: der oben beschriebene `POST /integrations/token` ist ein Maschine-zu-Maschine-Fluss (Client Credentials) für den Server-zu-Server-Zugriff deines Projekts, NICHT der Nutzer-Login.

Der OIDC-Provider ist Keycloak mit einem versionierten Realm `securemessenger` (Entwurf und Begründung in [ADR-0011](entscheidungen/0011-sso-keycloak-realm.md), Realm-Export und lokaler Start in [deploy/keycloak/](../deploy/keycloak/README.md)). So bindest du an:

1. **Discovery lesen.** Deine OIDC-Bibliothek konfiguriert sich aus `{keycloak}/realms/securemessenger/.well-known/openid-configuration` (Authorization-, Token- und JWKS-Endpunkt). Lokal ist `{keycloak}` = `http://localhost:8090`.
2. **Client wählen.** Für ein serverseitiges Projekt der vertrauliche Client `azubios` (Authorization Code Flow mit Client-Secret und PKCE); für eine Browser-App der öffentliche Client `azubios-spa` (Authorization Code Flow mit PKCE, ohne Secret). Der Betrieb vergibt dir die echten `redirect_uri`-Werte und (für den vertraulichen Client) das Secret.
3. **Anmelden.** Deine Bibliothek schickt den Nutzer zum `authorization_endpoint`, Keycloak zeigt die Anmeldeseite, und nach dem Login kommt dein `redirect_uri` mit einem `code` zurück, den du am `token_endpoint` gegen ein `id_token` (die Anmelde-Identität) und ein `access_token` tauschst.

Das ist derselbe standardkonforme OIDC-Fluss, den jede Bibliothek (Python `authlib`, PHP, JS `oidc-client`) spricht, du baust nichts selbst.

**Was der Realm-Export bewusst nicht enthält:**

- Nutzer-Konten. Die legt der Betreiber an oder bindet eine Nutzer-Föderation an.
- Das Client-Secret. Das erzeugt Keycloak beim Import (Admin-Konsole -> Clients -> `azubios` -> Credentials).

Wie ein per SSO angemeldeter Nutzer sein Messenger-Gerät koppelt (die Verbindung von Anmelde- und kryptografischer Identität), ist bewusst getrennt und ein eigener Entwurf.

## Webhooks: Präsenz-Änderungen zugestellt bekommen (Push statt Poll)

Statt Präsenz zu pollen (Schritt 4), kannst du dir eine Änderung zustellen lassen: du registrierst einen Callback, und sobald ein Nutzer online oder offline geht, schickt der Dienst einen signierten Envelope an deine URL. Das braucht denselben Scope wie die Abfrage (`presence`), ist also nicht durchlässiger; abonniert wird je Handle, den du ausdrücklich nennst.

**Endpunkt registrieren** (Bearer-Token, wie die übrigen Aufrufe):

```bash
curl -sS -X POST "$BASE/integrations/azubios/webhooks" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://azubios.intern/hooks/presence","events":["presence.changed"],"handles":["alice","bob"]}'
```

Antwort (201):

```json
{ "id": "...", "url": "...", "events": ["presence.changed"], "handles": ["alice","bob"], "created_at": 1700000000 }
```

- Listen: `GET /integrations/azubios/webhooks`
- Entfernen: `DELETE /integrations/azubios/webhooks/{id}` (204; ein fremder oder unbekannter ist 404)

Die `url` muss öffentlich erreichbar sein: Ziele im internen Netz, auf `localhost` oder auf Cloud-Metadaten weist der Dienst ab (`400 invalid_url`, SSRF-Schutz).

**Was ankommt.** Bei einer Änderung bekommt deine URL ein `POST` mit diesem Body:

```json
{ "id": "<zustell-uuid>", "type": "presence.changed", "tenant": "azubios",
  "created_at": 1700000000, "data": { "handle": "alice", "online": true, "seq": 42 } }
```

Dazu diese Header:

- `X-SecureMessenger-Event: presence.changed`
- `X-SecureMessenger-Delivery: <uuid>` (zum Deduplizieren)
- `X-SecureMessenger-Timestamp: <unix>`
- `X-SecureMessenger-Signature: ed25519=<base64>`

`data.seq` ist eine je Nutzer fortlaufende Nummer des Übergangs. Die Zustellung ist Best effort und NICHT geordnet (zwei schnelle Wechsel können in anderer Reihenfolge ankommen); ordne online/offline deshalb nach `seq` und ignoriere eine niedrigere als die zuletzt gesehene, dann bleibst du nie im falschen Zustand hängen.

**Signatur prüfen.**

1. Hol den öffentlichen Schlüssel einmal von `GET $BASE/integrations/webhook-key` (`{ "alg": "Ed25519", "public_key": "<base64>" }`, du kannst ihn cachen).
2. Prüfe die Ed25519-Signatur über die kanonische Nachricht `{timestamp}.{body}` (der rohe Body, dem der Zeitstempel und ein Punkt vorangestellt sind). So verifizierst du, dass der Envelope wirklich vom Messenger kommt und nicht verändert wurde.
3. Weise über den Zeitstempel einen zu alten (wiedereingespielten) Aufruf ab.
4. Antworte mit `2xx`, sonst gilt die Zustellung als fehlgeschlagen.

**Grenzen:**

- Die Zustellung ist Best effort (ein nicht erreichbarer Empfänger hält weder den Chat noch andere Webhooks auf); einen dauerhaften Wiederhol-Speicher (Outbox mit Retry) gibt es in dieser Etappe noch nicht.
- Wird dein Mandant gesperrt oder verlierst du den `presence`-Scope, hört die Zustellung auf. Die Berechtigung wird bei jeder Zustellung erneut geprüft.
- Heute ist `presence.changed` das einzige Ereignis; das Envelope-Format ist versioniert genug (`type`, `id`, `seq`), dass weitere Ereignisse alte Empfänger nicht brechen.
