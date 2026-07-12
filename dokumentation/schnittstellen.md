# Schnittstellen

Zwei Wege zwischen Client und Kern. REST über HTTPS für alles, was du auslöst, WebSocket für alles, was der Server von sich aus meldet. Bodies sind JSON, Binärdaten gehen Base64-kodiert über die Leitung. Authentifiziert wird per `Authorization: Bearer <token>`, Access-Token kurzlebig, Refresh-Token rotiert.

Die Übersicht zeigt die grobe Form. Für die oeffentliche Integrations-API (token, notify, presence) liegt der maschinenlesbare Feldvertrag als OpenAPI-Datei im Repo ([openapi-integrations.yaml](openapi-integrations.yaml)), ergänzt um den [Integrations-Leitfaden](integration-leitfaden.md). Für die übrigen Dienste ist die jeweilige Handler-Quelle der verbindliche Vertrag; eine gemeinsam ausgelieferte, aus dem Code erzeugte OpenAPI-Spec über alle Routen (etwa per utoipa) bleibt eine offene Aufgabe.

## Konto und Geräte

- `POST /accounts` legt ein Konto mit Handle an und registriert das erste Gerät.
- `POST /sessions`, `POST /sessions/refresh`, `DELETE /sessions` für Login, Erneuern, Logout.
- `GET /devices`, `POST /devices` (Freischaltung durch ein bestehendes Gerät, mit Geräte-Credential), `DELETE /devices/{id}` (entfernt und stößt Gruppen-Neuschlüsseln an).

## Schlüssel, Credentials, Zertifikate

- `GET /keys/{handle}` liefert die Prekey-Bündel aller Geräte, klassisch und post-quantum. Rate-limitiert pro Abrufer.
- `POST /keys/prekeys` füllt den eigenen Pool nach.
- `GET /keys/prekeys` nennt die eigenen Zählstände, damit der Client weiß, wann er nachfüllen muss. [ANNAHME: eigener Endpunkt statt Push-Hinweis; die Spec lässt den Weg offen.]
- `POST /credentials/sender` gibt ein anonymes Sende-Credential (zkgroup-Linie) aus, das beweist, dass der Abruf von einem gültigen Konto kommt, ohne zu verraten, von welchem.

## Key Transparency

- `GET /kt/proof/{handle}` gibt den Inklusionsbeweis samt VRF-Beweis.
- `GET /kt/epoch/{n}` liefert die signierte Wurzel einer Epoche.
- `GET /kt/consistency?from=a&to=b` gibt den Konsistenzbeweis zwischen zwei Epochen.

## Nachrichten

`POST /messages` ist die heikle Stelle. Die Sendung darf den Absender nicht preisgeben, der Server muss aber prüfen können, dass sie von einem berechtigten Konto kommt. Deshalb trägt der Request kein Absender-Feld, sondern ein anonymes Sende-Credential und die Sealed-Sender-Hülle. Der Server verifiziert das Credential, ohne den Absender zu lernen, und stellt zu.

- `POST /messages` nimmt eine oder mehrere Hüllen entgegen (eine je Zielgerät), idempotent über die client-erzeugte `id`.
- `GET /messages` holt die wartenden Sendungen für die eigenen Geräte.
- `POST /messages/ack` bestätigt den Empfang, danach wird die Sendung weggeräumt.
- `POST /messages/report` meldet Abuse unter Aufdeckung des Franking-Tags.

[ANNAHME: Bis die Sealed-Sender-Etappe die anonymen Sende-Credentials liefert, ist `POST /messages` normal Bearer-authentifiziert. Der Absender wird dabei nur geprüft und für die Dauer des Requests gehalten, nie gespeichert - die Ablage kennt weiterhin kein Absender-Feld, damit der Umbau auf Sealed Sender die Daten nicht anfassen muss.]

## Gruppen

- `POST /groups` erzeugt eine MLS-Gruppe.
- `POST /groups/{id}/commit` reicht einen MLS-Commit ein. Der Delivery Service ordnet konkurrierende Commits, siehe [specs/mls-delivery-service.md](specs/mls-delivery-service.md).
- `POST /groups/{id}/messages` verteilt eine Gruppennachricht an die Mitgliedsgeräte.

## Medien

- `POST /media` lädt einen verschlüsselten Blob hoch und gibt eine Referenz zurück.
- `GET /media/{ref}` lädt ihn herunter. Der Schlüssel reist in der Nachricht.

[ANNAHME: Der Upload ist der rohe Body (kein Base64: ein Drittel Overhead auf Megabyte-Dateien), die Referenz eine server-erzeugte UUID als Capability. Blob max. 50 MiB, Upload 30/min, Abruf 120/min je Konto. Chunking und resumable Uploads bleiben eine offene Frage (offene-fragen.md).]

## Integration für andere Projekte

Andere Ausbildungsprojekte binden den Kern über Standard-Protokolle ein, ohne ihren Stack zu ändern. Jedes Projekt ist ein eigener Mandant mit eigenem Token und eigenem Rate-Limit. Der konsumentenseitige Schritt-für-Schritt-Weg samt curl-Beispielen steht im [Integrations-Leitfaden](integration-leitfaden.md), die öffentlichen Endpunkte maschinenlesbar in [openapi-integrations.yaml](openapi-integrations.yaml).

- OpenID Connect (Discovery plus Authorization-Code-Flow) soll die Anmeldung delegieren: SSO gäbe dem Projekt die Anmelde-Identität, nie private Schlüssel oder Lesezugriff auf Inhalte. Stand: Keycloak liegt bisher nur als Deployment-Skelett vor, ein nutzbarer OIDC-Fluss (Realm, registrierter Client, redirect_uri, Discovery-URL) fehlt noch. Der Mandanten-Token unten ist ein Maschine-zu-Maschine-Fluss (Client Credentials), NICHT der Nutzer-Login.
- `POST /integrations/{tenant}/notify` löst eine Benachrichtigung an einen Nutzer aus. Sie ist eine markierte Maschinen-Benachrichtigung mit minimalem Inhalt, kein Ende-zu-Ende-Chat, weil der Absender ein Server ist.
- `GET /integrations/{tenant}/presence/{handle}` fragt den Online-Status ab. Die Freigabe je Nutzer ("soweit der Nutzer es erlaubt") braucht Nutzer-Einstellungen, die noch fehlen; bis dahin ist die Präsenz für Mandanten pauschal sichtbar.
- Webhook-Callbacks sollen dem Projekt Status zurückmelden (etwa die Zustellung); sie sind noch nicht gebaut.

[ANNAHME: Mandanten authentifizieren sich über `POST /integrations/token` (client_id plus client_secret gegen ein kurzlebiges Bearer-Token, Client-Credentials-Zuschnitt). Der notify-Body ist minimal ({handle, title}, Titel max. 200 Zeichen); das Event beim Nutzer trägt nur Mandant und Titel. Die Präsenz-Freigabe je Nutzer braucht Nutzer-Einstellungen, die noch fehlen; bis dahin ist sie pauschal an. Webhook-Callbacks folgen mit einer späteren Etappe.]

Das Konzept dahinter steht im [pflichtenheft.md](pflichtenheft.md), Abschnitt 5.2.

## Echtzeit-Events

Über die WebSocket-Verbindung schickt der Server nur Hinweise, den Chiffretext holt der Client danach selbst.

[ANNAHME: Authentifiziert wird die Verbindung über den ersten Frame `{"token":"<access-token>"}` binnen zehn Sekunden, nicht über einen Header - Browser-WebSocket-Clients können keine Header setzen. Bei Auth-Fehlern schließt der Server mit Code 4401, bei internen Fehlern mit 1011 (Client verbindet neu, loggt aber nicht aus).]

| Event | Bedeutung |
|-------|-----------|
| `message.waiting` | Es liegt etwas für ein Gerät bereit |
| `message.delivered` | Eine Nachricht wurde zugestellt |
| `message.read` | Eine Nachricht wurde gelesen |
| `presence` | Ein Kontakt ist online oder offline |
| `typing` | Das Gegenüber tippt |
| `key.changed` | Der Schlüssel eines Kontakts hat sich geändert |
| `integration.notification` | Ein Fremdprojekt hat eine Benachrichtigung ausgelöst |

## Fehler und Drosselung

Fehler kommen einheitlich als JSON mit Code, Klartextmeldung und optionalen Detailfeldern. Krypto-Fehler bleiben nach außen generisch. Rate-Limiting läuft als Middleware mit Zählern in Redis, streng auf Login, Registrierung und die Schlüssel-Endpunkte. Bei Überschreitung kommt eine `429` mit `Retry-After`.
