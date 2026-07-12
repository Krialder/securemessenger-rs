# Vorführung

Das Drehbuch für eine Live-Vorführung des SecureMessengers auf einer frischen Windows-Maschine. Jeder Abschnitt zeigt eine Eigenschaft, die das Projekt behauptet, und den Handgriff, mit dem sie sich vorführen lässt: Behauptungen ohne Vorführung wären nur Doku.

## Voraussetzungen

Einmalig `scripts\sm.ps1 -Setup` ausführen (installiert Rust, MSVC, protoc, Docker samt WSL, trunk und legt den `sm-postgres`-Container an); die grafische `SecureMessenger.cmd` erledigt dasselbe per Haken-Auswahl. Danach genügt für jede Vorführung:

```powershell
scripts\sm.ps1          # startet Dienste (8080-8083) und Web-Clients (3000, 3001)
scripts\sm.ps1 -Reset   # dasselbe mit frischen demo_*-Datenbanken
scripts\sm.ps1 -Stop    # beendet alles wieder
```

Das Skript nutzt eigene `demo_*`-Datenbanken (getrennt von den Test-Datenbanken, in denen `cargo test` arbeitet) und deterministische Demo-Schlüssel; in jeder echten Umgebung kämen die Schlüssel aus einem Secret-Store. Jeder Dienst läuft in einem eigenen Fenster mit sichtbaren Logs, weil die Logs Teil der Vorführung sind: dort sieht man, was der Server sieht, und vor allem, was er nicht sieht.

## 1. Zwei Browser chatten Ende-zu-Ende (Meilenstein 1)

1. Öffne http://localhost:3000 (Alice) und http://localhost:3001 (Bob), am besten zwei Browserprofile oder ein normales plus ein privates Fenster, damit die IndexedDB-Ablagen getrennt sind.
2. Registriere in beiden Fenstern je ein Konto (`alice`, `bob`, Passwort frei). Die Registrierung löst nebenbei den Proof-of-Work (Sybil-Bremse, im Demo-Betrieb 8 Bit) und veröffentlicht die Prekey-Bündel.
3. Alice startet einen Chat mit `bob` und schreibt. Die Nachricht erscheint bei Bob in Echtzeit (WebSocket-Hinweiskanal), ohne dass er lädt; Antworten laufen genauso zurück.
4. Zeige die Safety Number in beiden Fenstern: dieselben 60 Ziffern auf beiden Seiten. Stimmen sie überein, spricht niemand mit einem untergeschobenen Schlüssel.

## 2. Der Server sieht nur Chiffretext

Der Kernbeweis des Projekts, direkt auf der Datenbank der Zustellung (vor dem Abholen der Nachricht ausführen, das Ack räumt auf):

```powershell
docker exec sm-postgres psql -U postgres -d demo_delivery -c "SELECT device_id, left(envelope, 60) FROM messages"
```

Zu sehen sind Base64-Blobs. Die Suche nach dem eben getippten Klartext bleibt leer:

```powershell
docker exec sm-postgres psql -U postgres -d demo_delivery -tAc "SELECT count(*) FROM messages WHERE envelope LIKE '%geheim%'"
```

## 3. CLI: derselbe Kern, sichtbarer Protokollfluss

Der Referenzclient `sm` spricht dieselben Dienste. Zwei CLI-Nutzer auf einer Maschine trennt man über die Profil-Dateien:

```powershell
cd <Projekt-Root>
$env:SM_PROFILE='carol-profile.json'; $env:SM_STATE='carol-state.json'
.\target\debug\sm.exe register carol ein-langes-demo-passwort
.\target\debug\sm.exe login ein-langes-demo-passwort
.\target\debug\sm.exe publish-keys
.\target\debug\sm.exe send alice "hallo aus der kommandozeile"
```

Die Nachricht erscheint im Alice-Browserfenster. Antworten holt `sm recv` ab, `sm listen` bleibt am Hinweiskanal und empfängt live.

## 4. Sealed Sender: der Server kennt den Absender nicht

```powershell
.\target\debug\sm.exe send alice "versiegelte nachricht" --sealed
docker exec sm-postgres psql -U postgres -d demo_delivery -tAc "SELECT count(*) FROM messages WHERE envelope LIKE '%carol%'"
```

Die Einreichung läuft ohne Token (`POST /sealed`), und die Zählung liefert 0: weder die Authentifizierung noch die gespeicherte Hülle nennt den Absender. Alice sieht die Nachricht trotzdem mit Absender `carol`, weil das server-signierte Absender-Zertifikat mitverschlüsselt in der Hülle reist und ihr Client es gegen den Trust Root prüft. Zum Vergleich trägt eine normale Hülle (`sm send` ohne `--sealed`) den Absender im Framing; genau dieser Unterschied ist die Vorführung.

## 5. Schlüssel-Verifikation: KT, Safety Number, Schlüsselwechsel

```powershell
.\target\debug\sm.exe verify           # KT-Selbstpruefung: das Verzeichnis fuehrt genau meine Geraete
.\target\debug\sm.exe audit 1 2        # Append-only-Beweis zwischen zwei Epochen
.\target\debug\sm.exe keycheck alice   # Geraeteschluessel des Kontakts gegen die gespeicherten vergleichen
```

Eine Epoche entsteht nur, wenn sich das Verzeichnis geändert hat (der 5-Sekunden-Takt der Demo veröffentlicht dann): nach den Registrierungen von Alice, Bob und Carol liegen mindestens zwei Epochen vor, sonst legt eine weitere Registrierung eine nach.

`keycheck` meldet je Gerät „unverändert", „Erstkontakt" oder eine deutliche Warnung bei einem Schlüsselwechsel; ein manipulierender Server fällt an genau dieser Stelle auf.

## 6. Missbrauchs-Meldung und Blockieren

```powershell
.\target\debug\sm.exe recv                  # gibt je Nachricht eine Melde-ID auf stderr aus
.\target\debug\sm.exe report <melde-id>     # deckt die Nachricht gegenueber der Zustellung auf; sie verifiziert das Franking-Commitment
.\target\debug\sm.exe block alice           # ab jetzt verwirft die Zustellung alices Huellen still
.\target\debug\sm.exe unblock alice
```

Das Melden bricht die Ende-zu-Ende-Verschlüsselung nicht: Der Server lernt den Inhalt erst, wenn der Empfänger ihn beweisbar aufdeckt (Message Franking), und kann die Meldung kryptografisch nicht fälschen.

## 7. Vergängliche Nachrichten

```powershell
.\target\debug\sm.exe send alice "weg in zehn sekunden" --ttl 10
```

Wird die Hülle nicht binnen zehn Sekunden abgeholt, liefert die Zustellung sie nicht mehr aus; ein `recv` nach Ablauf bleibt leer.

## Was die Vorführung nicht zeigt

Gruppen (MLS) sind gebaut und sowohl im CLI (`sm group-create`, `groups`, `group-send`, Einladungen annehmen, Entfernen und Verlassen) als auch im Web-Client bedienbar; diese Vorführung konzentriert sich auf den 1:1-Weg und geht nicht eigens durch den Gruppen-Ablauf (der Drei-Parteien-Test `cargo test -p client-app --test group_e2e` belegt ihn). Offen markiert bleiben die Punkte aus [live-dokument.md](dokumentation/live-dokument.md) Abschnitt 9a, allen voran das externe Audit (ADR-0008): diese Vorführung zeigt Funktionsfähigkeit, keine geprüfte Produktionsreife.
