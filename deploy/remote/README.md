# Auslieferung auf den Server (Proxmox-VM)

Der dritte Start-Weg neben dem lokalen Compose-Stack (`scripts\sm.ps1`) und
dem lokalen Kubernetes (`deploy\kind`): den fertigen Stack auf den Server
bringen, wo er dauerhaft laufen soll. Das Modell ist bewusst schlicht und
ohne Zugriff auf den Server hier vorbereitbar: **eine Linux-VM auf dem
Proxmox-Host, angesprochen ueber SSH.** Auf dem Proxmox-Host selbst laeuft
kein Docker (der bleibt Hypervisor); Docker gehoert in die VM.

Zwei Einstiege, gleiche Engine (`lib-deploy.ps1`):

- **Grafisch:** `ServerDeploy.cmd` (Projekt-Root) oeffnet ein Fenster:
  Verbindungsdaten eintragen, Schluessel einrichten, ausliefern.
- **Konsole:** `deploy\remote\deploy.ps1` (Details unten).

## Schritt 1 (einmalig): Linux-VM auf Proxmox anlegen

In der Proxmox-Weboberflaeche. Empfohlen ist **Debian 12** oder **Ubuntu
Server 24.04** (fuer beide kennt das Werkzeug den Docker-Installationsweg).
Am schnellsten ist eine Cloud-Image-VM oder ein LXC-Container, es geht aber
auch die klassische ISO-Installation:

1. **Vorlage/ISO:** unter *local (pve) -> ISO Images* das Debian/Ubuntu-ISO
   hochladen (oder ein Cloud-Image als Vorlage nutzen).
2. **VM erstellen** (*Create VM*):
   - **OS:** das ISO auswaehlen.
   - **System:** Standard; QEMU-Gastagent anhaken (praktisch, nicht Pflicht).
   - **Disk:** 20 GB genuegen fuer den Stack samt Images und Daten, mehr fuer
     viele Medien-Blobs.
   - **CPU:** 2 Kerne. **RAM:** 4096 MB (mit Keycloak eher 6144 MB).
   - **Netz:** Bridge `vmbr0`; eine erreichbare IP im LAN (per DHCP oder
     statisch), die notiert wird.
3. **VM starten**, das Betriebssystem installieren. Dabei:
   - einen **Benutzer** anlegen (z. B. `deploy`) und/oder root ein Passwort
     geben,
   - den **OpenSSH-Server** mitinstallieren (Debian-Installer: Punkt "SSH
     server"; Ubuntu-Server: standardmaessig dabei).
4. **Erreichbarkeit pruefen:** von Windows aus `ssh benutzer@<vm-ip>` muss
   nach dem Passwort fragen. Ab hier uebernimmt das Werkzeug.

Merke dir: **IP der VM**, **SSH-Benutzer**, **dessen Passwort** (nur fuer den
einmaligen Schluessel-Eintrag). Alles Weitere macht das Werkzeug.

> LXC-Container statt VM geht auch (leichter), muss aber "nested" und mit
> `keyctl`/`fuse` fuer Docker konfiguriert sein; eine echte VM ist der
> unkompliziertere, robustere Weg.

## Schritt 2: Ausliefern

### Grafisch

`ServerDeploy.cmd` doppelklicken. Im Fenster:

1. Server-IP, Port (meist 22), Benutzer und Zielordner eintragen; optional
   Web-Client und/oder Keycloak anhaken.
2. **"1. Schluessel einrichten"** klicken: ein Konsolenfenster fragt EINMAL
   nach dem Server-Passwort und traegt danach den erzeugten SSH-Schluessel
   ein. Ab jetzt laeuft alles ueber den Schluessel, kein Passwort wird
   gespeichert.
3. **"2. Ausliefern und starten"** klicken: das Werkzeug prueft die
   Verbindung, stellt Docker auf dem Server sicher, laedt den Projektstand
   und die fertig gebauten Images hoch, erzeugt die `.env` auf dem Server
   und startet den Stack. Der Fortschritt steht im Protokoll.

### Konsole

```powershell
# einmalig: Profil und Schluessel
deploy\remote\deploy.ps1 -Configure -TargetHost 192.168.1.50 -User deploy
deploy\remote\deploy.ps1 -SetupKey            # fragt einmal nach dem Passwort

# vor der ersten Auslieferung optional pruefen
deploy\remote\deploy.ps1 -CheckOnly

# ausliefern und starten
deploy\remote\deploy.ps1                       # nur die Dienste
deploy\remote\deploy.ps1 -Web -Sso             # samt Web-Client und Keycloak

# spaeter
deploy\remote\deploy.ps1 -Status
deploy\remote\deploy.ps1 -Stop
```

## Was dabei passiert (und was nicht)

- **Die Images baut die lokale Maschine** (`docker compose build`) und
  uebertraegt sie fertig per `docker save` / `scp` / `docker load`. Der
  Server kompiliert **nie** selbst; er braucht nur Docker.
- **Der Projektstand** kommt aus `git archive HEAD` (der committete Stand),
  entpackt in den Zielordner. Uncommittetes reist bewusst nicht mit.
- **Die Geheimnisse** (`.env`) entstehen **auf dem Server** mit starken
  Zufallswerten (`envgen.sh`) und verlassen ihn nie. Eine vorhandene `.env`
  bleibt unangetastet, damit die KT-Schluessel (die das Transparenz-Log
  signieren) Neustarts ueberleben.
- **Docker** installiert das Werkzeug bei Bedarf ueber `get.docker.com`
  (Debian/Ubuntu). Auf anderen Systemen sagt es das und bittet um
  Handinstallation, statt blind etwas zu tun.
- **Kein Passwort wird gespeichert.** Das lokale Verbindungsprofil
  (`profile.json`) und der SSH-Schluessel (`keys/`) sind gitignored und
  enthalten keine Server-Passwoerter.

## Sicherheit fuer den echten Betrieb

Der Stack lauscht auf den Dienst-Ports (8080-8085, Web 3000, SSO 8090). Fuer
mehr als einen Test:

- Eine **Firewall/Reverse-Proxy** (z. B. Caddy/nginx/Traefik mit TLS) vor die
  Dienste setzen; nur den noetigen Weg nach aussen oeffnen. Die `/internal`-
  Routen duerfen NIE oeffentlich erreichbar sein (sie sind zusaetzlich durch
  den `INTERNAL_TOKEN` geschuetzt, aber gehoeren hinter die Firewall).
- Keycloak laeuft hier mit `KC_HOSTNAME=http://...`; produktiv gehoert TLS
  davor und ein echter Hostname.
- Fuer echte Hochverfuegbarkeit und Skalierung ist der Kubernetes-Weg
  (`deploy/k8s`, lokal `deploy/kind`) gedacht, nicht ein einzelner
  Compose-Host.

## Grenzen dieses Standes

Die Engine ist gegen einen lokalen SSH-Testcontainer verifiziert (Verbindung,
Zielsystem-Erkennung, Docker-Pruefung, Skript- und Datei-Upload,
Server-seitige `.env`-Erzeugung, CRLF-Bereinigung). Der eigentliche
`docker compose up` auf dem Server konnte hier mangels echtem Docker-Ziel
nicht durchlaufen; er nutzt exakt denselben Compose-Stand, der lokal
bewiesen ist. Ein echter Lauf gegen die Proxmox-VM steht noch aus (Zugriff
ab naechster Woche).
