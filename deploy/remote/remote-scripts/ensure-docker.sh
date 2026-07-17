#!/bin/sh
# Stellt Docker samt compose-Plugin auf dem Zielsystem sicher (Debian/Ubuntu).
# Laeuft auf dem SERVER (von deploy.ps1 hochgeladen und per ssh gestartet).
# Exit 0 = vorhanden oder erfolgreich installiert, 2 = braucht Handarbeit.
set -u

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    echo "docker und compose vorhanden: $(docker --version)"
    exit 0
fi

# Distribution pruefen: der Installationsweg gilt fuer die apt-Familie.
ID_LIKE=""
ID=""
if [ -r /etc/os-release ]; then
    . /etc/os-release
fi
case "${ID:-} ${ID_LIKE:-}" in
    *debian*|*ubuntu*) : ;;
    *)
        echo "Nicht-apt-System (${ID:-unbekannt}); Docker bitte von Hand installieren." >&2
        exit 2
        ;;
esac

# Root noetig; als Nicht-Root nur mit passwortlosem sudo.
RUN=""
if [ "$(id -u)" != "0" ]; then
    if sudo -n true 2>/dev/null; then
        RUN="sudo"
    else
        echo "Kein Root und kein passwortloses sudo; get.docker.com bitte von Hand als root ausfuehren." >&2
        exit 2
    fi
fi

echo "Installiere Docker ueber get.docker.com (braucht Internet auf dem Server)..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL https://get.docker.com | $RUN sh
else
    wget -qO- https://get.docker.com | $RUN sh
fi

if command -v docker >/dev/null 2>&1 && $RUN docker compose version >/dev/null 2>&1; then
    $RUN systemctl enable --now docker 2>/dev/null || true
    echo "Docker installiert: $(docker --version)"
    exit 0
fi
echo "Docker-Installation fehlgeschlagen." >&2
exit 2
