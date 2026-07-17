#!/bin/sh
# Faehrt den Stack auf dem Server herunter (Daten bleiben).
# Aufruf: stop.sh <zielordner>
set -eu
DIR="${1:?Aufruf: stop.sh <zielordner>}"
DOCKER="docker"
if [ "$(id -u)" != "0" ] && ! docker info >/dev/null 2>&1; then
    DOCKER="sudo docker"
fi
cd "$DIR"
$DOCKER compose --profile web --profile sso down
