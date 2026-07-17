#!/bin/sh
# Zeigt den Stack-Status auf dem Server. Aufruf: status.sh <zielordner>
set -eu
DIR="${1:?Aufruf: status.sh <zielordner>}"
DOCKER="docker"
if [ "$(id -u)" != "0" ] && ! docker info >/dev/null 2>&1; then
    DOCKER="sudo docker"
fi
cd "$DIR"
$DOCKER compose --profile web --profile sso ps --format 'table {{.Service}}\t{{.Status}}'
