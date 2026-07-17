#!/bin/sh
# Startet den Stack auf dem Server und wartet auf die Healthchecks.
# Aufruf: start.sh <zielordner> [web] [sso]
# --no-build: die Images kommen fertig gebaut per docker load, der Server
# kompiliert nie selbst.
set -eu
DIR="${1:?Aufruf: start.sh <zielordner> [web] [sso]}"
shift
PROFILES=""
EXPECTED=8
for p in "$@"; do
    case "$p" in
        web) PROFILES="$PROFILES --profile web"; EXPECTED=$((EXPECTED + 1)) ;;
        sso) PROFILES="$PROFILES --profile sso"; EXPECTED=$((EXPECTED + 1)) ;;
    esac
done

DOCKER="docker"
if [ "$(id -u)" != "0" ] && ! docker info >/dev/null 2>&1; then
    DOCKER="sudo docker"
fi

cd "$DIR"
# shellcheck disable=SC2086
$DOCKER compose $PROFILES up -d --no-build

echo "Warte auf die Healthchecks..."
i=0
while [ $i -lt 60 ]; do
    # web und keycloak haben keinen Healthcheck; running zaehlt fuer sie.
    UP=$($DOCKER compose $PROFILES ps --format '{{.Service}} {{.Status}}' 2>/dev/null | grep -c -E 'healthy|Up' || true)
    BAD=$($DOCKER compose $PROFILES ps --format '{{.Service}} {{.Status}}' 2>/dev/null | grep -c -E 'unhealthy|Restarting|Exited' || true)
    if [ "$UP" -ge "$EXPECTED" ] && [ "$BAD" -eq 0 ]; then
        echo "Stack laeuft ($UP Container):"
        $DOCKER compose $PROFILES ps --format 'table {{.Service}}\t{{.Status}}'
        exit 0
    fi
    i=$((i + 1))
    sleep 5
done
echo "Stack nach 300 s nicht vollstaendig bereit:" >&2
$DOCKER compose $PROFILES ps
exit 1
