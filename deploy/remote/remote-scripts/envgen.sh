#!/bin/sh
# Erzeugt die .env des Stacks AUF DEM SERVER, falls sie fehlt: die
# Geheimnisse entstehen dort, wo sie gebraucht werden, und verlassen die
# Maschine nie. Formate wie deploy/k8s/SECRETS.md (Seeds 32 Bytes Base64,
# Passwoerter/Tokens 32 Bytes Hex). Eine vorhandene .env bleibt unangetastet
# (die KT-Schluessel muessen Neustarts ueberleben).
# Aufruf: envgen.sh <zielordner>
set -eu
DIR="${1:?Aufruf: envgen.sh <zielordner>}"
ENVFILE="$DIR/.env"
mkdir -p "$DIR"

if [ -f "$ENVFILE" ]; then
    echo ".env vorhanden, bleibt unangetastet"
    exit 0
fi

seed() { head -c 32 /dev/urandom | base64 | tr -d '\n'; }
hexpw() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

umask 077
{
    echo "POSTGRES_PASSWORD=$(hexpw)"
    echo "INTERNAL_TOKEN=$(hexpw)"
    echo "CDS_OPRF_KEY=$(seed)"
    echo "SEALED_SENDER_TRUST_ROOT=$(seed)"
    echo "KT_SIGNING_KEY=$(seed)"
    echo "KT_VRF_KEY=$(seed)"
    echo "INTEGRATIONS_WEBHOOK_SIGNING_KEY=$(seed)"
    echo "MEDIA_S3_ACCESS_KEY=sm-media"
    echo "MEDIA_S3_SECRET_KEY=$(hexpw)"
    echo "KEYCLOAK_ADMIN_PASSWORD=$(hexpw)"
} > "$ENVFILE"
echo ".env erzeugt ($ENVFILE, Rechte 600)"
