#!/bin/sh
# Erzeugt die .env des Stacks AUF DEM SERVER, falls sie fehlt, und zieht
# fehlende Schluessel nach: die Geheimnisse entstehen dort, wo sie gebraucht
# werden, und verlassen die Maschine nie. Formate wie deploy/k8s/SECRETS.md
# (Seeds 32 Bytes Base64, Passwoerter/Tokens 32 Bytes Hex, VAPID base64url).
# Die Basis-Geheimnisse einer vorhandenen .env bleiben unangetastet (die
# KT-Schluessel muessen Neustarts ueberleben); NEUE Schluessel (VAPID, TURN)
# werden angehaengt, falls sie fehlen, damit ein Upgrade einer aelteren .env
# Web-Push und Anrufe bekommt.
# Aufruf: envgen.sh <zielordner> [turn_host]
#   turn_host nicht leer  -> Anrufe (F2) einschalten: TURN-Geheimnis erzeugen
#                            und TURN_URLS auf diese Server-Adresse setzen.
set -eu
DIR="${1:?Aufruf: envgen.sh <zielordner> [turn_host]}"
TURN_HOST="${2:-}"
ENVFILE="$DIR/.env"
mkdir -p "$DIR"

seed()    { head -c 32 /dev/urandom | base64 | tr -d '\n'; }
# base64url ohne Padding: das Format des VAPID-Privatschluessels (delivery
# liest ihn per URL_SAFE_NO_PAD). 32 zufaellige Bytes sind mit
# ueberwaeltigender Wahrscheinlichkeit ein gueltiger P-256-Skalar.
seedurl() { head -c 32 /dev/urandom | base64 | tr -d '\n=' | tr '+/' '-_'; }
hexpw()   { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

umask 077
if [ ! -f "$ENVFILE" ]; then
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
else
    echo ".env vorhanden, Basis-Geheimnisse bleiben unangetastet"
fi

# Web-Push (F1): den VAPID-Schluessel nachziehen, falls er fehlt (auch bei
# einer aelteren .env von vor F1). ACHTUNG: Push wirkt erst, wenn der
# Web-Client ueber HTTPS ausgeliefert wird (Service Worker brauchen TLS); die
# Compose-Auslieferung serviert HTTP, TLS an der Edge ist Betriebssache.
if ! grep -q '^VAPID_PRIVATE_KEY=' "$ENVFILE"; then
    {
        echo "VAPID_PRIVATE_KEY=$(seedurl)"
        echo "VAPID_SUBJECT=mailto:admin@securemessenger.local"
    } >> "$ENVFILE"
    echo "VAPID-Schluessel (Web-Push) ergaenzt"
fi

# Anrufe (F2): nur mit uebergebener Server-Adresse. Das TURN-Geheimnis
# nachziehen (dasselbe nutzt coturn) und TURN_URLS auf die Server-Adresse
# setzen, damit der Browser den Relay dort erreicht (localhost taugt nur
# lokal). coturn braucht dann noch die offenen Ports 3478 (UDP/TCP) und
# 49160-49200 (UDP); bei NAT zusaetzlich EXTERNAL_IP in der .env.
if [ -n "$TURN_HOST" ]; then
    if ! grep -q '^TURN_SHARED_SECRET=' "$ENVFILE"; then
        echo "TURN_SHARED_SECRET=$(hexpw)" >> "$ENVFILE"
        echo "TURN-Geheimnis (Anrufe) ergaenzt"
    fi
    TURN_URLS="stun:$TURN_HOST:3478,turn:$TURN_HOST:3478?transport=udp"
    if grep -q '^TURN_URLS=' "$ENVFILE"; then
        sed -i "s#^TURN_URLS=.*#TURN_URLS=$TURN_URLS#" "$ENVFILE"
    else
        echo "TURN_URLS=$TURN_URLS" >> "$ENVFILE"
    fi
    echo "Anrufe (coturn) eingeschaltet, TURN_URLS=$TURN_URLS"
fi
