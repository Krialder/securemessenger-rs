# Ein-Image-Build fuer den lokalen Compose-Stack: baut ALLE sechs Dienst-
# Binaries in EINEM cargo-Lauf und liefert sie in einem Image. docker-compose
# startet dasselbe Image sechsmal und waehlt je Container das Binary ueber
# SM_SERVICE. Das spart fuenf komplette Release-Builds gegenueber dem
# per-Dienst-Image aus deploy/docker/Dockerfile (das bleibt fuer CI und
# Kubernetes, wo je Dienst ein schlankes Image gewollt ist).
#
# Basis-Image per Digest gepinnt wie in deploy/docker/Dockerfile
# (rust:1.96.1-slim, entspricht rust-toolchain.toml).
FROM rust@sha256:31ee7fc65186be7e0e0ccb3f2ca305f14e4739e7642a1ae65753aa5d7b874523 AS builder
WORKDIR /build
# protoc: der Krypto-Kern (ueber sealed-cert -> libsignal) kompiliert seine
# Protobuf-Schemas.
RUN apt-get update \
 && apt-get install -y --no-install-recommends protobuf-compiler \
 && rm -rf /var/lib/apt/lists/*
COPY . .
# Ein Lauf baut alle sechs Dienste; die geteilten Abhaengigkeiten (axum,
# libsignal, ...) werden nur einmal kompiliert.
RUN cargo build --release --locked \
      -p identity -p directory -p delivery -p kt -p integrations -p media

# debian:bookworm-slim, per Digest gepinnt wie im per-Dienst-Image.
FROM debian@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS runtime
# curl NUR fuer den Compose-Healthcheck (jeder Dienst antwortet auf /ready).
# Das per-Dienst-/k8s-Image bleibt schlank; dort prueft der kubelet per
# httpGet und braucht kein Werkzeug im Container.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --user-group --no-create-home appuser
COPY --from=builder \
    /build/target/release/identity \
    /build/target/release/directory \
    /build/target/release/delivery \
    /build/target/release/kt \
    /build/target/release/integrations \
    /build/target/release/media \
    /usr/local/bin/
USER appuser
ENV BIND_ADDR=0.0.0.0:8080
EXPOSE 8080
# SM_SERVICE waehlt das Binary (identity|directory|delivery|kt|integrations|
# media). exec, damit der Dienst PID 1 wird und SIGTERM fuers Graceful
# Shutdown bekommt.
ENTRYPOINT ["/bin/sh", "-c", "exec /usr/local/bin/${SM_SERVICE:?SM_SERVICE muss gesetzt sein}"]
