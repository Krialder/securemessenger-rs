# Multi-Stage-Build für die Rust-Dienste. Baut einen wählbaren Dienst (ARG SERVICE)
# und liefert ein schlankes Runtime-Image. Die Härtung auf statisch gegen musl
# bzw. ein distroless-Image folgt (siehe dokumentation/pflichtenheft.md 8.1).
#
# Reproduzierbarkeit (pflichtenheft.md 8.2): Basis-Images sind per Digest
# gepinnt (Tags sind beweglich, Digests nicht), die Rust-Version entspricht
# rust-toolchain.toml, Cargo.lock liegt im Repo. Damit ist der Build
# eingabestabil: derselbe Quellstand zieht dieselben Zutaten. [ANNAHME:
# Bit-identische Images sind erst mit der Client-/BT-Etappe gefordert
# (F220 betrifft Client-Builds); fürs Backend genügt die Eingabestabilität,
# volle Bit-Gleichheit käme mit kaniko/buildkit-Rewriting später.]
#
# Digest-Wartung: neue Digests per
#   docker buildx imagetools inspect rust:<version>-slim
# ermitteln und hier zusammen mit rust-toolchain.toml anheben.

# rust:1.96.1-slim
FROM rust@sha256:31ee7fc65186be7e0e0ccb3f2ca305f14e4739e7642a1ae65753aa5d7b874523 AS builder
ARG SERVICE=identity
WORKDIR /build
COPY . .
RUN cargo build --release --locked -p "${SERVICE}" \
 && cp "target/release/${SERVICE}" /build/service-bin

# debian:bookworm-slim
FROM debian@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS runtime
# Nicht als root laufen. Feste, hohe UID fuer Kubernetes runAsNonRoot/runAsUser.
RUN useradd --uid 10001 --user-group --no-create-home appuser
COPY --from=builder /build/service-bin /usr/local/bin/service
USER appuser
ENV BIND_ADDR=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/service"]
