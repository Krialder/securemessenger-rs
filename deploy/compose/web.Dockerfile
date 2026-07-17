# Web-Client (WASM) fuer den Compose-Stack: baut clients/web mit trunk und
# liefert das Ergebnis ueber nginx aus, das /api/* auf die Dienst-Container
# proxyt (dieselbe Pfad-Zuordnung wie der trunk-Dev-Server in Trunk.toml und
# der Cluster-Ingress). Nur im Profil "web" gebaut.
FROM rust@sha256:31ee7fc65186be7e0e0ccb3f2ca305f14e4739e7642a1ae65753aa5d7b874523 AS builder
WORKDIR /build
RUN apt-get update \
 && apt-get install -y --no-install-recommends protobuf-compiler curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
ENV PROTOC=/usr/bin/protoc
# wasm-Target der gepinnten Toolchain und das trunk-Binary (vorgebaut, spart
# einen cargo-install-Kompilierlauf). trunk holt wasm-bindgen und wasm-opt
# beim Build selbst nach.
RUN rustup target add wasm32-unknown-unknown \
 && curl -fsSL https://github.com/trunk-rs/trunk/releases/latest/download/trunk-x86_64-unknown-linux-gnu.tar.gz \
      | tar -xz -C /usr/local/bin trunk
COPY . .
WORKDIR /build/clients/web
RUN trunk build --release

FROM nginx:1.27-alpine AS runtime
COPY deploy/compose/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /build/clients/web/dist /usr/share/nginx/html
EXPOSE 80
