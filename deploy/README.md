# Deployment

Container- und Kubernetes-Definitionen für die sechs SecureMessenger-Dienste: `identity`, `directory`, `delivery`, `integrations`, `kt`, `media`, dazu Keycloak als OIDC-Provider (F060) und optional coturn für 1:1-Anrufe (F2).

## Docker-Image bauen

Das Dockerfile ist generisch und baut einen wählbaren Dienst über `--build-arg SERVICE`. Aufruf aus dem Projekt-Stammverzeichnis:

```
docker build -f deploy/docker/Dockerfile --build-arg SERVICE=identity -t securemessenger/identity:dev .
```

Der Build kompiliert nur den gewählten Dienst im Container (`cargo build --locked -p <dienst>`), es braucht also weder eine lokale Rust-Toolchain noch protoc (der Krypto-Kern ist keine Dienst-Abhängigkeit). Die Runtime-Stage läuft als nicht-privilegierter Nutzer und lauscht auf Port 8080.

Reproduzierbarkeit (pflichtenheft.md 8.2): beide Basis-Images sind per Digest gepinnt, die Rust-Version entspricht `rust-toolchain.toml`, `Cargo.lock` erzwingt über `--locked` exakte Dependency-Stände. Beim Anheben der Rust-Version beide Stellen synchron pflegen; neue Digests liefert `docker buildx imagetools inspect`.

## Kubernetes

`k8s/` enthält je Dienst ein Deployment samt Service (Probes auf `/live` und `/ready`, zwei Repliken). Jeder Dienst braucht mindestens `DATABASE_URL` und `INTERNAL_TOKEN`; die dienstspezifischen Geheimnisse (etwa VAPID und TURN für `delivery`, der Webhook-Signierschlüssel für `integrations`, Sealed-Sender und CDS-OPRF für `identity`) sind in [k8s/SECRETS.md](k8s/SECRETS.md) vollständig aufgeführt. Dazu Namespace, Ingress, NetworkPolicy und die Kustomization, die alles zusammenbindet:

```
kubectl apply -k deploy/k8s
```

Der Ingress veröffentlicht nur die öffentlichen Pfade; die `/internal`-Routen der Dienste tauchen dort nicht auf und sind zusätzlich per NetworkPolicy auf Namespace-Verkehr begrenzt (Shared Secret bleibt die erste Schicht). Image-Tags, Hostnamen und Ressourcen sind Platzhalter und kommen über die GitOps-Pipeline (ArgoCD oder Flux, siehe [pflichtenheft.md](../dokumentation/pflichtenheft.md) 8.2).

## CI

`.github/workflows/ci.yml` prüft Format, Clippy (Warnungen sind Fehler) und die komplette Testsuite inklusive der PostgreSQL-Integrationstests (Service-Container, eine Datenbank je Dienst) und baut anschließend jedes Docker-Image. Die Datei ist zugleich die CI-Vorlage für Folgeprojekte (pflichtenheft.md 8.8).

## Was noch fehlt

Bewusst noch nicht enthalten und als Folgeschritte vorgesehen: die Härtung auf ein statisch gegen musl gebautes oder distroless-Image, TLS über cert-manager, die Operatoren für PostgreSQL, Redis, NATS und MinIO, die GitOps-Anbindung selbst sowie der Push in die interne Registry.
