# Lokales Kubernetes (kind)

Fährt die ECHTEN Manifeste aus `deploy/k8s` (inklusive securityContext-
Härtung, Probes, PodDisruptionBudgets, NetworkPolicies, Keycloak, Ingress)
auf einem lokalen [kind](https://kind.sigs.k8s.io/)-Cluster. Das ist der
Beweis, dass die Kubernetes-Artefakte nicht nur render-korrekt sind,
sondern wirklich laufen.

## Aufsetzen

```
deploy\kind\up.ps1          # Cluster, Image, Secrets, apply, Rollouts, Smoke-Test
deploy\kind\up.ps1 -Down    # Cluster komplett loeschen
```

`up.ps1` ist idempotent: es legt den Cluster nur an, wenn er fehlt, baut das
Ein-Image (deploy/compose/Dockerfile) neu und lädt es, lässt vorhandene
Secrets unangetastet und wendet dann `deploy/kind` per kustomize an.

## Was dieses Overlay ergänzt bzw. abweicht

- **infra.yaml**: PostgreSQL und MinIO im Cluster (emptyDir, Wegwerf-Daten).
  In echt stellen Operatoren beide (betrieb.md); die Haupt-Manifeste setzen
  sie bewusst als extern voraus.
- **Secrets werden GENERIERT** (Formate nach deploy/k8s/SECRETS.md): starke
  Zufallswerte je Cluster, einmalig; nichts Eingechecktes. In echt liefert
  sie ein Secret-Store (ExternalSecret/SealedSecret).
- **Ein Image für alle sechs Dienste** (Auswahl per SM_SERVICE): EIN
  Release-Build statt sechs. Die per-Dienst-Images baut die CI/Pipeline
  weiterhin aus deploy/docker/Dockerfile.
- **kindnet setzt NetworkPolicies nicht durch**: die Policy wird angewendet,
  aber nicht erzwungen. Enforcement prüft ein Cluster mit Netz-Plugin
  (z. B. Calico).
- **Kein Ingress-Controller**: das Ingress-Objekt liegt an, bleibt aber
  unbedient; Zugriff lokal über `kubectl port-forward`.

## Nach dem Aufsetzen

```
kubectl -n securemessenger get pods
kubectl -n securemessenger port-forward svc/identity 8080:80
kubectl -n securemessenger get secret keycloak-admin -o jsonpath="{.data.password}"
```

Hinweis Erst-Start: die Dienste starten im Produktionsmodus (SM_ENV=
production) und brechen hart ab, solange PostgreSQL noch nicht bereit ist;
Kubernetes startet sie per Backoff neu, bis alles konvergiert. Das ist das
beabsichtigte Fail-Fast-Verhalten, kein Fehlerbild.
