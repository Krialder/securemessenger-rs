# Monitoring (Prometheus-Operator)

ServiceMonitor und PrometheusRule fuer die sechs eigenen Dienste. Getrennt
von der Haupt-Kustomization, weil beide CRDs des Prometheus-Operators
voraussetzen.

## Was gescrapt wird

Jeder Dienst liefert auf demselben Port wie die API `/metrics` im
Prometheus-Textformat (`crates/common` `ops_router`, `common::metrics`):

- `process_up` (gauge)
- `http_requests_total{method,route,status}` (counter)
- `http_request_duration_seconds` (histogram, feste Buckets)

Die `route` ist immer das axum-Routenmuster (nie der rohe Pfad), damit die
Kardinalitaet nicht mit jedem Handle explodiert.

## Voraussetzungen

1. **Prometheus-Operator installiert** (die CRDs `ServiceMonitor` und
   `PrometheusRule` existieren).
2. **serviceMonitorSelector der Prometheus-CR** trifft das Label
   `app.kubernetes.io/part-of: securemessenger`. Bei kube-prometheus-stack
   ist oft ein `release`-Label noetig; dann das Label in
   `servicemonitor.yaml` und `prometheusrule.yaml` entsprechend ergaenzen.
3. **Monitoring-Namespace ist beschriftet**: Die NetworkPolicy
   `services-network` (deploy/k8s/network-policy.yaml) laesst Scrape-Verkehr
   nur aus einem Namespace mit dem Label
   `kubernetes.io/metadata.name: monitoring` auf Port 8080 zu. Laeuft
   Prometheus in einem anders benannten Namespace, ist der Selektor dort
   anzupassen.

## Anwenden

```
kubectl apply -k deploy/k8s/monitoring
```

## Hinweis zum Scrape-Port

`/metrics` liegt auf demselben Port (8080) wie die API und die
`/internal`-Routen. Der Netzzugang der Monitoring-Namespace auf 8080 ist
also breiter als nur Metriken; die `/internal`-Routen bleiben aber durch den
`INTERNAL_TOKEN` (Shared Secret) geschuetzt, die NetworkPolicy ist zweite
Schicht. Ein eigener Metrik-Port waere sauberer und ist als spaetere
Verbesserung vorgemerkt (App- und Manifest-Aenderung).
