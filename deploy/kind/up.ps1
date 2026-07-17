<#
  Lokaler Kubernetes-Lauf der ECHTEN Manifeste (deploy/k8s) auf kind.

  Macht in einem Durchlauf, idempotent:
    1. kind-Cluster 'securemessenger' anlegen (falls er fehlt)
    2. das Ein-Image bauen (deploy/compose/Dockerfile) und in den Cluster laden
    3. Namespace und Secrets anlegen: ZUFAELLIG generiert (einmal je Cluster,
       vorhandene bleiben unangetastet), Formate nach deploy/k8s/SECRETS.md
    4. kubectl apply -k deploy/kind (Basis + infra: PostgreSQL, MinIO)
    5. auf die Rollouts warten und /ready aller Dienste im Cluster pruefen

  Aufrufe:
    deploy\kind\up.ps1          aufsetzen bzw. aktualisieren
    deploy\kind\up.ps1 -Down    Cluster komplett loeschen
#>
param(
    [switch]$Down
)

$ErrorActionPreference = 'Continue'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$ns = 'securemessenger'
$clusterName = 'securemessenger'

function Write-Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "    [ok] $m" -ForegroundColor Green }
function Write-Bad($m)  { Write-Host "    [x]  $m" -ForegroundColor Red }

# kind/kubectl aufloesen (kind liegt nach der Einrichtung in .cargo\bin).
$cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
if ((Test-Path $cargoBin) -and ($env:Path -notlike "*$cargoBin*")) { $env:Path = "$cargoBin;$env:Path" }
foreach ($tool in 'docker', 'kubectl', 'kind') {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Bad "$tool fehlt (kind installiert scripts\sm.ps1 -Setup; kubectl kommt mit Docker Desktop)"
        exit 1
    }
}

if ($Down) {
    Write-Step "Loesche kind-Cluster '$clusterName'"
    kind delete cluster --name $clusterName
    exit $LASTEXITCODE
}

# Docker-Selbstheilung wie beim Compose-/nativen Start.
. (Join-Path $root 'scripts\lib-checks.ps1')
if (-not (Test-SmDockerDaemon)) {
    Write-Step 'Docker-Daemon nicht erreichbar, belebe ihn wieder'
    $daemonComp = Get-SmComponents | Where-Object { $_.Key -eq 'daemon' }
    [void](& $daemonComp.Fix { param($t) Write-Host "        $t" -ForegroundColor DarkGray })
}
if (-not (Test-SmDockerDaemon)) { Write-Bad 'Docker-Daemon nicht erreichbar.'; exit 1 }
Disable-SmModelRunner

# 1. Cluster
Write-Step "kind-Cluster '$clusterName'"
$clusters = kind get clusters 2>$null
if ($clusters -contains $clusterName) {
    Write-Ok 'Cluster vorhanden'
} else {
    kind create cluster --name $clusterName --wait 120s
    if ($LASTEXITCODE -ne 0) { Write-Bad 'Cluster-Anlage fehlgeschlagen'; exit 1 }
    Write-Ok 'Cluster angelegt'
}
kubectl config use-context "kind-$clusterName" *> $null

# 2. Image bauen und laden
Write-Step 'Ein-Image bauen (alle sechs Dienste) und in den Cluster laden'
Push-Location $root
docker build -t securemessenger-local:dev -f deploy/compose/Dockerfile .
$buildOk = ($LASTEXITCODE -eq 0)
Pop-Location
if (-not $buildOk) { Write-Bad 'Image-Build fehlgeschlagen'; exit 1 }
kind load docker-image securemessenger-local:dev --name $clusterName
if ($LASTEXITCODE -ne 0) { Write-Bad 'kind load fehlgeschlagen'; exit 1 }
Write-Ok 'Image im Cluster'

# 3. Namespace und Secrets (generiert, einmal je Cluster; Formate SECRETS.md)
Write-Step 'Namespace und Secrets'
kubectl create namespace $ns --dry-run=client -o yaml | kubectl apply -f - | Out-Null

# Zufallswerte: 32 Bytes als Base64 (Seeds) bzw. Hex (Passwoerter/Tokens).
$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
function New-RandBytes { $b = New-Object byte[] 32; $rng.GetBytes($b); return $b }
function New-Seed { return [Convert]::ToBase64String((New-RandBytes)) }
function New-Hex  { return -join ((New-RandBytes) | ForEach-Object { $_.ToString('x2') }) }

function Test-SmSecret($name) {
    kubectl -n $ns get secret $name *> $null
    return ($LASTEXITCODE -eq 0)
}
function New-SmSecret($name, [hashtable]$kv) {
    if (Test-SmSecret $name) { Write-Ok "Secret $name vorhanden"; return }
    $args = @('-n', $ns, 'create', 'secret', 'generic', $name)
    foreach ($k in $kv.Keys) { $args += "--from-literal=$k=$($kv[$k])" }
    & kubectl @args | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Ok "Secret $name angelegt" } else { Write-Bad "Secret $name fehlgeschlagen" }
}
function Get-SmSecretValue($name, $key) {
    $b64 = kubectl -n $ns get secret $name -o jsonpath="{.data.$key}" 2>$null
    if (-not $b64) { return $null }
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
}

# Das PostgreSQL-Passwort steckt in mehreren Secrets (postgres-admin und den
# fuenf DB-URLs): ein vorhandenes wird wiederverwendet, sonst neu erzeugt.
$pgPass = Get-SmSecretValue 'postgres-admin' 'password'
if (-not $pgPass) { $pgPass = New-Hex }
New-SmSecret 'postgres-admin' @{ password = $pgPass }
foreach ($db in 'identity', 'directory', 'delivery', 'integrations', 'kt') {
    New-SmSecret "$db-db" @{ url = "postgres://postgres:${pgPass}@postgres:5432/$db" }
}
New-SmSecret 'internal-token' @{ token = (New-Hex) }
New-SmSecret 'identity-keys' @{ 'sealed-sender-trust-root' = (New-Seed); 'cds-oprf-key' = (New-Seed) }
New-SmSecret 'kt-keys' @{ signing = (New-Seed); vrf = (New-Seed) }
New-SmSecret 'integrations-webhook' @{ 'signing-key' = (New-Seed) }
New-SmSecret 'media-s3' @{ 'access-key' = 'sm-media'; 'secret-key' = (New-Hex) }
New-SmSecret 'keycloak-db' @{ url = "jdbc:postgresql://postgres:5432/keycloak"; username = 'postgres'; password = $pgPass }
New-SmSecret 'keycloak-admin' @{ username = 'admin'; password = (New-Hex) }

# 4. Anwenden. Der minio-init-Job ist immutable: einen alten Abschluss vorher
# wegraeumen, damit ein geaenderter Job-Spec nicht am apply scheitert.
Write-Step 'Manifeste anwenden (kubectl apply -k deploy/kind)'
kubectl -n $ns delete job minio-init --ignore-not-found *> $null
kubectl apply -k (Join-Path $root 'deploy\kind')
if ($LASTEXITCODE -ne 0) { Write-Bad 'apply fehlgeschlagen'; exit 1 }

# 5. Rollouts abwarten und im Cluster /ready pruefen.
Write-Step 'Warte auf die Rollouts'
$failed = @()
foreach ($d in 'postgres', 'minio', 'identity', 'directory', 'delivery', 'kt', 'integrations', 'media', 'keycloak') {
    kubectl -n $ns rollout status "deploy/$d" --timeout=300s
    if ($LASTEXITCODE -ne 0) { $failed += $d; Write-Bad "$d nicht bereit" } else { Write-Ok "$d bereit" }
}

Write-Step 'Pruefe /ready aller Dienste im Cluster'
# Bewusst ohne Anfuehrungszeichen im sh-Befehl: PowerShell 5.1 zerlegt beim
# Durchreichen an native Programme eingebettete Quotes und zerreisst den
# Befehl sonst mitten im Skript.
kubectl -n $ns run smoke-ready --rm -i --restart=Never --image=curlimages/curl --command -- /bin/sh -c 'for s in identity directory delivery kt integrations media; do echo $s; curl -fsS http://$s/ready || exit 1; echo; done'
$smokeOk = ($LASTEXITCODE -eq 0)

if (($failed.Count -eq 0) -and $smokeOk) {
    Write-Host "`nCluster laeuft: alle Dienste bereit (Namespace $ns)." -ForegroundColor White
    Write-Host '    Status:   kubectl -n securemessenger get pods'
    Write-Host '    Zugriff:  kubectl -n securemessenger port-forward svc/identity 8080:80'
    Write-Host '    Abbauen:  deploy\kind\up.ps1 -Down'
} else {
    Write-Bad ("Nicht alles bereit" + $(if ($failed.Count) { ": " + ($failed -join ', ') } else { " (Smoke-Test fehlgeschlagen)" }))
    Write-Host '    Diagnose: kubectl -n securemessenger get pods; kubectl -n securemessenger describe pod <name>'
    exit 1
}
