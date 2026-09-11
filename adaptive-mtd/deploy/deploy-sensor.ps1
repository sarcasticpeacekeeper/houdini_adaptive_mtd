# deploy-sensor.ps1 — runs from Windows, provisions the sensor VM over SSH.
#
# Prereqs:
#   - SSH from Windows to sensor works (key-based or password)
#   - Sensor is on NAT (has internet) and maverick can sudo
#   - VMware shared folder enabled (repo at D:\JSACWC\Project\Cursor\adaptive-mtd)
#     OR this script will scp the repo tarball to the sensor as a fallback.
#
# Usage:
#   .\deploy\deploy-sensor.ps1
#
# If SSH key not set up, it will prompt for the maverick password on the sensor.

param(
    [string]$Sensor = "sensor",
    [string]$RepoLocal = "D:\JSACWC\Project\Cursor\adaptive-mtd"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Adaptive MTD — Sensor automated deploy ===" -ForegroundColor Cyan
Write-Host "Sensor host alias: $Sensor"
Write-Host "Repo local:      $RepoLocal"
Write-Host ""

# 1. Test SSH connectivity
Write-Host ">>> Testing SSH to $Sensor..." -ForegroundColor Yellow
$test = ssh $Sensor "hostname; whoami; sudo -n true 2>/dev/null && echo SUDO_OK || echo SUDO_NEEDS_PASSWORD" 2>&1
Write-Host $test
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: cannot SSH to $Sensor. Set up SSH first (enable ssh on sensor, push key)." -ForegroundColor Red
    exit 1
}
Write-Host ""

# 2. Copy the setup script to the sensor
Write-Host ">>> Copying setup-sensor.sh to sensor:/tmp/..." -ForegroundColor Yellow
scp "$RepoLocal\deploy\setup-sensor.sh" "${Sensor}:/tmp/setup-sensor.sh"
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: scp of setup script failed." -ForegroundColor Red
    exit 1
}

# 3. Check if the repo is reachable on the sensor via shared folder.
#    If not, scp a tarball as fallback.
Write-Host ">>> Checking for repo on sensor (/mnt/repo or /tmp/mtd-lab)..." -ForegroundColor Yellow
$repoCheck = ssh $Sensor "ls /mnt/repo/mtd_controller 2>/dev/null && echo SHARED_FOLDER_OK || (ls /tmp/mtd-lab/mtd_controller 2>/dev/null && echo TARBALL_OK || echo NO_REPO)" 2>&1
Write-Host $repoCheck

if ($repoCheck -match "NO_REPO") {
    Write-Host ">>> Repo not on sensor. SCP-ing a tarball as fallback..." -ForegroundColor Yellow
    Push-Location $RepoLocal
    tar -czf ..\mtd-lab.tar.gz --exclude=.git --exclude=venv --exclude=__pycache__ .
    Pop-Location
    scp "$RepoLocal\..\mtd-lab.tar.gz" "${Sensor}:/tmp/mtd-lab.tar.gz"
    ssh $Sensor "mkdir -p /tmp/mtd-lab && tar -xzf /tmp/mtd-lab.tar.gz -C /tmp/mtd-lab && ls /tmp/mtd-lab"
    Remove-Item "$RepoLocal\..\mtd-lab.tar.gz" -ErrorAction SilentlyContinue
}

# 4. Run the setup script on the sensor over SSH
Write-Host ""
Write-Host ">>> Running setup-sensor.sh on $Sensor (this takes ~5-10 min)..." -ForegroundColor Yellow
Write-Host "    (installs packages, writes config, deploys controller + dashboard, sets up Suricata + iptables)"
ssh $Sensor "sudo bash /tmp/setup-sensor.sh"

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: setup-sensor.sh failed on the sensor. Check output above." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== Sensor deploy complete ===" -ForegroundColor Green
Write-Host "Dashboard (on sensor): https://localhost:43123"
Write-Host "Next: Phase 3 — switch NICs to host-only, apply static netplan."
Write-Host ""
Write-Host "Verify from Windows (once NICs are switched to host-only in Phase 3):"
Write-Host "  curl -k https://203.0.113.2:43123/api/surface"
