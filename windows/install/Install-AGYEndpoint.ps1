<#
Copyright 2026 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

.SYNOPSIS
  Offline installer for a Windows device outside Google Cloud (Azure / on-premises / laptop):
  stages the AGY bundle and settings, installs the prerequisites the Google Cloud image bakes in, and runs the same
  bootstrap + controls as the reference VMs. Stand-in for AGY-Endpoint.msi (Intune / ConfigMgr) - same contract.

.EXAMPLE
  # in an elevated PowerShell, from the extracted agy-windows-offline folder:
  .\Install-AGYEndpoint.ps1 -ParamsFile .\params.json
#>
param(
  [Parameter(Mandatory)][string]$ParamsFile,
  [string]$BundleDir = "",   # default set below: $PSScriptRoot is empty in parameter defaults on PowerShell 5.1
  [switch]$SkipPrerequisites
)
$ErrorActionPreference = "Stop"; $ProgressPreference = "SilentlyContinue"
if (-not $BundleDir) { $BundleDir = Join-Path $PSScriptRoot "bundle" }
$Root = "C:\ProgramData\Antigravity"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "run this in an elevated PowerShell (Run as administrator)"
}
foreach ($need in "bootstrap.ps1", "files\controls\Apply-AGYControls.ps1", "files\hooks\agy-hook.py", "files\policies\hooks.json") {
  if (-not (Test-Path (Join-Path $BundleDir $need))) { throw "bundle incomplete: $need missing in $BundleDir" }
}
$params = Get-Content $ParamsFile -Raw | ConvertFrom-Json   # fail early on invalid JSON
function P([string]$k, $d) { $v = $params.PSObject.Properties[$k]; if ($v -and "$($v.Value)" -ne "") { $v.Value } else { $d } }
function Get-Verified([string]$url, [string]$out, [string]$sha256, [string]$signer) {
  & curl.exe -fsSL --retry 3 -o $out $url; if ($LASTEXITCODE -ne 0) { throw "download failed: $url" }
  $h = (Get-FileHash $out -Algorithm SHA256).Hash.ToLower()
  if ($sha256 -and $h -ne $sha256.ToLower()) { Remove-Item $out -Force; throw "sha256 mismatch for $url ($h)" }
  if ($signer) {
    $sig = Get-AuthenticodeSignature $out
    if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch [regex]::Escape($signer)) { Remove-Item $out -Force; throw "signature check failed for $url ($($sig.Status) $($sig.SignerCertificate.Subject))" }
  }
  Write-Host "  verified $(Split-Path $out -Leaf) sha256=$h"
}

Write-Host "== 1/4 staging settings and bundle in $Root"
New-Item -ItemType Directory -Force -Path $Root | Out-Null
# upgrade / re-run: the device's own settings file may be passed in - don't copy it onto itself
if ((Resolve-Path $ParamsFile).Path -ne (Join-Path $Root "params.json")) { Copy-Item $ParamsFile "$Root\params.json" -Force }
New-Item -ItemType Directory -Force -Path "$Root\bundle" | Out-Null
& robocopy (Join-Path $BundleDir "files") "$Root\bundle\files" /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
Copy-Item (Join-Path $BundleDir "bootstrap.ps1") "$Root\bootstrap.ps1" -Force
& icacls $Root /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" /q | Out-Null

if (-not $SkipPrerequisites) {
  Write-Host "== 2/4 prerequisites (the Google Cloud image has these baked in)"
  # Python 3.12 per machine: the corporate hook runs on it (C:\Program Files\Python312\python.exe)
  if (-not (Test-Path "C:\Program Files\Python312\python.exe")) {
    $py = "$env:TEMP\python-3.12.7-amd64.exe"
    Get-Verified (P "agy-python-url" "https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe") $py (P "agy-python-sha256" "") "Python Software Foundation"
    Start-Process $py -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0 Include_launcher=0" -Wait
    if (-not (Test-Path "C:\Program Files\Python312\python.exe")) { throw "Python install failed" }
  }
  # Sysmon binary (configuration is managed by Apply-AGYControls.ps1)
  if ((P "agy-sysmon" "on") -ne "off" -and -not (Test-Path "C:\Program Files\Sysmon\Sysmon64.exe")) {
    $zip = "$env:TEMP\Sysmon.zip"
    & curl.exe -fsSL --retry 3 -o $zip "https://download.sysinternals.com/files/Sysmon.zip"; if ($LASTEXITCODE -ne 0) { throw "Sysmon download failed" }
    Expand-Archive $zip -DestinationPath "C:\Program Files\Sysmon" -Force
    $sig = Get-AuthenticodeSignature "C:\Program Files\Sysmon\Sysmon64.exe"
    if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "O=Microsoft Corporation") { throw "Sysmon64.exe signature invalid" }
    Write-Host "  Sysmon $((Get-Item 'C:\Program Files\Sysmon\Sysmon64.exe').VersionInfo.FileVersion)"
  }
  # Antigravity Desktop app: official per-user installer -> copied per machine, read-only for users
  $obj = P "agy-desktop-windows-object" ""
  if ($obj -and -not (Test-Path "C:\Program Files\Antigravity\Desktop\Antigravity.exe")) {
    $inst = "$env:TEMP\Antigravity-x64.exe"
    Get-Verified "https://storage.googleapis.com/antigravity-public/$obj" $inst (P "agy-desktop-sha256" "") "O=Google LLC"
    Start-Process $inst -ArgumentList "/S" -Wait
    $src = Join-Path $env:LOCALAPPDATA "Programs\antigravity"; $dst = "C:\Program Files\Antigravity\Desktop"
    if (-not (Test-Path (Join-Path $src "Antigravity.exe"))) { throw "Desktop app not found after install" }
    & robocopy $src $dst /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
    $un = Join-Path $src "Uninstall Antigravity.exe"; if (Test-Path $un) { Start-Process $un -ArgumentList "/S" -Wait }
    & icacls $dst /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" /q | Out-Null
  }
}

Write-Host "== 3/4 bootstrap + controls (personas, CLI, hook, AppLocker / WDAC, firewall, Sysmon, baseline)"
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$Root\bootstrap.ps1"
if ($LASTEXITCODE -ne 0) { throw "bootstrap failed (exit $LASTEXITCODE) - see $Root\bootstrap.log" }
# re-run at every boot as SYSTEM (the drift task AGY-Policy re-applies the controls every 5 minutes)
$act = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$Root\bootstrap.ps1`""
Register-ScheduledTask -TaskName "AGY-Bootstrap" -Action $act -Trigger (New-ScheduledTaskTrigger -AtStartup) -User "SYSTEM" -RunLevel Highest -Force | Out-Null

Write-Host "== 4/4 validation"
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$Root\bundle\files\controls\Test-AGYEndpoint.ps1"
if (Test-Path "$Root\persona-initial-passwords.txt") {
  Write-Host "`nInitial persona passwords: $Root\persona-initial-passwords.txt (Administrators only) - hand them over, then delete the file."
}
Write-Host "Done. Sign out / reboot once so PATH, symlink right and group changes apply to new sessions."
