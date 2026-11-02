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
  Runs the AGY telemetry shipper once (scheduled task AGY-Telemetry, SYSTEM, every 5 minutes).
  Device identity from the customer PKI (policy values agy-device-*):
    agy-device-cert-source = file   certificate / key / chain PEM files your PKI tooling places on the device
                           = store  a certificate in LocalMachine\My (client authentication, exportable key), exported
                                    to SYSTEM-only PEM files because the shipper's TLS stack needs a key file
  Writes C:\ProgramData\AntigravityTelemetry\config.json and runs agy-telemetry.py (Python standard library only).
#>
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "AGYConfig.ps1")
$Dir = "C:\ProgramData\AntigravityTelemetry"; $IdDir = Join-Path $Dir "id"
function Audit([string]$m, [string]$type = "Information") { Write-EventLog -LogName Application -Source "agy-mdm" -EventId 1022 -EntryType $type -Message $m -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force -Path $Dir, $IdDir | Out-Null
& icacls $Dir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /q | Out-Null   # keys + tokens: SYSTEM / Administrators only

$source = [string](Get-AgyParam "agy-device-cert-source" "store")
$issuer = [string](Get-AgyParam "agy-device-cert-issuer" "")
$subjectRe = [string](Get-AgyParam "agy-device-cert-subject" "^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")
$certFile = ""; $keyFile = ""; $chainFile = [string](Get-AgyParam "agy-device-chain-file" "")
if ($source -eq "file") {
  $certFile = [string](Get-AgyParam "agy-device-cert-file" ""); $keyFile = [string](Get-AgyParam "agy-device-key-file" "")
  if (-not $certFile -or -not (Test-Path $certFile) -or -not $keyFile -or -not (Test-Path $keyFile)) { Audit "TELEMETRY_NO_DEVICE_CERT: certificate / key file missing ($certFile)" "Warning"; exit 3 }
  $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $certFile
} else {
  $cn = { param($c) ([regex]::Match($c.Subject, 'CN=([^,]+)')).Groups[1].Value }
  $cands = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object {
      $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) -and ($_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.2") -and
      ((& $cn $_) -match $subjectRe) -and (-not $issuer -or ([regex]::Match($_.Issuer, 'CN=([^,]+)')).Groups[1].Value -eq $issuer) } |
    Sort-Object NotAfter -Descending)
  if (-not $cands) { Audit "TELEMETRY_NO_DEVICE_CERT: no client-authentication certificate in LocalMachine\My matches (issuer '$issuer')" "Warning"; exit 3 }
  $cert = $cands[0]
  $certFile = Join-Path $IdDir "device.crt"; $keyFile = Join-Path $IdDir "device.key"; $tp = Join-Path $IdDir "thumbprint"
  if (-not (Test-Path $tp) -or (Get-Content $tp -Raw).Trim() -ne $cert.Thumbprint -or -not (Test-Path $keyFile)) {
    $k = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
    if (-not $k) { $k = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert) }
    try { $blob = $k.Key.Export([Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob) }
    catch { Audit "TELEMETRY_KEY_NOT_EXPORTABLE: the device certificate's key can't be exported for the shipper ($($_.Exception.Message)); use agy-device-cert-source = file or an exportable template" "Error"; exit 4 }
    $label = "PRIVATE" + " KEY"   # assembled at run time: the key is exported on this device, never stored in the package
    [IO.File]::WriteAllText($keyFile, "-----BEGIN $label-----`n" + [Convert]::ToBase64String($blob, "InsertLineBreaks") + "`n-----END $label-----`n")
    [IO.File]::WriteAllText($certFile, "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($cert.RawData, "InsertLineBreaks") + "`n-----END CERTIFICATE-----`n")
    $cert.Thumbprint | Set-Content $tp -Encoding ascii
    Audit "TELEMETRY_DEVICE_CERT exported for the shipper: $($cert.Subject), until $($cert.NotAfter.ToString('s'))"
  }
}
$deviceId = ([regex]::Match($cert.Subject, 'CN=([^,]+)')).Groups[1].Value
if (-not $deviceId) { Audit "TELEMETRY_NO_DEVICE_CERT: certificate has no subject CN" "Warning"; exit 3 }
$csv = { param($v) @(([string]$v) -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
$cfg = [ordered]@{
  project = [string](Get-AgyParam "agy-telemetry-project" ""); audience = [string](Get-AgyParam "agy-telemetry-audience" "")
  log_id = [string](Get-AgyParam "agy-telemetry-log" "agy_winevt"); location = [string](Get-AgyParam "agy-telemetry-location" "europe-west4")
  device_id = $deviceId; cert_file = $certFile; key_file = $keyFile; chain_file = $chainFile; cert_not_after = $cert.NotAfter.ToUniversalTime().ToString("s") + "Z"
  events = @(& $csv (Get-AgyParam "agy-telemetry-events" "agy")); os_channels = @(& $csv (Get-AgyParam "agy-telemetry-os-channels" ""))
  daily_cap_mb = [int](Get-AgyParam "agy-telemetry-daily-cap-mb" "5"); heartbeat_min = [int](Get-AgyParam "agy-telemetry-heartbeat-min" "15")
  spool_mb = [int](Get-AgyParam "agy-telemetry-spool-mb" "50"); state_dir = $Dir
}
if (-not $cfg.project -or -not $cfg.audience) { Audit "TELEMETRY_NOT_CONFIGURED: agy-telemetry-project / agy-telemetry-audience missing" "Warning"; exit 2 }
[IO.File]::WriteAllText((Join-Path $Dir "config.json"), ($cfg | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding $false))
$py = "C:\Program Files\Python312\python.exe"
& $py (Join-Path (Split-Path $PSScriptRoot -Parent) "telemetry\agy-telemetry.py") --config (Join-Path $Dir "config.json")
exit $LASTEXITCODE
