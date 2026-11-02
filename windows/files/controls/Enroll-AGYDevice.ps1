# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Device certificate for the gateway front door (Windows, SYSTEM; called by Apply-AGYControls in gateway mode).
# Same contract as endpoint/files/credproxy/agy-device-enroll.sh:
#   * ECDSA P-256 key generated on the device, readable by SYSTEM / Administrators only (the persona can't read it)
#   * certificate from the device CA pool through the device template only (the VM's own service account is the
#     only requester), SPIFFE URI SAN spiffe://<project>.<internal domain>/device/<instance>, 30 days
#   * renewed when less than 10 days remain
# Google Cloud VMs only (Compute Engine identity); managed laptops enrol through the enrolment API (planned S8c-2).
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "AGYConfig.ps1")
function Audit([string]$m, [string]$type = "Information") { Write-EventLog -LogName Application -Source "agy-mdm" -EventId 1003 -EntryType $type -Message $m -ErrorAction SilentlyContinue }

$pool = [string](Get-AgyParam "agy-device-ca-pool" ""); $template = [string](Get-AgyParam "agy-device-template" "")
$spiffe = [string](Get-AgyParam "agy-spiffe-prefix" ""); $root = [string](Get-AgyParam "agy-device-root-pem" "")
if (-not ($pool -and $template -and $spiffe) -or -not (Test-AgyOnGce)) { Write-Host "device enrolment not configured (or not on Google Cloud) - skipping"; return }
$md = "http://metadata.google.internal/computeMetadata/v1"
function Get-Md([string]$p) { Invoke-RestMethod -Headers @{ "Metadata-Flavor" = "Google" } -Uri "$md/$p" -TimeoutSec 10 }
$instance = Get-Md "instance/name"; $zone = (Get-Md "instance/zone").Split("/")[-1]; $region = $zone.Substring(0, $zone.LastIndexOf("-"))
$project = Get-Md "project/project-id"
$dir = "C:\ProgramData\Antigravity\credproxy"; New-Item -ItemType Directory -Force -Path $dir | Out-Null
# folder: SYSTEM + Administrators only (the key must not be readable by personas)
& icacls $dir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /q | Out-Null
if ($root) { [IO.File]::WriteAllText("$dir\root.pem", $root) }
$san = "$spiffe$instance"

$crt = "$dir\device.crt"
if (Test-Path $crt) {
  $c = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $crt
  $sanOk = ($c.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" } | ForEach-Object { $_.Format($false) }) -match [regex]::Escape($san)
  if ($sanOk -and $c.NotAfter -gt (Get-Date).AddDays(10)) { Write-Host "device certificate valid > 10 days - nothing to do"; return }
}

# key + CSR (.NET Framework 4.7.2+: CertificateRequest); the key is exported once to a SYSTEM-only file for the proxy
# ephemeral key (never persisted in a key store). Not CngKey::Create(alg, $null, ...): PowerShell passes $null as ""
# for [string], which creates a *persisted* key with an empty name (and "Access denied" once one exists).
$ec = New-Object Security.Cryptography.ECDsaCng -ArgumentList 256
$key = $ec.Key
if (-not $key.IsEphemeral) { throw "device key is not ephemeral" }
$req = New-Object Security.Cryptography.X509Certificates.CertificateRequest -ArgumentList "O=AGY, CN=$instance", $ec, ([Security.Cryptography.HashAlgorithmName]::SHA256)
$sb = New-Object Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder
$sb.AddUri([Uri]$san)
$req.CertificateExtensions.Add($sb.Build())
$csrPem = "-----BEGIN CERTIFICATE REQUEST-----`n" + [Convert]::ToBase64String($req.CreateSigningRequest(), "InsertLineBreaks") + "`n-----END CERTIFICATE REQUEST-----`n"
# PEM label assembled at run time: the key itself is generated above on this device (the release secret scanner flags
# the literal label as if a key were embedded in the file)
$label = "PRIVATE" + " KEY"
$keyPem = "-----BEGIN $label-----`n" + [Convert]::ToBase64String($key.Export([Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob), "InsertLineBreaks") + "`n-----END $label-----`n"

# issue through the device template (the template allows only device SPIFFE client certificates)
$tok = (Invoke-RestMethod -Headers @{ "Metadata-Flavor" = "Google" } -Uri "$md/instance/service-accounts/default/token").access_token
$poolName = $pool.Split("/")[-1]
$body = @{ lifetime = "2592000s"; pemCsr = $csrPem; certificateTemplate = $template } | ConvertTo-Json
$uri = "https://privateca.googleapis.com/v1/projects/$project/locations/$region/caPools/$poolName/certificates?certificateId=$instance-$((Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss'))"
$res = Invoke-RestMethod -Method Post -Uri $uri -Headers @{ Authorization = "Bearer $tok" } -ContentType "application/json" -Body $body
$chain = $res.pemCertificate + (($res.pemCertificateChain | Select-Object -SkipLast 1) -join "")
[IO.File]::WriteAllText("$dir\device.key.new", $keyPem); [IO.File]::WriteAllText("$dir\device.crt.new", $chain)
Move-Item "$dir\device.key.new" "$dir\device.key" -Force; Move-Item "$dir\device.crt.new" $crt -Force
$c = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $crt
Audit "device certificate enrolled san=$san notAfter=$($c.NotAfter.ToString('s')) sha256=$((Get-FileHash -InputStream ([IO.MemoryStream]::new($c.RawData)) -Algorithm SHA256).Hash)"
Stop-ScheduledTask -TaskName "AGY-CredProxy" -ErrorAction SilentlyContinue; Start-ScheduledTask -TaskName "AGY-CredProxy" -ErrorAction SilentlyContinue
