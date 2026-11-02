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

# AGY Windows reference workstation bootstrap (windows-startup-script-ps1). Runs as LocalSystem at every boot,
# idempotent. Stand-in for an SCCM / Intune deployment: in production the same steps ship as AGY-Endpoint.msi plus
# Detect-AGY.ps1 / Remediate-AGY.ps1 (see docs/customer/PILOT-TO-PRODUCTION.md).
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # PS 5.1: the progress bar makes downloads extremely slow
$Root = "C:\ProgramData\Antigravity"; $Log = "$Root\bootstrap.log"
New-Item -ItemType Directory -Force -Path $Root | Out-Null
function Log([string]$m) { "$((Get-Date).ToString('s')) $m" | Out-File -FilePath $Log -Append -Encoding utf8; Write-Host $m }
# Settings: MDM registry policy (HKLM\SOFTWARE\Policies\AGY) > C:\ProgramData\Antigravity\params.json (offline installer)
# > GCE instance metadata. Same order as files\controls\AGYConfig.ps1 (inline here: the bundle may not exist yet).
$OnGce = $(try { [bool]([System.Net.Dns]::GetHostAddresses("metadata.google.internal")) } catch { $false })
$ParamsFile = "$Root\params.json"
$Params = if (Test-Path $ParamsFile) { $(try { Get-Content $ParamsFile -Raw | ConvertFrom-Json } catch { [pscustomobject]@{} }) } else { [pscustomobject]@{} }
function Get-AgyMeta([string]$k, [string]$d = "") {
  if (Test-Path "HKLM:\SOFTWARE\Policies\AGY") { $v = (Get-Item "HKLM:\SOFTWARE\Policies\AGY").GetValue($k, $null); if ("$v" -ne "") { return $v } }
  $p = $Params.PSObject.Properties[$k]; if ($p -and "$($p.Value)" -ne "") { return $(if ($p.Value -is [array]) { $p.Value -join "," } else { $p.Value }) }
  if ($OnGce) {
    $v = $(try { Invoke-RestMethod -Headers @{ "Metadata-Flavor" = "Google" } -TimeoutSec 5 `
                   -Uri "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$k" } catch { $null })
    if ("$v" -ne "") { return $v }
  }
  $d
}
function Token() {
  (Invoke-RestMethod -Headers @{ "Metadata-Flavor" = "Google" } `
    -Uri "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token").access_token
}
function Retry([scriptblock]$b, [int]$n = 5) {
  for ($i = 1; $i -le $n; $i++) { try { return & $b } catch { if ($i -eq $n) { throw }; Start-Sleep -Seconds ([math]::Pow(2, $i)) } }
}
Log "=== AGY Windows bootstrap start mode=$(Get-AgyMeta agy-client-mode gateway) platform=$(if ($OnGce) { 'gce' } else { 'offline (params.json / MDM policy)' })"

# ---------------------------------------------------------------- 0. event sources (audit -> Ops Agent -> SIEM)
foreach ($src in "agy-hook", "agy-launch", "agy-mdm") {
  if (-not [System.Diagnostics.EventLog]::SourceExists($src)) { New-EventLog -LogName Application -Source $src }
}
function Audit([string]$m, [string]$type = "Information") { Write-EventLog -LogName Application -Source "agy-mdm" -EventId 1000 -EntryType $type -Message $m }

# ---------------------------------------------------------------- 1. operator automation: OpenSSH from IAP only (Google Cloud)
# elsewhere the device's own management channel is used (Intune / ConfigMgr, or an operator-configured SSH rule)
if ($OnGce) {
if (-not (Get-Service -Name sshd -ErrorAction SilentlyContinue)) {
  Get-WindowsCapability -Online -Name "OpenSSH.Server*" | Where-Object State -ne "Installed" | Add-WindowsCapability -Online | Out-Null
}
& googet -noconfirm=true install google-compute-engine-ssh 2>&1 | Out-Null
Set-Service -Name sshd -StartupType Automatic; Start-Service sshd
if (-not (Get-NetFirewallRule -Name "AGY-OpenSSH-IAP" -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -Name "AGY-OpenSSH-IAP" -DisplayName "AGY operator SSH (IAP)" -Direction Inbound -Protocol TCP `
    -LocalPort 22 -RemoteAddress 35.235.240.0/20 -Action Allow | Out-Null
}
}

# ---------------------------------------------------------------- 2. workspace disk D:\projects
$raw = if ($OnGce) { Get-Disk | Where-Object PartitionStyle -eq "RAW" } else { @() }   # never format disks elsewhere
foreach ($d in $raw) {
  Initialize-Disk -Number $d.Number -PartitionStyle GPT
  New-Partition -DiskNumber $d.Number -UseMaximumSize -DriveLetter D | Format-Volume -FileSystem NTFS -NewFileSystemLabel "projects" -Confirm:$false | Out-Null
  Log "data disk $($d.Number) initialised as D:"
}
# off Google Cloud D: is often a temporary disk (Azure): default C:\projects unless agy-workspace-root says otherwise
$Ws = Get-AgyMeta "agy-workspace-root" $(if ($OnGce -and (Test-Path "D:\")) { "D:\projects" } else { "C:\projects" })
New-Item -ItemType Directory -Force -Path $Ws | Out-Null

# ---------------------------------------------------------------- 3. personas (non-admin) + groups, passwords from Secret Manager
foreach ($g in @{ "AGY-Dev" = "dev"; "AGY-Contractor" = "contractor" }.GetEnumerator()) {
  if (-not (Get-LocalGroup -Name $g.Key -ErrorAction SilentlyContinue)) { New-LocalGroup -Name $g.Key -Description "AGY policy group ($($g.Value))" | Out-Null }
}
$secrets = (Get-AgyMeta agy-desktop-secrets) -split "," | Where-Object { $_ -match "=" }
$verFile = "$Root\secret-ver"; $ver = Get-AgyMeta agy-desktop-secret-ver
$rotate = -not (Test-Path $verFile) -or ((Get-Content $verFile -Raw).Trim() -ne $ver)
foreach ($pair in $secrets) {
  $u, $sid = $pair.Split("=", 2)
  $grp = if ($u -eq "contractor") { "AGY-Contractor" } else { "AGY-Dev" }
  $proj = (Invoke-RestMethod -Headers @{ "Metadata-Flavor" = "Google" } -Uri "http://metadata.google.internal/computeMetadata/v1/project/project-id")
  $exists = [bool](Get-LocalUser -Name $u -ErrorAction SilentlyContinue)
  if (-not $exists -or $rotate) {
    $b64 = Retry { (Invoke-RestMethod -Headers @{ Authorization = "Bearer $(Token)" } `
            -Uri "https://secretmanager.googleapis.com/v1/projects/$proj/secrets/$sid/versions/latest:access").payload.data }
    $pw = ConvertTo-SecureString ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))) -AsPlainText -Force
    if ($exists) { Set-LocalUser -Name $u -Password $pw } else { New-LocalUser -Name $u -Password $pw -PasswordNeverExpires -AccountNeverExpires | Out-Null }
    Log "persona ${u}: password set from Secret Manager"
  }
  foreach ($lg in $grp, "Remote Desktop Users") {
    if (-not (Get-LocalGroupMember -Group $lg -Member $u -ErrorAction SilentlyContinue)) { Add-LocalGroupMember -Group $lg -Member $u }
  }
  # never an administrator
  if (Get-LocalGroupMember -Group "Administrators" -Member $u -ErrorAction SilentlyContinue) { Remove-LocalGroupMember -Group "Administrators" -Member $u; Audit "removed $u from Administrators" "Warning" }
  # workspace: owner = persona (Modify), SYSTEM / Administrators full, nobody else
  $p = Join-Path $Ws $u; New-Item -ItemType Directory -Force -Path $p | Out-Null
  & icacls $p /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "${u}:(OI)(CI)M" | Out-Null
}
if ($secrets) { $ver | Set-Content -Path $verFile -Encoding ascii }
# off Google Cloud (no Secret Manager): personas from agy-personas, created once with a generated, typeable password
# written to an Administrators-only file - hand it over and delete the file; in production use real accounts / Entra ID
# agy-persona-source = groups: no local persona accounts - developers sign in with their own Entra ID / AD accounts and
# the persona comes from directory groups (agy-persona-groups); Apply-AGYControls manages their profiles
$personaSource = Get-AgyMeta "agy-persona-source" "local"
if (-not $secrets -and $personaSource -ne "groups") {
  $pwFile = "$Root\persona-initial-passwords.txt"
  foreach ($u in ((Get-AgyMeta "agy-personas" "dev,contractor") -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^[a-z][a-z0-9-]{1,19}$' })) {
    $grp = if ($u -eq "contractor") { "AGY-Contractor" } else { "AGY-Dev" }
    if (-not (Get-LocalUser -Name $u -ErrorAction SilentlyContinue)) {
      $abc = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789".ToCharArray()
      $plain = -join ((1..13) | ForEach-Object { $abc | Get-Random }) + "Aa7"
      New-LocalUser -Name $u -Password (ConvertTo-SecureString $plain -AsPlainText -Force) -PasswordNeverExpires -AccountNeverExpires | Out-Null
      "$u $plain" | Add-Content $pwFile -Encoding ascii
      & icacls $pwFile /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" /q | Out-Null
      Log "persona ${u}: created, initial password in $pwFile (Administrators only)"; Audit "persona $u created (offline)"
    }
    # agy-rdp = admins | off: personas get no Remote Desktop access (Apply-AGYControls also denies the logon right)
    foreach ($lg in @($grp) + $(if ((Get-AgyMeta agy-rdp "on") -eq "on") { @("Remote Desktop Users") } else { @() })) {
      if (-not (Get-LocalGroupMember -Group $lg -Member $u -ErrorAction SilentlyContinue)) { Add-LocalGroupMember -Group $lg -Member $u }
    }
    if (Get-LocalGroupMember -Group "Administrators" -Member $u -ErrorAction SilentlyContinue) { Remove-LocalGroupMember -Group "Administrators" -Member $u; Audit "removed $u from Administrators" "Warning" }
    $p = Join-Path $Ws $u; New-Item -ItemType Directory -Force -Path $p | Out-Null
    & icacls $p /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "${u}:(OI)(CI)M" | Out-Null
  }
}

# ---------------------------------------------------------------- 4. Antigravity CLI per machine (pinned sha512), no self-update
# device packages: only when the AGY Client package is installed (module marker); classic installs: always
$modKey = "HKLM:\SOFTWARE\Policies\AGY\Modules"
$wantClient = -not (Test-Path $modKey) -or (("" + (Get-Item $modKey).GetValue("client", "")) -ne "")
$dir = "C:\Program Files\Antigravity"; New-Item -ItemType Directory -Force -Path $dir | Out-Null
$exe = Join-Path $dir "agy.exe"
if ($wantClient -and -not (Test-Path $exe)) {
  $m = Retry { Invoke-RestMethod (Get-AgyMeta agy-cli-manifest-url) }
  $url = ($m.url, $m.downloadUrl | Where-Object { $_ } | Select-Object -First 1)
  $want = ($m.sha512, $m.checksum, $m.sha512sum | Where-Object { $_ } | Select-Object -First 1)
  if (-not $url -or -not $want) { throw "CLI manifest lacks url or sha512" }
  & curl.exe -fsSL --retry 3 -o "$exe.tmp" $url; if ($LASTEXITCODE -ne 0) { throw "CLI download failed" }
  $h = (Get-FileHash "$exe.tmp" -Algorithm SHA512).Hash.ToLower()
  if ($h -ne $want.ToLower()) { Remove-Item "$exe.tmp" -Force; throw "agy.exe sha512 mismatch" }
  Move-Item "$exe.tmp" $exe -Force; Log "agy.exe installed sha512=$h"; Audit "Antigravity CLI installed (sha512 $h)"
}
if ($wantClient) {
  [Environment]::SetEnvironmentVariable("AGY_CLI_DISABLE_AUTO_UPDATE", "1", "Machine")
  $path = [Environment]::GetEnvironmentVariable("Path", "Machine"); if (($path -split ";") -notcontains $dir) { [Environment]::SetEnvironmentVariable("Path", "$path;$dir", "Machine") }
}
& icacls $dir /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" | Out-Null

# Windows Terminal (portable build, pinned by SHA-256): text selection with Shift+drag even while a full-screen
# CLI captures the mouse, Ctrl+Shift+C to copy. Installed per machine, read-only for users.
function Install-WindowsTerminal {
  $dst = "C:\Program Files\WindowsTerminal"
  if (Test-Path "$dst\wt.exe") { return }
  $zip = "$env:TEMP\wt.zip"
  & curl.exe -fsSL --retry 3 -o $zip "https://github.com/microsoft/terminal/releases/download/v1.25.2733.0/Microsoft.WindowsTerminal_1.25.2733.0_x64.zip"; if ($LASTEXITCODE -ne 0) { throw "Windows Terminal download failed" }
  $h = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
  if ($h -ne "bf3ef2012f6c44d8340a4c58125acc9498d19b580f9890dc043cdf831852e796") { Remove-Item $zip -Force; throw "Windows Terminal sha256 mismatch ($h)" }
  $tmp = "$env:TEMP\wt-x"; Expand-Archive $zip -DestinationPath $tmp -Force
  $inner = Get-ChildItem $tmp -Directory | Select-Object -First 1
  New-Item -ItemType Directory -Force -Path $dst | Out-Null
  Copy-Item "$($inner.FullName)\*" $dst -Recurse -Force
  Remove-Item $zip, $tmp -Recurse -Force
  & icacls $dst /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" | Out-Null
}
try { Install-WindowsTerminal } catch { Log "WARN: $($_.Exception.Message)" }

# ---------------------------------------------------------------- 4b. desktop shortcuts for every persona (Public Desktop, admin-owned)
$pub = "C:\Users\Public\Desktop"; $wsh = New-Object -ComObject WScript.Shell
function New-Shortcut([string]$name, [string]$target, [string]$arguments, [string]$icon, [string]$dir) {
  $l = $wsh.CreateShortcut((Join-Path $pub "$name.lnk")); $l.TargetPath = $target; $l.Arguments = $arguments
  if ($icon) { $l.IconLocation = $icon }; if ($dir) { $l.WorkingDirectory = $dir }; $l.Save()
}
$desk = "C:\Program Files\Antigravity\Desktop\Antigravity.exe"
if (Test-Path $desk) { New-Shortcut "Antigravity (managed)" $desk "" "$desk,0" "" }
$wt = "C:\Program Files\WindowsTerminal\wt.exe"
if (-not $wantClient) {
  Remove-Item (Join-Path $pub "Antigravity CLI.lnk") -Force -ErrorAction SilentlyContinue
} elseif (Test-Path $wt) {
  New-Shortcut "Antigravity CLI" $wt "-d `"$Ws`" cmd /k `"cd /d $Ws\%USERNAME% && agy`"" "$exe,0" "$Ws"
  New-Shortcut "Workspace terminal" $wt "-d `"$Ws`" cmd /k `"cd /d $Ws\%USERNAME%`"" "$wt,0" "$Ws"
} else {
  New-Shortcut "Antigravity CLI" "$env:SystemRoot\System32\cmd.exe" "/k cd /d $Ws\%USERNAME% && agy" "$exe,0" "$Ws"
  New-Shortcut "Workspace terminal" "$env:SystemRoot\System32\cmd.exe" "/k cd /d $Ws\%USERNAME%" "" "$Ws"
}
Get-ChildItem $pub -Filter "*.lnk" | Where-Object Name -match "Google Cloud SDK" | Remove-Item -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------- 5. Ops Agent: Windows Event Log -> log "agy_winevt" -> SIEM
$opsCfg = "C:\Program Files\Google\Cloud Operations\Ops Agent\config\config.yaml"
$wantOps = $OnGce -or ((Get-AgyMeta "agy-ops-agent" "false") -eq "true")   # off Google Cloud it needs a credential
if ($wantOps -and -not (Get-Service -Name google-cloud-ops-agent -ErrorAction SilentlyContinue)) {
  $inst = "$env:TEMP\add-google-cloud-ops-agent-repo.ps1"
  Retry { Invoke-WebRequest -UseBasicParsing "https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.ps1" -OutFile $inst }
  & powershell -NoProfile -ExecutionPolicy Bypass -File $inst -AlsoInstall | Out-Null
  Log "Ops Agent installed"
}
$want = @"
logging:
  receivers:
    agy_winevt:
      type: windows_event_log
      receiver_version: 2
      channels:
        - Application
        - Security
        - Microsoft-Windows-PowerShell/Operational
        - Microsoft-Windows-AppLocker/EXE and DLL
        - Microsoft-Windows-AppLocker/MSI and Script
        - Microsoft-Windows-CodeIntegrity/Operational
        - Microsoft-Windows-Sysmon/Operational
        - Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
  processors:
    # volume control (measured on the reference VM: ~300k events / day, 75% noise): script blocks of the SYSTEM
    # management tasks, informational AppLocker "allowed" events, Sysmon process-terminate
    agy_drop_noise:
      type: exclude_logs
      match_any:
        - 'jsonPayload.EventID = 4104 AND jsonPayload.UserId = "S-1-5-18"'
        - 'jsonPayload.Channel =~ "^Microsoft-Windows-AppLocker/" AND jsonPayload.Level = 4'
        - 'jsonPayload.Channel = "Microsoft-Windows-Sysmon/Operational" AND jsonPayload.EventID = 5'
  service:
    pipelines:
      agy:
        receivers: [agy_winevt]
        processors: [agy_drop_noise]
"@
$hasBom = (Test-Path $opsCfg) -and (([IO.File]::ReadAllBytes($opsCfg) | Select-Object -First 3) -join ",") -eq "239,187,191"
if ($wantOps -and (Test-Path (Split-Path $opsCfg)) -and ($hasBom -or (-not (Test-Path $opsCfg)) -or ([IO.File]::ReadAllText($opsCfg) -ne $want) -or
    ((Get-Service google-cloud-ops-agent -ErrorAction SilentlyContinue).Status -ne "Running"))) {
  # BOM-less UTF-8: PowerShell 5.1 "-Encoding utf8" writes a BOM, which the Ops Agent rejects ("unknown field ?logging")
  [IO.File]::WriteAllText($opsCfg, $want, (New-Object Text.UTF8Encoding $false))
  Restart-Service google-cloud-ops-agent -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 5
  if ((Get-Service google-cloud-ops-agent).Status -ne "Running") { Audit "Ops Agent not running after config change" "Error"; Log "WARN: Ops Agent not running" }
  else { Log "Ops Agent config applied" }
}
# audit policy: process creation with command line, PowerShell script block logging
& auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null   # Process Creation
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null }
New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWord | Out-Null
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null }
New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord | Out-Null

# ---------------------------------------------------------------- 6. RDP hardening (IAP only at the VPC; NLA; no drive / printer redirection)
$ts = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; if (-not (Test-Path $ts)) { New-Item -Path $ts -Force | Out-Null }
New-ItemProperty -Force -Path $ts -Name UserAuthentication -Value 1 -PropertyType DWord | Out-Null          # NLA
New-ItemProperty -Force -Path $ts -Name fDisableCdm -Value 1 -PropertyType DWord | Out-Null                 # drive redirection off
New-ItemProperty -Force -Path $ts -Name fDisableCpm -Value 1 -PropertyType DWord | Out-Null                 # printer redirection off
New-ItemProperty -Force -Path $ts -Name fDisableClip -Value ([int]((Get-AgyMeta agy-rdp-clipboard "true") -ne "true")) -PropertyType DWord | Out-Null
New-ItemProperty -Force -Path $ts -Name MaxDisconnectionTime -Value 28800000 -PropertyType DWord | Out-Null # 8 h, then the session ends
# agy-rdp = on (default: persona desktops over RDP) | admins (RDP for Administrators / SYSTEM only, e.g. remote support
# by the client-management tool; personas are denied the RDP logon right by Apply-AGYControls) | off (RDP not enabled)
if ((Get-AgyMeta agy-rdp "on") -ne "off") {
  New-ItemProperty -Force -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -Value 0 -PropertyType DWord | Out-Null
  Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------- 7. endpoint controls bundle (WDAC, AppLocker, firewall, CLM, hook, drift)
$bucket = if ($OnGce) { Get-AgyMeta agy-config-bucket } else { "" }; $bundle = "$Root\bundle"
if ($bucket -or (Test-Path "$bundle\files\controls\Apply-AGYControls.ps1")) {
 if ($bucket) {
  New-Item -ItemType Directory -Force -Path $bundle | Out-Null
  $hdr = @{ Authorization = "Bearer $(Token)" }
  $list = Retry { Invoke-RestMethod -Headers $hdr -Uri "https://storage.googleapis.com/storage/v1/b/$bucket/o?prefix=win/files/" }
  foreach ($o in $list.items) {
    $rel = $o.name.Substring(4); $dst = Join-Path $bundle $rel; New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
    Retry { Invoke-WebRequest -UseBasicParsing -Headers $hdr -OutFile $dst `
      -Uri "https://storage.googleapis.com/storage/v1/b/$bucket/o/$([uri]::EscapeDataString($o.name))?alt=media" } | Out-Null
  }
 }
  & icacls $Root /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" | Out-Null
  $apply = Join-Path $bundle "files\controls\Apply-AGYControls.ps1"
  if (Test-Path $apply) { & $apply -Mode (Get-AgyMeta agy-client-mode gateway) -Workspace $Ws; Log "controls applied" }
  else { Log "controls bundle not present yet (delivered in S5)" }
}
Audit "bootstrap complete (mode $(Get-AgyMeta agy-client-mode gateway), bundle $(Get-AgyMeta agy-bundle-hash))"
Log "=== AGY Windows bootstrap done"
