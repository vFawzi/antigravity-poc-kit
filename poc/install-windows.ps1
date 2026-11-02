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

<#
.SYNOPSIS
  Antigravity pay-as-you-go POC: Windows endpoint script (run once by IT, in an elevated PowerShell, from the kit folder).

  .\install-windows.ps1 -Install [-User <DOMAIN\user | AzureAD\user@corp | local user>] [-Yes]   install + self-test
                       (no -User: the signed-in user is proposed as device owner)
                       [-Offline]   (no gateway reachability check, e.g. IT bench before the VPN)
  .\install-windows.ps1 -Test                                                            PASS / FAIL per control
  .\install-windows.ps1 -Collect                                                         evidence zip
  .\install-windows.ps1 -Uninstall                                                       remove everything, then -Test

  The kit folder holds poc.json, device.crt, device.key, gateway-ca.pem and bundle\ (endpoint controls). Installs:
  pinned Antigravity client, locked admin settings (gateway -> local credential proxy), corporate hook (stricter for
  contractors; noisy rules in audit during week 1), credential proxy with the device certificate (key readable by
  SYSTEM / Administrators only), terminal sandbox where Windows supports it, self-test. Optional layers (off by default
  on daily-use laptops): -AppControl (AppLocker + WDAC audit), -Sysmon.
#>
[CmdletBinding(DefaultParameterSetName = "Install")]
param(
  [Parameter(ParameterSetName = "Install")][switch]$Install,
  [Parameter(ParameterSetName = "Test", Mandatory)][switch]$Test,
  [Parameter(ParameterSetName = "Collect", Mandatory)][switch]$Collect,
  [Parameter(ParameterSetName = "Uninstall", Mandatory)][switch]$Uninstall,
  # the device owner's account (standard user); it is added to the local persona group
  [Parameter(ParameterSetName = "Install")][string]$User = "",
  [Parameter(ParameterSetName = "Install")][switch]$AppControl,
  [Parameter(ParameterSetName = "Install")][switch]$Sysmon,
  # lab simulation only: allow Windows Server (no terminal sandbox: every agent command needs approval)
  [Parameter(ParameterSetName = "Install")][switch]$AllowServer,
  # install without network access to the gateway (IT bench before the VPN, lab without VPN): skips only the
  # reachability check; the gateway self-test (P02) reports FAIL until the device is on the network
  [Parameter(ParameterSetName = "Install")][switch]$Offline,
  # accept the proposed device owner (the signed-in user) without asking
  [Parameter(ParameterSetName = "Install")][switch]$Yes,
  [string]$Kit = ""
)
$ErrorActionPreference = "Stop"
if (-not $Kit) { $Kit = Split-Path -Parent $MyInvocation.MyCommand.Path }   # PowerShell 5.1: no $PSScriptRoot in param defaults
$Root = "C:\ProgramData\Antigravity"
$PocState = "C:\ProgramData\AntigravityPOC"          # survives uninstall of $Root: install record, test and collect output
$HostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$HostsMarker = "# agy-poc-gw"
$PersonaGroups = @{ "dev" = "AGY-Dev"; "contractor" = "AGY-Contractor" }

function Say([string]$m) { Write-Host "[poc] $m" }
function Fail([string]$m) { Write-Host "[poc] ERROR: $m" -ForegroundColor Red; exit 1 }
function Assert-Admin {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail "run in an elevated PowerShell (administrator)" }
}
function Read-Kit {
  $f = Join-Path $Kit "poc.json"
  if (-not (Test-Path $f)) { Fail "poc.json not found in $Kit" }
  $c = Get-Content $f -Raw | ConvertFrom-Json
  if ($c.schema -ne "agy-poc-kit/1") { Fail "poc.json: unsupported schema '$($c.schema)'" }
  if ($c.os -ne "windows") { Fail "this kit is for $($c.os), not Windows" }
  if ($c.persona -notin $PersonaGroups.Keys) { Fail "poc.json: unknown persona '$($c.persona)'" }
  $c
}
function New-PocState {
  New-Item -ItemType Directory -Force -Path $PocState | Out-Null
  & icacls $PocState /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /q | Out-Null
}
function Get-OsInfo {
  $cv = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
  $os = Get-CimInstance Win32_OperatingSystem
  [pscustomobject]@{ Caption = $os.Caption; Build = [int]$cv.CurrentBuild; Ubr = [int]$cv.UBR; Client = ($os.ProductType -eq 1) }
}
function Set-HostsEntry([string]$ip, [string]$name) {
  $lines = @(Get-Content $HostsFile -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch [regex]::Escape($HostsMarker) + '$' })
  if ($ip) { $lines += "$ip $name $HostsMarker" }
  for ($i = 1; $i -le 6; $i++) {   # Defender / DNS client briefly lock the hosts file after a change
    try { [IO.File]::WriteAllText($HostsFile, (($lines -join "`r`n") + "`r`n"), [Text.Encoding]::ASCII); return }
    catch { Start-Sleep -Seconds (2 * $i) }
  }
  Fail "hosts file locked - retry"
}
function Resolve-Account([string]$name) {
  try { (New-Object Security.Principal.NTAccount($name)).Translate([Security.Principal.SecurityIdentifier]).Value }
  catch { $null }
}
function Test-IsLocalAdmin([string]$sid) {
  $adm = @(Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction SilentlyContinue | ForEach-Object { $_.SID.Value })
  $adm -contains $sid
}
function Invoke-GatewayHandshake($cfg) {
  # TLS + mTLS to the gateway front door with the device certificate, as this (SYSTEM / admin) process: proves name
  # resolution, routing over the VPN, the server certificate and that the load balancer accepts the device certificate
  $py = "C:\Program Files\Python312\python.exe"
  if (-not (Test-Path $py)) { return "python not installed yet" }
  $code = @'
import json, socket, ssl, sys
host, port, d = sys.argv[1], 443, sys.argv[2]
ctx = ssl.create_default_context(cafile=d + "\\root.pem")
ctx.load_cert_chain(d + "\\device.crt", d + "\\device.key")
with socket.create_connection((host, port), timeout=30) as s, ctx.wrap_socket(s, server_hostname=host) as t:
    t.sendall(f"GET /_gw/health HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
    print("OK " + t.version() + " " + t.recv(64).decode(errors="replace").splitlines()[0])
'@
  $tmp = Join-Path $env:TEMP "agy-poc-tls.py"; [IO.File]::WriteAllText($tmp, $code)
  $prev = $ErrorActionPreference; $ErrorActionPreference = "Continue"   # Python writes errors to stderr: report, don't abort
  $out = @(& $py $tmp $cfg.gateway.hostname "$Root\credproxy" 2>&1 | ForEach-Object { "$_" })
  $ErrorActionPreference = $prev
  Remove-Item $tmp -Force -ErrorAction SilentlyContinue
  [string]($out | Where-Object { $_ } | Select-Object -Last 1)
}

# ----------------------------------------------------------------------------- -Install
function Invoke-Install {
  Assert-Admin
  $t0 = Get-Date
  $cfg = Read-Kit
  foreach ($f in "device.crt", "device.key", "gateway-ca.pem", "bundle\bootstrap.ps1", "bundle\files\controls\Apply-AGYControls.ps1", "Install-AGYEndpoint.ps1") {
    if (-not (Test-Path (Join-Path $Kit $f))) { Fail "kit file missing: $f" }
  }
  $os = Get-OsInfo
  Say "device $($cfg.device_id) ($($cfg.persona)) - $($os.Caption) build $($os.Build).$($os.Ubr)"
  if (-not $os.Client -and -not $AllowServer) { Fail "Windows 11 required (Windows Server only with -AllowServer, lab simulation)" }
  if ($os.Client -and $os.Build -lt 26100) { Fail "Windows 11 24H2 (build 26100) or later required for the terminal sandbox; this device: $($os.Build)" }
  if (-not $os.Client) { Say "LAB SIMULATION: Windows Server has no terminal sandbox - every agent command needs approval" }
  # owner account -> persona group (never an administrator: the POC proves the user can't remove the controls)
  if (-not $User) {
    # propose the user signed in at the console (the device owner signs in once before IT runs the script)
    $User = [string](Get-CimInstance Win32_ComputerSystem).UserName
    if (-not $User) { Fail "nobody is signed in at the console - let the owner sign in, or pass -User (e.g. AzureAD\$($cfg.owner) or DOMAIN\user)" }
    if (-not $Yes) {
      $a = Read-Host "Device owner: $User (kit owner: $($cfg.owner)) - correct? (y/n)"
      if ($a -notmatch '^(y|yes)$') { Fail "cancelled - pass -User <account> to choose the owner" }
    }
    Say "device owner: $User (signed-in user)"
  }
  $sid = Resolve-Account $User
  if (-not $sid) { Fail "account '$User' not found on this device" }
  if (Test-IsLocalAdmin $sid) { Fail "'$User' is a local administrator - POC users must be standard users" }
  # gateway reachable over the VPN / internal network
  if ($cfg.gateway.ip) {
    if ($Offline) { Say "offline install: gateway reachability not checked (P02 fails until the device is on the VPN)" }
    else {
      $tcp = Test-NetConnection -ComputerName $cfg.gateway.ip -Port 443 -WarningAction SilentlyContinue
      if (-not $tcp.TcpTestSucceeded) { Fail "gateway $($cfg.gateway.ip):443 not reachable - check the VPN / routing (checklist B1-B4), or use -Offline" }
    }
    Set-HostsEntry $cfg.gateway.ip $cfg.gateway.hostname
    Say "hosts: $($cfg.gateway.ip) $($cfg.gateway.hostname)"
  }
  # device certificate for the credential proxy: SYSTEM / Administrators only
  $cp = "$Root\credproxy"
  New-Item -ItemType Directory -Force -Path $cp | Out-Null
  & icacls $Root /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /q | Out-Null
  & icacls $cp /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /q | Out-Null
  Copy-Item (Join-Path $Kit "device.crt") "$cp\device.crt" -Force
  Copy-Item (Join-Path $Kit "device.key") "$cp\device.key" -Force
  Copy-Item (Join-Path $Kit "gateway-ca.pem") "$cp\root.pem" -Force
  Say "device certificate installed (key readable by SYSTEM / Administrators only)"
  # persona group membership (local group SID is in the user's logon token -> proxy, hook and settings)
  foreach ($g in $PersonaGroups.Values) {
    if (-not (Get-LocalGroup -Name $g -ErrorAction SilentlyContinue)) { New-LocalGroup -Name $g -Description "AGY managed" | Out-Null }
  }
  $want = $PersonaGroups[$cfg.persona]
  foreach ($g in $PersonaGroups.Values) {
    $isMember = @(Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -eq $sid }).Count -gt 0
    if ($g -eq $want -and -not $isMember) { Add-LocalGroupMember -Group $g -Member $sid }
    if ($g -ne $want -and $isMember) { Remove-LocalGroupMember -Group $g -Member $sid }
  }
  Say "$User -> $want"
  # endpoint settings for the existing installer (gateway mode, certificate device proof, POC layer profile)
  $params = [ordered]@{
    "agy-client-mode"        = "gateway"
    "agy-gateway-url"        = $cfg.gateway.url
    "agy-device-auth"        = "cert"
    "agy-cli-manifest-url"   = $cfg.client.cli_manifest_url
    "agy-version-policy"     = $cfg.client.version_policy
    "agy-desktop-windows-object" = $cfg.client.desktop_object
    "agy-desktop-sha256"     = $cfg.client.desktop_sha256
    "agy-workspace-root"     = "C:\projects"
    "agy-persona-source"     = "groups"
    "agy-personas"           = ""
    "agy-sandbox"            = "auto"
    "agy-wdac-mode"          = "Audit"
    "agy-app-control"        = $(if ($AppControl) { "on" } else { "off" })
    "agy-sysmon"             = $(if ($Sysmon) { "on" } else { "off" })
    "agy-rdp"                = "admins"   # remote support by Administrators / SYSTEM keeps working; personas denied
    "agy-hook-audit-classes" = $(if ($cfg.hook.noisy -eq "audit") { ($cfg.hook.audit_classes -join ",") } else { "" })
    "agy-hosts-pin"          = $cfg.hosts_pin
    "agy-ops-agent"          = "false"
    "agy-cost-center"        = "poc-$($cfg.persona)"
  }
  New-PocState
  $pf = "$PocState\params.json"
  [IO.File]::WriteAllText($pf, ($params | ConvertTo-Json), (New-Object Text.UTF8Encoding $false))
  Copy-Item (Join-Path $Kit "poc.json") "$PocState\poc.json" -Force
  Say "running the endpoint installer (Python, client, controls) - typically 3-6 minutes"
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Kit "Install-AGYEndpoint.ps1") -ParamsFile $pf -BundleDir (Join-Path $Kit "bundle")
  if ($LASTEXITCODE -ne 0) { Fail "endpoint installer failed (exit $LASTEXITCODE) - see $Root\bootstrap.log" }
  # the proxy re-reads the files per request; restart so the first request already uses the dropped certificate
  Stop-ScheduledTask -TaskName "AGY-CredProxy" -ErrorAction SilentlyContinue; Start-ScheduledTask -TaskName "AGY-CredProxy"
  $mins = [math]::Round(((Get-Date) - $t0).TotalMinutes, 1)
  [ordered]@{ device = $cfg.device_id; persona = $cfg.persona; user = $User; sid = $sid; installed = (Get-Date).ToString("s")
              minutes = $mins; os_build = "$($os.Build).$($os.Ubr)"; app_control = [bool]$AppControl; sysmon = [bool]$Sysmon
              sysmon_preinstalled = (Test-Path "C:\Program Files\Sysmon\Sysmon64.exe") } |
    ConvertTo-Json | Set-Content "$PocState\install.json" -Encoding utf8
  Say "installed in $mins min (target < 10, no reboot); running the self-test"
  Invoke-Test
  Say "Ask $User to sign out and in once (group membership and PATH apply to new sessions)."
}

# ----------------------------------------------------------------------------- -Test
function Invoke-Test {
  Assert-Admin
  $rows = New-Object System.Collections.Generic.List[object]
  function Add-Row([string]$st, [string]$id, [string]$title, [string]$detail) { $rows.Add([pscustomobject]@{ status = $st; id = $id; title = $title; detail = $detail }) }
  if (-not (Test-Path "$Root\bundle\files\controls\Test-AGYEndpoint.ps1")) {
    $left = @()
    if (Test-Path $Root) { $left += $Root }
    if (Select-String -Path $HostsFile -Pattern ([regex]::Escape($HostsMarker)) -Quiet) { $left += "hosts entry" }
    foreach ($t in "AGY-Policy", "AGY-Bootstrap", "AGY-CredProxy", "AGY-EgressSync") { if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) { $left += "task $t" } }
    if (Test-Path "C:\Program Files\Antigravity\agy.exe") { $left += "agy.exe" }
    if ($left) { Add-Row "FAIL" "P00" "Not installed, but leftovers found" ($left -join ", ") }
    else { Add-Row "PASS" "P00" "Not installed" "no AGY files, tasks or hosts entries" }
  } else {
    $cfg = $(try { Get-Content "$PocState\poc.json" -Raw | ConvertFrom-Json } catch { $null })
    $inst = $(try { Get-Content "$PocState\install.json" -Raw | ConvertFrom-Json } catch { $null })
    $prev = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    $lines = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$Root\bundle\files\controls\Test-AGYEndpoint.ps1" 2>$null)
    $ErrorActionPreference = $prev
    foreach ($l in $lines) {
      if ($l -match '^RESULT\|(\w+)\|([^|]+)\|([^|]*)\|(.*)$') { Add-Row $Matches[1] $Matches[2] $Matches[3] $Matches[4] }
    }
    if ($cfg) {
      # P01 gateway name pinned to the internal address
      $h = Select-String -Path $HostsFile -Pattern ([regex]::Escape($HostsMarker) + '$') | Select-Object -First 1
      if (-not $cfg.gateway.pin_hosts) { Add-Row "SKIP" "P01" "Gateway name resolves to the internal address" "DNS provided by the customer" }
      elseif ($h -and $h.Line -match [regex]::Escape($cfg.gateway.hostname)) { Add-Row "PASS" "P01" "Gateway name resolves to the internal address" $h.Line }
      else { Add-Row "FAIL" "P01" "Gateway name resolves to the internal address" "hosts entry missing" }
      # P02 mTLS handshake with the device certificate
      $hs = Invoke-GatewayHandshake $cfg
      Add-Row $(if ($hs -like "OK *") { "PASS" } else { "FAIL" }) "P02" "Device certificate accepted by the gateway front door (mTLS)" $hs
      # P03 owner mapped to the persona group, not an administrator
      if ($inst) {
        $g = $PersonaGroups[$cfg.persona]
        $m = @(Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -eq $inst.sid }).Count -gt 0
        $adm = Test-IsLocalAdmin $inst.sid
        Add-Row $(if ($m -and -not $adm) { "PASS" } else { "FAIL" }) "P03" "Device owner is a standard user in the persona group" "$($inst.user) in ${g}: $m; local admin: $adm"
        # P04 install time
        Add-Row $(if ([double]$inst.minutes -lt 10) { "PASS" } else { "WARN" }) "P04" "Install time under 10 minutes, no reboot" "$($inst.minutes) min"
      }
      # P06 Remote Desktop: Administrators / SYSTEM only (remote support), persona groups denied
      $inf = Join-Path $env:TEMP "agy-poc-rights.inf"
      & secedit /export /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
      $deny = [string](Get-Content $inf -ErrorAction SilentlyContinue | Where-Object { $_ -match "^SeDenyRemoteInteractiveLogonRight" })
      Remove-Item $inf -Force -ErrorAction SilentlyContinue
      $gSids = @(Get-LocalGroup -Name "AGY-Dev", "AGY-Contractor" -ErrorAction SilentlyContinue | ForEach-Object { $_.SID.Value })
      $denied = @($gSids | Where-Object { $deny -match [regex]::Escape($_) -or $deny -match "AGY-(Dev|Contractor)" }).Count -eq $gSids.Count -and $gSids.Count -gt 0
      $rdpOn = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections -eq 0
      $rdu = @(Get-LocalGroupMember -SID "S-1-5-32-555" -ErrorAction SilentlyContinue | Where-Object { $inst -and $_.SID.Value -eq $inst.sid }).Count -gt 0
      Add-Row $(if ($rdpOn -and $denied -and -not $rdu) { "PASS" } else { "FAIL" }) "P06" "Remote Desktop for Administrators only (persona groups denied)" "RDP enabled: $rdpOn; persona groups denied RDP logon: $denied; owner in Remote Desktop Users: $rdu"
      # P05 device certificate lifetime
      $c = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList "$Root\credproxy\device.crt"
      $days = [int]($c.NotAfter - (Get-Date)).TotalDays
      Add-Row $(if ($days -ge 7) { "PASS" } elseif ($days -ge 0) { "WARN" } else { "FAIL" }) "P05" "Device certificate valid" "until $($c.NotAfter.ToString('yyyy-MM-dd')) ($days days)"
    }
  }
  New-PocState
  $rows | ConvertTo-Json -Depth 4 | Set-Content "$PocState\test.json" -Encoding utf8
  $rows | Format-Table -AutoSize status, id, title, detail | Out-String -Width 220 | Write-Host
  $fails = @($rows | Where-Object status -eq "FAIL").Count
  Say "$(@($rows | Where-Object status -eq 'PASS').Count) PASS, $(@($rows | Where-Object status -eq 'WARN').Count) WARN, $fails FAIL, $(@($rows | Where-Object status -eq 'SKIP').Count) SKIP - $PocState\test.json"
}

# ----------------------------------------------------------------------------- -Collect
function Invoke-Collect {
  Assert-Admin
  New-PocState
  $ts = (Get-Date).ToString("yyyyMMdd-HHmmss")
  $dev = $(try { (Get-Content "$PocState\poc.json" -Raw | ConvertFrom-Json).device_id } catch { $env:COMPUTERNAME.ToLower() })
  $w = Join-Path $env:TEMP "agy-collect-$ts"; New-Item -ItemType Directory -Force -Path $w | Out-Null
  # AGY events from the Application log (hook decisions, controls, uninstall), plus the security channels if present
  $q = "*[System[Provider[@Name='agy-hook' or @Name='agy-mdm' or @Name='agy-shim' or @Name='agy-launch']]]"
  & wevtutil epl Application "$w\agy-application.evtx" "/q:$q" 2>$null
  Get-WinEvent -FilterXPath $q -LogName Application -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message | ConvertTo-Json -Depth 3 | Set-Content "$w\agy-application.json" -Encoding utf8
  foreach ($ch in "Microsoft-Windows-AppLocker/EXE and DLL", "Microsoft-Windows-AppLocker/MSI and Script",
                  "Microsoft-Windows-CodeIntegrity/Operational", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-PowerShell/Operational") {
    if (Get-WinEvent -ListLog $ch -ErrorAction SilentlyContinue) { & wevtutil epl $ch "$w\$(($ch -replace '[\\/ ]', '_')).evtx" "/q:*[System[TimeCreated[timediff(@SystemTime) <= 1209600000]]]" 2>$null }
  }
  # state files (no keys), proxy log, POC records, users' CLI logs
  if (Test-Path $Root) {
    Get-ChildItem $Root -File -Include *.log, *.json, gateway_url -Recurse -Depth 1 -ErrorAction SilentlyContinue |
      Where-Object { $_.FullName -notmatch '\\credproxy\\' } | Copy-Item -Destination $w -ErrorAction SilentlyContinue
    Copy-Item "$Root\hooks\policy.json" "$w\hook-policy.json" -ErrorAction SilentlyContinue
  }
  Copy-Item "$PocState\*.json" $w -ErrorAction SilentlyContinue
  Remove-Item "$w\params.json" -ErrorAction SilentlyContinue
  Copy-Item "$PocState\params.json" "$w\endpoint-params.json" -ErrorAction SilentlyContinue
  foreach ($p in Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue) {
    $logs = Join-Path $p.FullName ".gemini\antigravity-cli\log"
    if (Test-Path $logs) { $d = "$w\cli-logs\$($p.Name)"; New-Item -ItemType Directory -Force -Path $d | Out-Null; Copy-Item "$logs\cli-*.log" $d -ErrorAction SilentlyContinue }
  }
  Invoke-Test *> "$w\test-output.txt"
  $zip = "$PocState\collect-$dev-$ts.zip"
  Compress-Archive -Path "$w\*" -DestinationPath $zip -Force
  Remove-Item $w -Recurse -Force
  Say "evidence: $zip (Administrators only)"
}

# ----------------------------------------------------------------------------- -Uninstall
function Invoke-Uninstall {
  Assert-Admin
  $inst = $(try { Get-Content "$PocState\install.json" -Raw | ConvertFrom-Json } catch { $null })
  $rm = "$Root\bundle\files\controls\Remove-AGYEndpoint.ps1"
  if (Test-Path $rm) {
    # copy first: -Scope core deletes $Root (incl. the script folder)
    $tmp = Join-Path $env:TEMP "agy-remove"; New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    Copy-Item "$Root\bundle\files\controls\Remove-AGYEndpoint.ps1", "$Root\bundle\files\controls\AGYConfig.ps1" $tmp -Force
    foreach ($s in "client", "core") { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$tmp\Remove-AGYEndpoint.ps1" -Scope $s }
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
  } else { Say "endpoint controls not present - cleaning leftovers only" }
  Set-HostsEntry "" ""
  # POC-specific leftovers: Sysmon (only if this POC installed it), canary, persona groups, workspace folders stay (data)
  if ($inst -and $inst.sysmon -and -not $inst.sysmon_preinstalled -and (Test-Path "C:\Program Files\Sysmon\Sysmon64.exe")) {
    Start-Process "C:\Program Files\Sysmon\Sysmon64.exe" -ArgumentList "-u" -Wait -NoNewWindow; Remove-Item "C:\Program Files\Sysmon" -Recurse -Force -ErrorAction SilentlyContinue
    Say "Sysmon removed"
  }
  Remove-Item "C:\secure-admin" -Recurse -Force -ErrorAction SilentlyContinue
  foreach ($g in @($PersonaGroups.Values) + "AGY-NoContainers", "AGY-ContainerDev") {
    if (Get-LocalGroup -Name $g -ErrorAction SilentlyContinue) { Remove-LocalGroup -Name $g; Say "local group $g removed" }
  }
  if (Test-Path "C:\Program Files\Antigravity") { Remove-Item "C:\Program Files\Antigravity" -Recurse -Force -ErrorAction SilentlyContinue }
  Remove-Item "$PocState\params.json", "$PocState\poc.json", "$PocState\install.json" -Force -ErrorAction SilentlyContinue
  Say "uninstalled (kept: Python, workspaces under C:\projects, OS hardening baseline, evidence in $PocState)"
  Invoke-Test
}

switch ($PSCmdlet.ParameterSetName) {
  "Install"   { Invoke-Install }
  "Test"      { Invoke-Test }
  "Collect"   { Invoke-Collect }
  "Uninstall" { Invoke-Uninstall }
}
