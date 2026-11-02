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
  Removes AGY from a device, per module (called by the uninstall of the SCCM / script packages, as SYSTEM).

  -Scope core      the device baseline: scheduled tasks, egress firewall rules, AppLocker policy (emptied), AGY WDAC
                   policies, the launcher shim and AGY machine environment variables, persona profile locks
                   (deny entries + read-only managed settings), C:\ProgramData\Antigravity (logs archived first)
  -Scope client    the Antigravity CLI / Desktop app, their PATH entry, auto-update switch and shortcuts
  -Scope telemetry the shipper task and its state (spool, bookmarks, exported device key, cached token)
  -Scope personas | seat | identity | edr   nothing on disk: their policy values are removed by the package

  Kept on purpose (data or organisation-wide baseline): persona accounts and groups, workspaces / build / cache
  folders, OS hardening (UAC auto-deny for standard users, sudo off, long paths, audit policy, script-block logging,
  symlink right), Python and Sysmon. Remove those through your own baseline if wanted.
#>
param([Parameter(Mandatory)][ValidateSet("core", "client", "personas", "seat", "telemetry", "identity", "edr")][string]$Scope)
$ErrorActionPreference = "Continue"
$Root = "C:\ProgramData\Antigravity"
$Prog = "C:\Program Files\Antigravity"
$done = New-Object System.Collections.Generic.List[string]
function Note([string]$m) { $done.Add($m); Write-Host "  $m" }
function Audit([string]$m) {
  if ([System.Diagnostics.EventLog]::SourceExists("agy-mdm")) { Write-EventLog -LogName Application -Source "agy-mdm" -EventId 1009 -EntryType Information -Message $m -ErrorAction SilentlyContinue }
}
$envKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
function Remove-MachinePathEntries([scriptblock]$match) {
  $p = (Get-Item $envKey).GetValue("Path", "", "DoNotExpandEnvironmentNames")
  $keep = @($p -split ";" | Where-Object { $_ -and -not (& $match $_) })
  if ($keep.Count -ne @($p -split ";" | Where-Object { $_ }).Count) {
    New-ItemProperty -Path $envKey -Name Path -Value ($keep -join ";") -PropertyType ExpandString -Force | Out-Null
    return $true
  }
  return $false
}

if ($Scope -eq "client") {
  foreach ($t in "agy.exe", "Desktop") {
    $p = Join-Path $Prog $t
    if (Test-Path $p) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue; Note "removed $p" }
  }
  foreach ($f in "versions-state.json", "versions-pending.json", "cli-version.json") { Remove-Item (Join-Path $Root $f) -Force -ErrorAction SilentlyContinue }
  if (Remove-MachinePathEntries { param($e) $e -eq $Prog }) { Note "removed $Prog from the machine PATH" }
  [Environment]::SetEnvironmentVariable("AGY_CLI_DISABLE_AUTO_UPDATE", $null, "Machine")
  foreach ($l in "Antigravity (managed).lnk", "Antigravity CLI.lnk") { Remove-Item (Join-Path "C:\Users\Public\Desktop" $l) -Force -ErrorAction SilentlyContinue }
  Note "client shortcuts and auto-update switch removed"
}

if ($Scope -eq "telemetry" -or $Scope -eq "core") {
  if (Get-ScheduledTask -TaskName "AGY-Telemetry" -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName "AGY-Telemetry" -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "AGY-Telemetry" -Confirm:$false; Note "scheduled task AGY-Telemetry removed"
  }
  if (Test-Path "C:\ProgramData\AntigravityTelemetry") {
    Remove-Item "C:\ProgramData\AntigravityTelemetry" -Recurse -Force -ErrorAction SilentlyContinue; Note "telemetry state removed (spool, exported key, token)"
  }
}

if ($Scope -eq "core") {
  # 1. management tasks first, so nothing re-applies while we remove
  foreach ($t in "AGY-Policy", "AGY-Bootstrap", "AGY-EgressSync", "AGY-CredProxy") {
    if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
      Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
      Unregister-ScheduledTask -TaskName $t -Confirm:$false; Note "scheduled task $t removed"
    }
  }
  Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
    Where-Object CommandLine -match "agy-credproxy" | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  # 2. persona egress firewall rules
  $fw = @(Get-NetFirewallRule -Group "AGY egress" -ErrorAction SilentlyContinue)
  if ($fw) { $fw | Remove-NetFirewallRule; Note "$($fw.Count) egress firewall rules removed" }
  # 3. AppLocker: replace the local policy with an empty one - only when AGY wrote it (its rules carry "AGY"); a local
  #    policy of your own (application control off in AGY) stays untouched. Domain / MDM policies are separate.
  $localAl = $(try { [string](Get-AppLockerPolicy -Local -Xml) } catch { "" })
  if ($localAl -match 'Description="AGY"|Name="AGY ') {
    $empty = "$env:TEMP\agy-applocker-empty.xml"
    # every collection explicitly empty + NotConfigured: a bare <AppLockerPolicy/> leaves the Script / Appx / Msi
    # caches (System32\AppLocker\*.AppLocker) in force, so personas would stay in Constrained Language Mode
    ('<AppLockerPolicy Version="1">' + (("Exe", "Msi", "Script", "Dll", "Appx" | ForEach-Object { "<RuleCollection Type=""$_"" EnforcementMode=""NotConfigured"" />" }) -join "") +
     '</AppLockerPolicy>') | Set-Content $empty -Encoding ascii
    try { Set-AppLockerPolicy -XmlPolicy $empty; Note "local AppLocker policy (AGY rules) emptied" } catch { Note "AppLocker: $($_.Exception.Message)" }
    Remove-Item $empty -Force -ErrorAction SilentlyContinue
  } else { Note "local AppLocker policy has no AGY rules - left unchanged" }
  # 4. WDAC: the AGY base and supplemental policies (their .cip files are named after the policy GUID)
  foreach ($cip in @(Get-ChildItem $Root -Filter "{*}.cip" -ErrorAction SilentlyContinue)) {
    $guid = $cip.BaseName
    if (Get-Command CiTool.exe -ErrorAction SilentlyContinue) {
      & CiTool.exe --remove-policy $guid -json 2>&1 | Out-Null
      Note "WDAC policy $guid removed (CiTool exit $LASTEXITCODE)"
    } else {   # Windows 10: no CiTool - the policy was staged in the active-policy folder; unloaded at the next reboot
      Remove-Item "$env:windir\System32\CodeIntegrity\CiPolicies\Active\$guid.cip" -Force -ErrorAction SilentlyContinue
      Note "WDAC policy $guid removed from the active-policy folder (unloaded at the next reboot)"
    }
  }
  # 5. persona profiles: lift the AGY locks (deny entries, SYSTEM-owned read-only settings) and delete managed files
  $cfgPs = Join-Path $PSScriptRoot "AGYConfig.ps1"
  $profiles = if (Test-Path $cfgPs) { . $cfgPs; @(Get-AgyKnownProfiles) } else { @() }
  foreach ($pp in $profiles) {
    $sid = "*$($pp.Sid)"; $h = $pp.Home
    foreach ($d in $h, "$h\.gemini", "$h\.gemini\antigravity-cli", "$h\.gemini\config", "$h\.gemini\antigravity") {
      if (Test-Path $d) { & icacls $d /remove:d $sid /q | Out-Null }
    }
    foreach ($f in "$h\.gemini\antigravity-cli\settings.json", "$h\.gemini\config\hooks.json", "$h\.gemini\config\mcp_config.json",
                   "$h\.gemini\antigravity\browserAllowlist.txt") {
      if (Test-Path $f) { & icacls $f /setowner $sid /q | Out-Null; Remove-Item $f -Force -ErrorAction SilentlyContinue }
    }
    Note "profile $($pp.Name): AGY locks lifted, managed settings removed"
  }
  # 6. launcher shim + machine environment set by the controls
  if (Test-Path "$Prog\bin") { Remove-Item "$Prog\bin" -Recurse -Force -ErrorAction SilentlyContinue; Note "launcher shim removed" }
  if (Remove-MachinePathEntries { param($e) $e -eq "$Prog\bin" -or $e -match '\\caches\\%USERNAME%\\' }) { Note "AGY entries removed from the machine PATH" }
  $agyEnv = "UseArtifactsOutput", "ArtifactsPath", "NUGET_PACKAGES", "npm_config_cache", "PIP_CACHE_DIR", "GOCACHE", "GOMODCACHE",
            "GOTMPDIR", "npm_config_prefix", "GOBIN", "PIPX_HOME", "PIPX_BIN_DIR", "WORKON_HOME", "POETRY_VIRTUALENVS_PATH",
            "UV_CACHE_DIR", "UV_TOOL_DIR", "UV_TOOL_BIN_DIR", "UV_PYTHON_INSTALL_DIR", "npm_config_registry", "PIP_INDEX_URL", "GOPROXY"
  $n = 0; foreach ($k in $agyEnv) { if ($null -ne (Get-Item $envKey).GetValue($k, $null)) { Remove-ItemProperty -Path $envKey -Name $k; $n++ } }
  if ($n) { Note "$n AGY machine environment variables removed" }
  # 6a. user right "Deny log on through Remote Desktop Services": remove the AGY persona groups (agy-rdp = admins)
  $agyG = @(Get-LocalGroup -Name "AGY-Dev", "AGY-Contractor" -ErrorAction SilentlyContinue | ForEach-Object { $_.SID.Value })
  if ($agyG) {
    $inf = "$env:TEMP\agy-rm-secpol.inf"; $db = "$env:TEMP\agy-rm-secpol.sdb"
    & secedit /export /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
    $line = (Get-Content $inf | Where-Object { $_ -match "^SeDenyRemoteInteractiveLogonRight\s*=" }) | Select-Object -First 1
    if ($line) {
      $vals = @(($line -split "=", 2)[1] -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($agyG -notcontains $_.TrimStart("*")) -and $_ -notin "AGY-Dev", "AGY-Contractor" })
      $new = "SeDenyRemoteInteractiveLogonRight = " + ($vals -join ",")
      if ($new -ne $line) {
        "[Unicode]`r`nUnicode=yes`r`n[Privilege Rights]`r`n$new`r`n[Version]`r`nsignature=`"`$CHICAGO`$`"`r`nRevision=1`r`n" | Set-Content $inf -Encoding Unicode
        & secedit /configure /db $db /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
        Note "AGY persona groups removed from 'Deny log on through Remote Desktop Services'"
      }
    }
    Remove-Item $inf, $db -Force -ErrorAction SilentlyContinue
  }
  # 6b. hosts entries written by AGY (endpoint sinkholes "# agy-pin", gateway name "# agy-poc-gw")
  $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
  $hl = @(Get-Content $hostsFile -ErrorAction SilentlyContinue)
  $keepH = @($hl | Where-Object { $_ -notmatch '# agy-(pin|poc-gw)$' })
  if ($keepH.Count -ne $hl.Count) {
    for ($i = 1; $i -le 6; $i++) {   # Defender / DNS client briefly lock the file after a change
      try { [IO.File]::WriteAllText($hostsFile, (($keepH -join "`r`n") + "`r`n"), [Text.Encoding]::ASCII); Note "$($hl.Count - $keepH.Count) AGY hosts entries removed"; break }
      catch { Start-Sleep -Seconds (2 * $i) }
    }
  }
  # 7. state: archive the audit-relevant logs (Administrators only), then remove C:\ProgramData\Antigravity
  if (Test-Path $Root) {
    $arc = "C:\ProgramData\AntigravityRemoved\$((Get-Date).ToString('yyyyMMdd-HHmmss'))"
    New-Item -ItemType Directory -Force -Path $arc | Out-Null
    Get-ChildItem "$Root\*" -File -Include *.log, *.json -ErrorAction SilentlyContinue | Copy-Item -Destination $arc -ErrorAction SilentlyContinue
    & icacls "C:\ProgramData\AntigravityRemoved" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /q | Out-Null
    Remove-Item $Root -Recurse -Force -ErrorAction SilentlyContinue
    Note "C:\ProgramData\Antigravity removed (logs archived in $arc)"
  }
}

Audit "AGY_UNINSTALL scope=${Scope}: $($done -join '; ')"
Write-Host "AGY uninstall ($Scope) done: $($done.Count) step(s)"
