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

# AGY Windows endpoint controls (stand-in for the SCCM / Intune deployment). Runs as SYSTEM at boot (bootstrap) and
# every 5 min + at every logon (scheduled task AGY-Policy): idempotent, repairs drift, audits every change.
#   S5a  managed admin settings, read-only per-persona settings and corporate hooks, onboarding seed, canary
# Later stages (egress firewall, WDAC / AppLocker, PowerShell CLM) are added as separate functions.
param(
  [ValidateSet("gateway", "seat")][string]$Mode = "gateway",
  [string]$Workspace = "D:\projects",
  [switch]$PolicyOnly
)
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "AGYConfig.ps1")   # settings: MDM registry > params.json > GCE metadata
$Bundle = Split-Path $PSScriptRoot -Parent          # ...\bundle\files
$Root = "C:\ProgramData\Antigravity"
$Utf8 = New-Object Text.UTF8Encoding $false
$Personas = @{ "dev" = "agy-dev"; "contractor" = "agy-contractor" }

function Audit([string]$m, [string]$type = "Information") {
  Write-EventLog -LogName Application -Source "agy-mdm" -EventId 1000 -EntryType $type -Message $m
}
function Write-IfChanged([string]$path, [string]$text) {
  # BOM-less UTF-8; returns $true when the content was different (drift or first write)
  $cur = if (Test-Path $path) { [IO.File]::ReadAllText($path) } else { $null }
  $bom = (Test-Path $path) -and ((([IO.File]::ReadAllBytes($path) | Select-Object -First 3) -join ",") -eq "239,187,191")
  if ($cur -ne $text -or $bom) {
    New-Item -ItemType Directory -Force -Path (Split-Path $path) | Out-Null
    if (Test-Path $path) { & icacls $path /reset /q | Out-Null }   # regain write after our own read-only ACL
    [IO.File]::WriteAllText($path, $text, $Utf8); return [bool]$cur
  }
  return $false
}
function Set-ReadOnlyFor([string]$path, [string]$user) {
  # SYSTEM / Administrators full, persona read only, nobody else; persona can't change ACL or owner
  & icacls $path /setowner "*S-1-5-18" /q | Out-Null
  & icacls $path /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" "${user}:RX" /q | Out-Null
}
function Deny-DeleteChild([string]$dir, [string]$user) {
  # A folder's "delete subfolders and files" right lets its owner delete / rename children whatever the child's
  # own ACL says. Deny it on the folders that hold the managed files (this folder only, not inherited).
  & icacls $dir /deny "${user}:(DC)" /q | Out-Null
}

# ---------------------------------------------------------------- managed admin settings (gateway / seat)
$adminSrc = Join-Path $Bundle ("policies\" + $(if ($Mode -eq "seat") { "admin_settings.seat.json" } else { "admin_settings.json" }))
$cc = Get-AgyParam "agy-cost-center" ""
$admin = ([IO.File]::ReadAllText($adminSrc)).Replace("@COST_CENTER@", $(if ($cc) { $cc } else { "unset" }))
if (Write-IfChanged "$Root\admin_settings.json" $admin) { Audit "ADMIN_SETTINGS_DRIFT corrected ($Mode)" "Warning" }
& icacls "$Root\admin_settings.json" /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" "*S-1-5-32-545:R" /q | Out-Null

# ---------------------------------------------------------------- corporate hook + Windows policy (admin-only write)
$hooks = "$Root\hooks"; New-Item -ItemType Directory -Force -Path $hooks | Out-Null
$hookChanged = Write-IfChanged "$hooks\agy-hook.py" ([IO.File]::ReadAllText((Join-Path $Bundle "hooks\agy-hook.py")))
# the bundle is generated for D:\projects; devices with another workspace root (e.g. C:\projects where D: is a
# temporary disk) get the same policy with their own root
$WsFwd = $Workspace.TrimEnd("\").Replace("\", "/")
function Set-AgyWorkspace([string]$text) { if ($WsFwd -ieq "D:/projects") { $text } else { $text.Replace("D:/projects", $WsFwd) } }
$polText = Set-AgyWorkspace ([IO.File]::ReadAllText((Join-Path $Bundle "hooks\policy.windows.json")))
# agent gcloud identity per group (hook-enforced impersonation), from metadata agy-agent-sa {"agy-dev": "<sa>"}
$asa = (Get-AgyParam "agy-agent-sa" $null)
if ($asa -is [string]) { $asa = $(try { $asa | ConvertFrom-Json } catch { $null }) }
if ($asa -and @($asa.PSObject.Properties).Count -gt 0) {
  $pol = $polText | ConvertFrom-Json
  foreach ($e in $asa.PSObject.Properties) {
    if ($e.Value -notmatch '^[a-z][a-z0-9-]+@[a-z][a-z0-9-]+\.iam\.gserviceaccount\.com$') { continue }
    if (-not $pol.groups.($e.Name)) { $pol.groups | Add-Member -NotePropertyName $e.Name -NotePropertyValue ([pscustomobject]@{}) }
    $pol.groups.($e.Name) | Add-Member -NotePropertyName agent_service_account -NotePropertyValue $e.Value -Force
  }
  $polText = $pol | ConvertTo-Json -Depth 20
}
# hook audit mode (tuning): agy-hook-audit-classes = comma-separated rule classes that are logged (AUDIT_ALLOW) instead
# of denied; the hook itself refuses to audit the critical classes. Empty = enforce everything.
$auditCls = @(([string](Get-AgyParam "agy-hook-audit-classes" "")) -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^[a-z_]+$' })
if ($auditCls.Count -gt 0) {
  $pol = $polText | ConvertFrom-Json
  $pol.default | Add-Member -NotePropertyName audit_classes -NotePropertyValue $auditCls -Force
  $polText = $pol | ConvertTo-Json -Depth 20
}
$polChanged = Write-IfChanged "$hooks\policy.json" $polText
# launcher without spaces or quotes: the CLI runs hooks via "cmd /c <command>", which mangles quoted paths
$cmdText = "@echo off`r`n`"C:\Program Files\Python312\python.exe`" `"%~dp0agy-hook.py`" %*`r`n"
$cmdChanged = Write-IfChanged "$hooks\agy-hook.cmd" $cmdText
if ($hookChanged -or $polChanged -or $cmdChanged) { Audit "HOOK_POLICY_DRIFT corrected" "Warning" }
& icacls $hooks /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" /q | Out-Null

# ---------------------------------------------------------------- canary (admin-only; protected-path tests)
$canary = "C:\secure-admin"
if (-not (Test-Path "$canary\canary.txt")) {
  New-Item -ItemType Directory -Force -Path $canary | Out-Null
  "AGY-CANARY-$(Get-Random)" | Set-Content "$canary\canary.txt" -Encoding ascii
}
& icacls $canary /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /q | Out-Null

# ---------------------------------------------------------------- terminal sandbox availability
# The Antigravity terminal sandbox on Windows needs Windows 11 24H2 + the August 2026 update. Elsewhere (Windows
# Server) the CLI tries it, fails, and the agent reaches for BypassSandbox (denied by the hook). So on platforms
# without the sandbox: no sandbox, every command needs the user's approval (allow-listed read-only commands excepted).
$sbMode = (Get-AgyParam "agy-sandbox" "auto")
$isServer = (Get-CimInstance Win32_OperatingSystem).ProductType -ne 1
# client 24H2 (build 26100) or later; the August 2026 update itself can't be read reliably -> the CLI reports it
$platformSandbox = (-not $isServer) -and ([Environment]::OSVersion.Version.Build -ge 26100)
$useSandbox = switch ($sbMode) { "on" { $true } "off" { $false } default { $platformSandbox } }

# ---------------------------------------------------------------- per persona: read-only settings + hooks, onboarding
$SandboxPlaceholderDirs = @(
  ".cache\ccache", ".cargo", ".ccache", ".config\yarn", ".deno", ".dotnet\corefx\cryptography", ".dzil",
  ".gradle\caches", ".local\share\uv", ".m2", ".nimble", ".nuget", ".nvm", ".volta", "Library\Preferences",
  "AppData\Local\Volta", "AppData\Local\Yarn", "AppData\Local\ccache", "AppData\Local\nvm", "AppData\Local\pnpm",
  "AppData\Roaming\nvm", "AppData\Roaming\uv\data", "AppData\Roaming\yarn", "AppData\Roaming\npm\etc"
)
$hooksJson = [IO.File]::ReadAllText((Join-Path $Bundle "policies\hooks.json"))
# managed browser allowlist (one host per line): local addresses + agy-browser-allowlist (comma-separated host names)
$balHosts = @(@(Get-AgyParam "agy-browser-allowlist" "") -join "," -split "[,\s]+" | ForEach-Object { $_.Trim().ToLowerInvariant() } |
  Where-Object { $_ -match '^(\*\.)?[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$' -and $_ -notin "localhost", "127.0.0.1" } | Select-Object -Unique)
$browserAllowlist = (@("# managed by AGY - one host per line", "localhost", "127.0.0.1") + $balHosts) -join "`n"
$browserAllowlist += "`n"
# persona accounts on this device: local dev / contractor, or (agy-persona-source = groups) the users' own directory
# accounts whose session token holds a persona group SID (seen at logon; profile created at first logon)
$PersonaProfiles = @(Get-AgyPersonaProfiles)
Write-AgyPersonaGroupsFile
foreach ($pp in $PersonaProfiles) {
  $u = $pp.Name; $home_ = $pp.Home; $grp = $pp.Group; $who = "*$($pp.Sid)"   # grant by SID: works for Entra / AD accounts
  $cli = "$home_\.gemini\antigravity-cli"; $cfg = "$home_\.gemini\config"; $agd = "$home_\.gemini\antigravity"
  New-Item -ItemType Directory -Force -Path $cli, $cfg, $agd, "$cli\cache" | Out-Null
  $settings = Set-AgyWorkspace ([IO.File]::ReadAllText((Join-Path $Bundle "policies\$grp.settings.json")))
  if ($u -ne $pp.Persona) {
    # directory account (e.g. JohnDoe): the templates name the persona's own paths (C:/Users/dev, <ws>/dev)
    # every occurrence that ends the path segment: /, ", ) (permission rules like write_file(<ws>/dev)), *, ] or ,
    $homeFwd = $home_.Replace("\", "/")
    $end = '(?=[/")*\],])'
    $settings = [regex]::Replace($settings, [regex]::Escape("C:/Users/$($pp.Persona)") + $end, $homeFwd.Replace('$', '$$'))
    $settings = [regex]::Replace($settings, [regex]::Escape("$WsFwd/$($pp.Persona)") + $end, "$WsFwd/$u".Replace('$', '$$'))
  }
  # the persona's workspace folder (Modify for the owner only)
  $wsDir = Join-Path $Workspace $u
  if (-not (Test-Path $wsDir)) {
    New-Item -ItemType Directory -Force -Path $wsDir | Out-Null
    & icacls $wsDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "${who}:(OI)(CI)M" /q | Out-Null
  }
  if (-not $useSandbox) {
    $settings = $settings.Replace('"toolPermission": "proceed-in-sandbox"', '"toolPermission": "request-review"').Replace('"enableTerminalSandbox": true', '"enableTerminalSandbox": false')
  }
  if ($Mode -eq "seat") {
    # seat mode: pin the licence project + location in the read-only settings (as on Linux) - the user can't pick another
    # licence or a global / us licence, which would send prompts outside the EU (found on the Windows 11 test device)
    $seatProject = [string](Get-AgyParam "agy-seat-project" ""); $seatLocation = [string](Get-AgyParam "agy-seat-location" "eu")
    if ($seatProject) {
      $sj = $settings | ConvertFrom-Json
      $sj | Add-Member -NotePropertyName gcp -NotePropertyValue ([pscustomobject]@{ project = $seatProject; location = $seatLocation }) -Force
      $settings = ($sj | ConvertTo-Json -Depth 20) + "`n"
    } else { Audit "user=$u SEAT_LICENCE_NOT_PINNED: agy-seat-project is not set - the persona can choose any licence" "Warning" }
  }
  $d1 = Write-IfChanged "$cli\settings.json" $settings
  $d2 = Write-IfChanged "$cfg\hooks.json" $hooksJson
  # managed MCP server config per group (ships with no servers) and browser allowlist: replaced and locked like hooks.json
  $d3 = Write-IfChanged "$cfg\mcp_config.json" ([IO.File]::ReadAllText((Join-Path $Bundle "policies\$grp.mcp_config.json")))
  $d4 = Write-IfChanged "$agd\browserAllowlist.txt" $browserAllowlist
  Set-ReadOnlyFor "$cli\settings.json" $who; Set-ReadOnlyFor "$cfg\hooks.json" $who
  Set-ReadOnlyFor "$cfg\mcp_config.json" $who; Set-ReadOnlyFor "$agd\browserAllowlist.txt" $who
  foreach ($dir in $home_, "$home_\.gemini", $cli, $cfg, $agd) { Deny-DeleteChild $dir $who }
  # and the folders themselves can't be deleted / renamed away (the inherited Full control includes DELETE)
  foreach ($dir in "$home_\.gemini", $cli, $cfg, $agd) { & icacls $dir /deny "${who}:(D)" /q | Out-Null }
  if ($d1 -or $d2 -or $d3 -or $d4) {
    Audit "user=$u SETTINGS_DRIFT corrected (settings $d1, hooks $d2, mcp_config $d3, browserAllowlist $d4)" "Warning"
  }
  # terminal sandbox (agy CLI 1.4.x): the sandbox denies credential files in toolchain folders; when a folder above
  # such a file does not exist the Windows sandbox API fails the whole sandbox ("CreateProcessSecurityEnvironment: The
  # system cannot find the path specified"). Empty placeholder folders avoid it (Windows 11 test device: the list
  # below, incl. AppData\Roaming\npm\etc, was enough). Harmless empty folders under the persona's own profile.
  if ($useSandbox) {
    $made = @()
    foreach ($rel in $SandboxPlaceholderDirs) {
      $pth = Join-Path $home_ $rel
      if (-not (Test-Path -LiteralPath $pth)) { New-Item -ItemType Directory -Force -Path $pth | Out-Null; $made += $rel }
    }
    if ($made) { Audit "user=$u SANDBOX_PLACEHOLDERS created: $($made -join ', ')" }
  }
  # the CLI can't persist the terms / onboarding step into read-only settings: seed it in its own state file
  $ob = "$cli\cache\onboarding.json"
  $state = if (Test-Path $ob) { try { Get-Content $ob -Raw -ErrorAction Stop | ConvertFrom-Json } catch { [pscustomobject]@{} } } else { [pscustomobject]@{} }
  if (-not $state.enterpriseOnboardingComplete) {
    $state | Add-Member -NotePropertyName enterpriseOnboardingComplete -NotePropertyValue $true -Force
    [IO.File]::WriteAllText($ob, ($state | ConvertTo-Json -Compress), $Utf8)
    & icacls $ob /grant "${who}:M" /q | Out-Null
    Audit "user=$u onboarding-state seeded (read-only managed settings)"
  }
}

# ---------------------------------------------------------------- sandbox enforced centrally on a platform without it
# Seat (business) accounts get admin controls from the admin console; they override settings.json, so
# "sandbox off" above has no effect there. On a platform without the sandbox every agent command then fails.
# Not fixable on the endpoint (by design): record it for V71 + the SIEM (rule: upgrade to Win11 24H2+).
$adminSandbox = $false
foreach ($pp in $PersonaProfiles) {
  $log = Get-ChildItem "$($pp.Home)\.gemini\antigravity-cli\log\cli-*.log" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if ($log -and (Select-String -Path $log.FullName -SimpleMatch "Enforcing SandboxMode = true" -Quiet)) { $adminSandbox = $true }
}
# sandbox failures actually observed (hook SANDBOX_FAILURE from the CLI transcript, last 24 h): the build number alone
# isn't enough - e.g. a VM without virtualization-based security fails with CreateProcessSecurityEnvironment errors
$sbFail = @(Get-WinEvent -FilterHashtable @{ LogName = "Application"; ProviderName = "agy-hook"; StartTime = (Get-Date).AddHours(-24) } -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match '"event": "SANDBOX_FAILURE"' })
$sbLast = if ($sbFail) { ([regex]::Match($sbFail[0].Message, '"error": "([^"]*)"')).Groups[1].Value } else { "" }
# AGY version management: CLI + Desktop to the version the deployment policy selects from the support matrix
# (Update-AGYVersions.ps1; swaps only while the program is not running, i.e. at the next logon). It also reports the
# installed CLI version (agy CLI 1.4.10 needs the sandbox placeholder folders; 1.4.11 fixed it).
$cliVer = ""
if (Test-AgyModule "client") {
  try {
    $vs = & (Join-Path $PSScriptRoot "Update-AGYVersions.ps1") -Bundle $Bundle -Root $Root
    $cliVer = [string]$vs.cli
  } catch { Audit "AGY_VERSION_SYNC_ERROR: $($_.Exception.Message)" "Warning" }
}
$sbState = [ordered]@{ platform_sandbox = $platformSandbox; configured_sandbox = $useSandbox; admin_enforced = $adminSandbox
                       observed_failures_24h = $sbFail.Count; last_failure = $sbLast; cli_version = $cliVer
                       os_build = [Environment]::OSVersion.Version.Build; product_type = (Get-CimInstance Win32_OperatingSystem).ProductType }
$sbFirst = -not (Test-Path "$Root\sandbox-state.json")   # Write-IfChanged reports drift only, not the first write
$sbChanged = (Write-IfChanged "$Root\sandbox-state.json" ($sbState | ConvertTo-Json -Compress)) -or $sbFirst
if ($sbChanged -and $sbFail.Count -gt 0) { Audit "SANDBOX_FAILURE_OBSERVED: $($sbFail.Count) in 24 h - $sbLast" "Warning" }
if ($sbChanged -and $adminSandbox -and -not $platformSandbox) { Audit "SANDBOX_UNAVAILABLE_ADMIN_ENFORCED: admin controls enforce the terminal sandbox, this OS has none - agent terminal commands fail" "Warning" }

# ---------------------------------------------------------------- S5b egress: hosts pins, WFP drop auditing, sync task
$pins = (Get-AgyParam "agy-hosts-pin" "") -split "," | Where-Object { $_ -match '^[A-Za-z0-9.-]+$' }
$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$body = ((Get-Content $hostsFile) | Where-Object { $_ -notmatch "# agy-pin$" }) + ($pins | ForEach-Object { "0.0.0.0 $_ # agy-pin" })
if (((Get-Content $hostsFile) -join "`n") -ne ($body -join "`n")) {
  # Defender / DNS client briefly lock the hosts file while scanning a change: retry, never abort the other controls
  $ok = $false
  for ($i = 1; $i -le 6 -and -not $ok; $i++) {
    try { [IO.File]::WriteAllText($hostsFile, (($body -join "`r`n") + "`r`n"), [Text.Encoding]::ASCII); $ok = $true }
    catch { Start-Sleep -Seconds (2 * $i) }
  }
  if ($ok) { Audit "hosts pins applied: $($pins.Count)" } else { Audit "HOSTS_PIN_FAILED: hosts file locked after 6 attempts - retried on the next run" "Warning" }
}
& auditpol /set /subcategory:"Filtering Platform Packet Drop" /failure:enable | Out-Null   # 5152 drops -> SIEM
& auditpol /set /subcategory:"Other Object Access Events" /success:enable | Out-Null        # 4698 scheduled task created (D15)
& auditpol /set /subcategory:"Security Group Management" /success:enable | Out-Null         # 4732 member added to a local group (D19)
if (-not $PolicyOnly) {
  & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "Sync-AGYEgress.ps1")
  $sync = Join-Path $PSScriptRoot "Sync-AGYEgress.ps1"
  $a2 = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$sync`""
  $t2 = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)
  Register-ScheduledTask -TaskName "AGY-EgressSync" -Action $a2 -Trigger $t2 -User "SYSTEM" -RunLevel Highest -Force | Out-Null
}

# ---------------------------------------------------------------- S5c application control (AppLocker per group, WDAC baseline)
$wdac = (Get-AgyParam "agy-wdac-mode" "Audit")
if ($wdac -notin "Audit", "Enforce") { $wdac = "Audit" }
# ---------------------------------------------------------------- developer build layout: D:\build\<user>, D:\caches\<user>
# Build output and package caches leave the workspace: AppLocker / WDAC then allow running own builds from one root
# instead of the whole (agent-writable) workspace. Folders are per user (Modify for the owner only).
$buildRoot = Join-Path (Split-Path $Workspace -Qualifier) "build"; $cacheRoot = Join-Path (Split-Path $Workspace -Qualifier) "caches"
foreach ($r in $buildRoot, $cacheRoot) {
  if (-not (Test-Path $r)) { New-Item -ItemType Directory -Path $r | Out-Null }
  & icacls $r /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:RX" /q | Out-Null
}
foreach ($pp in $PersonaProfiles) {
  $u = $pp.Name   # = %USERNAME% of the account (build / cache folders expand %USERNAME%)
  foreach ($r in $buildRoot, $cacheRoot) {
    $d = Join-Path $r $u
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
    & icacls $d /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*$($pp.Sid):(OI)(CI)M" /q | Out-Null
  }
}
# machine environment (REG_EXPAND_SZ, %USERNAME% expands per user); MSBuild reads environment variables as properties
$envKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
$envWant = [ordered]@{
  UseArtifactsOutput = "true"; ArtifactsPath = "$buildRoot\%USERNAME%"
  NUGET_PACKAGES = "$cacheRoot\%USERNAME%\nuget"; npm_config_cache = "$cacheRoot\%USERNAME%\npm"
  PIP_CACHE_DIR = "$cacheRoot\%USERNAME%\pip"; GOCACHE = "$cacheRoot\%USERNAME%\go-build"
  GOMODCACHE = "$cacheRoot\%USERNAME%\go-mod"; GOTMPDIR = "$cacheRoot\%USERNAME%\go-tmp"
  # user-space tool locations (decision: toolchains machine-wide from the catalog; their per-user tools land here,
  # where AppLocker / WDAC allow developers to run them - not in %APPDATA% or the profile)
  npm_config_prefix = "$cacheRoot\%USERNAME%\npm-global"; GOBIN = "$cacheRoot\%USERNAME%\go-bin"
  PIPX_HOME = "$cacheRoot\%USERNAME%\pipx"; PIPX_BIN_DIR = "$cacheRoot\%USERNAME%\pipx\bin"
  WORKON_HOME = "$cacheRoot\%USERNAME%\venvs"; POETRY_VIRTUALENVS_PATH = "$cacheRoot\%USERNAME%\poetry-venvs"
  UV_CACHE_DIR = "$cacheRoot\%USERNAME%\uv-cache"; UV_TOOL_DIR = "$cacheRoot\%USERNAME%\uv-tools"
  UV_TOOL_BIN_DIR = "$cacheRoot\%USERNAME%\uv-bin"; UV_PYTHON_INSTALL_DIR = "$cacheRoot\%USERNAME%\uv-python"
}
# their bin folders on the machine PATH (after the system entries; expanded per user)
$toolBins = @("$cacheRoot\%USERNAME%\npm-global", "$cacheRoot\%USERNAME%\go-bin", "$cacheRoot\%USERNAME%\pipx\bin",
              "$cacheRoot\%USERNAME%\uv-bin")
$envChanged = @()
foreach ($k in $envWant.Keys) {
  $cur = (Get-Item $envKey).GetValue($k, $null, "DoNotExpandEnvironmentNames")
  if ($cur -ne $envWant[$k]) { New-ItemProperty -Path $envKey -Name $k -Value $envWant[$k] -PropertyType ExpandString -Force | Out-Null; $envChanged += $k }
}
# corporate package proxy (metadata agy-package-proxy {npm, python, go, maven, docker, nuget}): machine-wide client
# config; the public registries are no longer in the egress allowlist, so this is the only working source
$pp = (Get-AgyParam "agy-package-proxy" $null)
if ($pp -is [string]) { $pp = $(try { $pp | ConvertFrom-Json } catch { $null }) }
$ppEnv = [ordered]@{ npm_config_registry = $pp.npm; PIP_INDEX_URL = $pp.python; GOPROXY = $(if ($pp.go) { "$($pp.go),off" }) }
foreach ($k in $ppEnv.Keys) {
  $cur = (Get-Item $envKey).GetValue($k, $null)
  if ($ppEnv[$k] -and $cur -ne $ppEnv[$k]) { New-ItemProperty -Path $envKey -Name $k -Value $ppEnv[$k] -PropertyType String -Force | Out-Null; $envChanged += $k }
  elseif (-not $ppEnv[$k] -and $null -ne $cur) { Remove-ItemProperty -Path $envKey -Name $k; $envChanged += "-$k" }
}
$nugetDir = "${env:ProgramFiles(x86)}\NuGet\Config"; $nugetCfg = "$nugetDir\agy-packages.config"
if ($pp.nuget -and $pp.nuget -match '^https://\S+/index\.json$') {
  $x = "<?xml version=""1.0"" encoding=""utf-8""?>`r`n<configuration>`r`n  <packageSources>`r`n    <clear />`r`n" +
       "    <add key=""corp"" value=""$([Security.SecurityElement]::Escape($pp.nuget))"" protocolVersion=""3"" />`r`n  </packageSources>`r`n" +
       "  <packageSourceMapping>`r`n    <packageSource key=""corp"">`r`n      <package pattern=""*"" />`r`n    </packageSource>`r`n" +
       "  </packageSourceMapping>`r`n</configuration>`r`n"
  New-Item -ItemType Directory -Force -Path $nugetDir | Out-Null
  if (Write-IfChanged $nugetCfg $x) { $envChanged += "nuget" }
  & icacls $nugetCfg /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" "*S-1-5-32-545:R" /q | Out-Null
} elseif (Test-Path $nugetCfg) { Remove-Item $nugetCfg -Force; $envChanged += "-nuget" }
$mp = (Get-Item $envKey).GetValue("Path", "", "DoNotExpandEnvironmentNames")
# NOT on the machine PATH: Windows builds PATH before USERNAME is set, so %USERNAME% there expands to SYSTEM (Windows 11
# test device: C:\caches\SYSTEM\npm-global). Remove those entries; each persona gets the concrete folders in its own
# (user) Path, written while its profile hive is loaded (AGY-Policy runs at logon and every 5 min).
$stale = @(($mp -split ";") | Where-Object { $toolBins -contains $_ })
if ($stale) {
  $keep = @(($mp -split ";") | Where-Object { $_ -and ($toolBins -notcontains $_) })
  New-ItemProperty -Path $envKey -Name Path -Value ($keep -join ";") -PropertyType ExpandString -Force | Out-Null
  $envChanged += "PATH(-machine tools)"
}
foreach ($pp in $PersonaProfiles) {
  $u = $pp.Name
  $uk = "Registry::HKEY_USERS\$($pp.Sid)\Environment"
  if (-not (Test-Path "Registry::HKEY_USERS\$($pp.Sid)")) { continue }   # hive not loaded: next run at logon
  if (-not (Test-Path $uk)) { New-Item -Path $uk | Out-Null }
  $up = (Get-Item $uk).GetValue("Path", "", "DoNotExpandEnvironmentNames")
  $want = @($toolBins | ForEach-Object { $_.Replace("%USERNAME%", $u) })
  $miss = @($want | Where-Object { ($up -split ";") -notcontains $_ })
  if ($miss) {
    New-ItemProperty -Path $uk -Name Path -Value ((@(($up -split ";") | Where-Object { $_ }) + $miss) -join ";") -PropertyType ExpandString -Force | Out-Null
    $envChanged += "PATH(tools, $u)"
  }
}

# ---------------------------------------------------------------- standard users: elevation settings (Intune / ConfigMgr
# baseline in production; this is the stand-in). UAC for standard users = auto-deny (no credential prompt the agent
# could trigger), Windows sudo off, Administrator protection on where the OS has it (Windows 11 2025+).
function Set-RegDword([string]$key, [string]$name, [int]$value) {
  if (-not (Test-Path $key)) {   # create each missing level; never -Force on an existing key (it would wipe it)
    $acc = ""
    foreach ($part in ($key -split "\\")) {
      $acc = if ($acc) { "$acc\$part" } else { $part }
      if ($acc -notmatch ":$" -and -not (Test-Path $acc)) { New-Item -Path $acc | Out-Null }
    }
  }
  $cur = (Get-Item $key).GetValue($name, $null)
  if ($cur -ne $value) { New-ItemProperty -Path $key -Name $name -Value $value -PropertyType DWord -Force | Out-Null; return $true }
  return $false
}
$sysPol = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$chg = @()
if (Set-RegDword $sysPol "ConsentPromptBehaviorUser" 0) { $chg += "UAC standard users auto-deny" }
if (Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sudo" "EnableSudo" 0) { $chg += "sudo policy off" }
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo") {
  if (Set-RegDword "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo" "Enabled" 0) { $chg += "sudo off" }
}
if (-not $isServer -and [Environment]::OSVersion.Version.Build -ge 26100) {
  if (Set-RegDword $sysPol "TypeOfAdminApprovalMode" 2) { $chg += "Administrator protection (next reboot)" }
}

# ---------------------------------------------------------------- pre-provisioning: what developers would otherwise ask
# admin for. Long paths; symlink right for AGY-Dev (instead of Developer Mode); user-mode ETW (Performance Log Users);
# URL ACLs for local web servers; no firewall prompts; Visual Studio updates by standard users.
if (Set-RegDword "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" "LongPathsEnabled" 1) { $chg += "long paths" }
if (Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Setup" "AllowStandardUserControl" 1) { $chg += "VS standard-user updates" }
# developer SIDs: the local group AGY-Dev and (persona source = groups) the directory group SIDs - user rights and URL
# ACLs are checked against the logon token, which carries directory group SIDs
$devSids = @((Get-AgyPersonaSids)["dev"])
$inf = "$env:TEMP\agy-secpol.inf"; $db = "$env:TEMP\agy-secpol.sdb"
& secedit /export /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
$line = (Get-Content $inf | Where-Object { $_ -match "^SeCreateSymbolicLinkPrivilege\s*=" }) | Select-Object -First 1
# secedit lists local groups by name (AGY-Dev) or by *SID: accept both, else it re-applies on every run
$missing = @($devSids | Where-Object { $line -notmatch ("\*" + [regex]::Escape($_) + "\b") -and -not ($_ -eq $devSids[0] -and $line -match "[=,]\s*AGY-Dev\s*(,|$)") })
if ($missing) {
  $new = if ($line) { "$line," + (($missing | ForEach-Object { "*$_" }) -join ",") } else { "SeCreateSymbolicLinkPrivilege = *S-1-5-32-544," + (($missing | ForEach-Object { "*$_" }) -join ",") }
  "[Unicode]`r`nUnicode=yes`r`n[Privilege Rights]`r`n$new`r`n[Version]`r`nsignature=`"`$CHICAGO`$`"`r`nRevision=1`r`n" | Set-Content $inf -Encoding Unicode
  & secedit /configure /db $db /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
  $chg += "symlink right for developers (next logon)"
}
Remove-Item $inf, $db -Force -ErrorAction SilentlyContinue
# agy-rdp = admins: Remote Desktop stays available to Administrators / SYSTEM (remote support), never to personas -
# persona group SIDs get "Deny log on through Remote Desktop Services" and leave Remote Desktop Users
if ([string](Get-AgyParam "agy-rdp" "on") -eq "admins") {
  $pSids = @((Get-AgyPersonaSids).Values | ForEach-Object { $_ } | Select-Object -Unique)
  & secedit /export /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
  $line = [string]((Get-Content $inf | Where-Object { $_ -match "^SeDenyRemoteInteractiveLogonRight\s*=" }) | Select-Object -First 1)
  # entries are "*<SID>" or account names (secedit writes local groups by name): resolve all of them to SIDs
  $have = @(($line -split "=", 2 | Select-Object -Skip 1) -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object {
    $n = $_
    if ($n.StartsWith("*")) { $n.Substring(1) } else { $(try { (New-Object Security.Principal.NTAccount($n)).Translate([Security.Principal.SecurityIdentifier]).Value } catch { $n }) }
  })
  $missing = @($pSids | Where-Object { $have -notcontains $_ })
  if ($missing) {
    $new = "SeDenyRemoteInteractiveLogonRight = " + ((@($have | ForEach-Object { "*$_" }) + @($missing | ForEach-Object { "*$_" })) -join ",")
    "[Unicode]`r`nUnicode=yes`r`n[Privilege Rights]`r`n$new`r`n[Version]`r`nsignature=`"`$CHICAGO`$`"`r`nRevision=1`r`n" | Set-Content $inf -Encoding Unicode
    & secedit /configure /db $db /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
    $chg += "RDP logon denied for persona groups"
  }
  Remove-Item $inf, $db -Force -ErrorAction SilentlyContinue
  $rdu = Get-LocalGroup -SID "S-1-5-32-555"
  $pMembers = @("AGY-Dev", "AGY-Contractor" | ForEach-Object { Get-LocalGroupMember -Group $_ -ErrorAction SilentlyContinue } | ForEach-Object { $_.SID.Value }) +
              @($PersonaProfiles | ForEach-Object { $_.Sid }) + $pSids
  foreach ($m in @(Get-LocalGroupMember -Group $rdu -ErrorAction SilentlyContinue)) {
    if ($pMembers -contains $m.SID.Value) { Remove-LocalGroupMember -Group $rdu -Member $m.SID.Value; $chg += "Remote Desktop Users -= $($m.Name)" }
  }
}
# Performance Log Users (user-mode ETW): local groups can't nest and Windows doesn't evaluate Entra group SIDs here -
# add the developer accounts themselves (local AGY-Dev members + developer profiles seen on this device)
$plu = Get-LocalGroup -SID "S-1-5-32-559"
$have = @(Get-LocalGroupMember -Group $plu -ErrorAction SilentlyContinue | ForEach-Object { $_.SID.Value })
$devUsers = @(Get-LocalGroupMember -Group "AGY-Dev" -ErrorAction SilentlyContinue | ForEach-Object { $_.SID.Value }) +
            @($PersonaProfiles | Where-Object Persona -eq "dev" | ForEach-Object { $_.Sid })
foreach ($m in ($devUsers | Select-Object -Unique)) {
  if ($have -notcontains $m) { try { Add-LocalGroupMember -Group $plu -Member $m -ErrorAction Stop; $chg += "Performance Log Users += $m" } catch { } }
}
$urls = @(5000..5010 + 7000..7010 | ForEach-Object { "http://+:$_/" }) + @("https://+:5001/", "https://+:7001/")
$urlSddl = "D:" + (($devSids | ForEach-Object { "(A;;GX;;;$_)" }) -join "")
foreach ($u in $urls) {
  # per-URL query: the listing's column layout is locale-dependent
  $cur = (& netsh http show urlacl url=$u) -join " "
  $ok = @($devSids | Where-Object { $cur -notmatch [regex]::Escape($_) -and -not ($_ -eq $devSids[0] -and $cur -match "AGY-Dev") }).Count -eq 0
  if (-not $ok) {
    if ($cur -match "Reserved URL") { & netsh http delete urlacl url=$u | Out-Null }
    & netsh http add urlacl url=$u sddl=$urlSddl | Out-Null; $chg += "urlacl $u"
  }
}
if (@(Get-NetFirewallProfile | Where-Object NotifyOnListen -ne "False").Count) { Set-NetFirewallProfile -All -NotifyOnListen False; $chg += "firewall prompts off" }
if ($chg) { Audit "standard-user baseline applied: $($chg -join '; ')" }

if ($envChanged) { Audit "developer build layout / package proxy: environment set ($($envChanged -join ', ')); takes effect at next logon" }
# Dev Drive (ReFS, performance mode): needs its own volume - never reformat the data disk automatically
$dd = (& fsutil devdrv query (Split-Path $Workspace -Qualifier) 2>&1) -join " "
$ddState = if ($dd -match "not a developer volume") { "available-not-used" } elseif ($dd -match "trusted|developer volume") { "in-use" } else { "unavailable" }
[void](Write-IfChanged "$Root\devdrive-state.txt" $ddState)

$corpPub = (Get-AgyParam "agy-corp-script-publisher" "")
# agy-app-control = on (default: AppLocker per persona group + WDAC baseline) | off (e.g. a POC on daily-use laptops)
if ([string](Get-AgyParam "agy-app-control" "on") -ne "off") {
  & (Join-Path $PSScriptRoot "Set-AGYAppControl.ps1") -WdacMode $wdac -Workspace $Workspace -BuildRoot $buildRoot -CacheRoot $cacheRoot `
    -CorpScriptPublisher ([string]$corpPub)
}

# ---------------------------------------------------------------- human review: agy launcher shim (first on PATH)
# The hook denies every tool call of a session started with --dangerously-skip-permissions / --mode auto|accept-edits
# (any launch path). The shim only refuses them early with a clear message and an audit event. Program Files:
# admin-only and allowed by the AppLocker script rules (a ProgramData copy would be blocked for personas).
$shimDir = "C:\Program Files\Antigravity\bin"; New-Item -ItemType Directory -Force -Path $shimDir | Out-Null
# eventcreate (used by the shim as the persona) only writes to sources it registered itself: register once as SYSTEM
if (-not [System.Diagnostics.EventLog]::SourceExists("agy-shim")) {
  Start-Process eventcreate.exe -ArgumentList '/L APPLICATION /SO agy-shim /T INFORMATION /ID 100 /D "agy launcher shim registered"' -Wait -NoNewWindow
}
if (Write-IfChanged "$shimDir\agy.cmd" ([IO.File]::ReadAllText((Join-Path $PSScriptRoot "agy.cmd")))) { Audit "AGY_SHIM_DRIFT corrected" "Warning" }
& icacls $shimDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" /q | Out-Null
$mpath = (Get-Item $envKey).GetValue("Path", "", "DoNotExpandEnvironmentNames")
if (($mpath -split ";")[0] -ne $shimDir) {
  $rest = @($mpath -split ";" | Where-Object { $_ -and $_ -ne $shimDir })
  New-ItemProperty -Path $envKey -Name Path -Value ((@($shimDir) + $rest) -join ";") -PropertyType ExpandString -Force | Out-Null
  Audit "agy launcher shim placed first on the machine PATH (takes effect at next logon)"
}

# ---------------------------------------------------------------- Sysmon configuration (binary from the image)
$sysmonExe = "C:\Program Files\Sysmon\Sysmon64.exe"; $sysmonCfg = Join-Path $PSScriptRoot "agy-sysmon.xml"
# agy-sysmon = on (default) | off
if ([string](Get-AgyParam "agy-sysmon" "on") -ne "off" -and (Test-Path $sysmonExe) -and (Test-Path $sysmonCfg)) {
  $h = (Get-FileHash $sysmonCfg -Algorithm SHA256).Hash; $mark = "$Root\sysmon-config.sha256"
  $svc = Get-Service Sysmon64 -ErrorAction SilentlyContinue
  # Start-Process: Sysmon prints its banner on stderr, which PowerShell 5.1 turns into a terminating NativeCommandError
  function Invoke-Sysmon([string[]]$a) {
    (Start-Process $sysmonExe -ArgumentList $a -Wait -PassThru -NoNewWindow `
       -RedirectStandardOutput "$env:TEMP\agy-sysmon.out" -RedirectStandardError "$env:TEMP\agy-sysmon.err").ExitCode
  }
  if (-not $svc) {
    if ((Invoke-Sysmon @("-accepteula", "-i", "`"$sysmonCfg`"")) -eq 0) { $h | Set-Content $mark -Encoding ascii; Audit "Sysmon installed with AGY configuration" }
    else { Audit "SYSMON_CONFIG_FAILED: Sysmon64 -i failed" "Error" }
  }
  elseif (-not (Test-Path $mark) -or (Get-Content $mark -Raw).Trim() -ne $h) {
    $rc = Invoke-Sysmon @("-c", "`"$sysmonCfg`"")
    if ($rc -eq 0) { $h | Set-Content $mark -Encoding ascii; Audit "Sysmon configuration applied ($($h.Substring(0, 12)))" }
    else { Audit "SYSMON_CONFIG_FAILED: Sysmon64 -c exit $rc $((Get-Content "$env:TEMP\agy-sysmon.err" -Raw -ErrorAction SilentlyContinue))" "Error" }
  }
  if ($svc -and $svc.Status -ne "Running") { Start-Service Sysmon64 -ErrorAction SilentlyContinue; Audit "SYSMON_DRIFT corrected: service was $($svc.Status)" "Warning" }
}

# ---------------------------------------------------------------- gateway mode: local credential proxy (127.0.0.1:8443)
# The client talks to the proxy (admin_settings gateway.url); the proxy identifies the caller from the TCP owner
# process token (persona groups, never what the client asserts), adds the device proof (Compute Engine identity
# token, or the device certificate alone on laptops) and forwards over mTLS to the gateway front door. Runs as
# SYSTEM; the device key is readable by SYSTEM / Administrators only.
$proxyTask = "AGY-CredProxy"
if ($Mode -eq "gateway") {
  $gwUrl = [string](Get-AgyParam "agy-gateway-url" "")
  if ($gwUrl) { [void](Write-IfChanged "$Root\gateway_url" $gwUrl) }
  try { & (Join-Path $PSScriptRoot "Enroll-AGYDevice.ps1") } catch { Audit "DEVICE_ENROLMENT_FAILED: $($_.Exception.Message)" "Warning" }
  $py = "C:\Program Files\Python312\python.exe"; $proxy = Join-Path $Bundle "credproxy\agy-credproxy.py"
  $auth = Get-AgyDeviceAuth
  # readiness gate: model calls of a persona whose managed settings / hooks are not locked yet (first minutes after a new
  # user's first sign-in) get 503 and AGY-Policy is started at once; "off" only for troubleshooting
  $reqPol = if ([string](Get-AgyParam "agy-require-managed-policy" "on") -eq "off") { "off" } else { "on" }
  $arg = "/c set AGY_DEVICE_AUTH=$auth&& set AGY_REQUIRE_MANAGED_POLICY=$reqPol&& `"$py`" `"$proxy`" >> `"$Root\credproxy.log`" 2>&1"
  $t = Get-ScheduledTask -TaskName $proxyTask -ErrorAction SilentlyContinue
  if (-not $t -or ($t.Actions[0].Arguments -ne $arg)) {
    $set = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
    Register-ScheduledTask -TaskName $proxyTask -Action (New-ScheduledTaskAction -Execute "cmd.exe" -Argument $arg) `
      -Trigger (New-ScheduledTaskTrigger -AtStartup) -User "SYSTEM" -RunLevel Highest -Settings $set -Force | Out-Null
    Audit "credential proxy task registered (device auth $auth)"
  }
  if ((Get-ScheduledTask -TaskName $proxyTask).State -ne "Running") { Start-ScheduledTask -TaskName $proxyTask; Audit "CREDPROXY_DRIFT corrected: proxy was not running" "Warning" }
} elseif (Get-ScheduledTask -TaskName $proxyTask -ErrorAction SilentlyContinue) {
  Stop-ScheduledTask -TaskName $proxyTask -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName $proxyTask -Confirm:$false
  Audit "credential proxy removed (mode $Mode)"
}

# ---------------------------------------------------------------- device telemetry (package-managed devices only)
# AGY Telemetry package installed (module marker) and configured: SYSTEM task every 5 minutes; otherwise removed.
$telTask = "AGY-Telemetry"
$modKey = "HKLM:\SOFTWARE\Policies\AGY\Modules"
$wantTel = (Test-Path $modKey) -and (Test-AgyModule "telemetry-shipper") -and [string](Get-AgyParam "agy-telemetry-audience" "")
if ($wantTel) {
  if (-not (Get-ScheduledTask -TaskName $telTask -ErrorAction SilentlyContinue)) {
    $ta = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $PSScriptRoot 'Start-AGYTelemetry.ps1')`""
    $tt = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
    $ts = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -StartWhenAvailable -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $telTask -Action $ta -Trigger $tt -Settings $ts -User "SYSTEM" -RunLevel Highest -Force | Out-Null
    Audit "telemetry shipper scheduled (every 5 minutes)"
  }
} elseif (Get-ScheduledTask -TaskName $telTask -ErrorAction SilentlyContinue) {
  Unregister-ScheduledTask -TaskName $telTask -Confirm:$false; Audit "telemetry shipper removed (module or configuration absent)"
}

# ---------------------------------------------------------------- drift task (SYSTEM, every 5 min and at logon)
if (-not $PolicyOnly) {
  $me = $MyInvocation.MyCommand.Path
  $act = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$me`" -Mode $Mode -Workspace `"$Workspace`" -PolicyOnly"
  $trg = @((New-ScheduledTaskTrigger -AtLogOn), (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)))
  Register-ScheduledTask -TaskName "AGY-Policy" -Action $act -Trigger $trg -User "SYSTEM" -RunLevel Highest -Force | Out-Null
}
Write-Host "AGY controls applied (mode $Mode, terminal sandbox $(if ($useSandbox) { "on" } else { "off: approval per command" }))"
