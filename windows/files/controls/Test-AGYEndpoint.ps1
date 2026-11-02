<#
.SYNOPSIS
  Windows endpoint validation: prints RESULT|<PASS|WARN|FAIL>|<id>|<title>|<detail> lines (same format as
  install/validate-vm.sh). Run as SYSTEM or an administrator; install.sh runs it over IAP SSH.
#>
param([string[]]$Only = @())   # -Only V86,V87: print just these checks
$ErrorActionPreference = "Continue"
. (Join-Path $PSScriptRoot "AGYConfig.ps1")   # settings: MDM registry > params.json > GCE metadata
$Root = "C:\ProgramData\Antigravity"
$OnlyIds = @($Only | ForEach-Object { $_ -split "," } | ForEach-Object { $_.Trim().ToUpper() } | Where-Object { $_ })
# layers switched off by setting (agy-app-control / agy-sysmon = off) report SKIP instead of FAIL
$SkipIds = @{}
if ([string](Get-AgyParam "agy-app-control" "on") -eq "off") { foreach ($i in "V72", "V74", "V75") { $SkipIds[$i] = "application control off (agy-app-control = off)" } }
if ([string](Get-AgyParam "agy-sysmon" "on") -eq "off") { $SkipIds["V77"] = "Sysmon off (agy-sysmon = off)" }

function Write-Result([string]$status, [string]$id, [string]$title, [string]$detail) {
  if ($OnlyIds.Count -gt 0 -and $OnlyIds -notcontains $id) { return }
  if ($SkipIds.ContainsKey($id)) { $status = "SKIP"; $detail = $SkipIds[$id] }
  Write-Output ("RESULT|{0}|{1}|{2}|{3}" -f $status, $id, $title, ($detail -replace "[\r\n|]", " "))
}

# ---------------------------------------------------------------- V71 terminal sandbox available where it is enforced
$t71 = "Terminal sandbox available on this OS (needed when admin controls enforce it)"
$sb = $(try { Get-Content "$Root\sandbox-state.json" -Raw -ErrorAction Stop | ConvertFrom-Json } catch { $null })
# agy CLI below 1.4.11 fails the Windows sandbox when a deny-listed toolchain folder is missing (placeholders work around it)
$cliOld = $false
if ($sb -and $sb.cli_version -match '(\d+)\.(\d+)\.(\d+)') { $cliOld = ([version]"$($Matches[1]).$($Matches[2]).$($Matches[3])") -lt [version]"1.4.11" }
if (-not $sb) {
  Write-Result "WARN" "V71" $t71 "no sandbox-state.json yet (no persona has started the CLI, or AGY-Policy has not run)"
} elseif ($sb.observed_failures_24h -gt 0) {
  Write-Result "FAIL" "V71" $t71 ("the sandbox fails on this device ($($sb.observed_failures_24h) failures in 24 h): $($sb.last_failure) - " +
    "check the agy CLI version (>= 1.4.11; this device: $($sb.cli_version)), then virtualization-based security / OS update")
} elseif ($cliOld -and $sb.configured_sandbox) {
  Write-Result "WARN" "V71" $t71 "agy CLI $($sb.cli_version) is older than 1.4.11: sandbox relies on the placeholder folders - update the CLI"
} elseif ($sb.platform_sandbox) {
  Write-Result "PASS" "V71" $t71 "client build $($sb.os_build), agy CLI $($sb.cli_version): sandbox supported (admin enforced: $($sb.admin_enforced))"
} elseif ($sb.admin_enforced) {
  Write-Result "WARN" "V71" $t71 ("build $($sb.os_build), product type $($sb.product_type): no sandbox, but admin controls enforce it - " +
    "agent terminal commands fail; use Windows 11 24H2 + Aug-2026 update or later")
} else {
  Write-Result "PASS" "V71" $t71 "build $($sb.os_build): no sandbox; not admin-enforced, so per-command approval (request-review) applies"
}

# ---------------------------------------------------------------- V84 AGY versions in the support matrix
# installed CLI / Desktop vs compat\agy-versions.json and the deployment policy's target (versions-state.json, written
# by Update-AGYVersions.ps1 every 5 min): PASS supported + on target; WARN deprecated / candidate / untested / upgrade
# pending / no target; FAIL blocked, below minimum or upgrade errors
$t84 = "AGY CLI and Desktop versions supported by this package (support matrix + deployment policy)"
$vs = $(try { Get-Content "$Root\versions-state.json" -Raw -ErrorAction Stop | ConvertFrom-Json } catch { $null })
$mx = $(try { Get-Content (Join-Path (Split-Path $PSScriptRoot -Parent) "compat\agy-versions.json") -Raw -ErrorAction Stop | ConvertFrom-Json } catch { $null })
if (-not $vs -or -not $mx) {
  Write-Result "WARN" "V84" $t84 "no versions-state.json / support matrix yet (AGY-Policy has not run with version management)"
} else {
  $worst = "PASS"; $notes = @()
  function Rank([string]$s) { switch ($s) { "FAIL" { 2 } "WARN" { 1 } default { 0 } } }
  foreach ($c in @(@{ n = "cli"; p = "windows_amd64" }, @{ n = "desktop"; p = "windows_x64" })) {
    $inst = [string]$vs.($c.n); $tgt = [string]$vs.("$($c.n)_target")
    if (-not $inst) { continue }
    $st = "PASS"; $why = "$($c.n) $inst"
    $rel = @($mx.releases | Where-Object { $_.component -eq $c.n -and $_.platform -eq $c.p -and $_.version -eq $inst })
    $min = $mx.minimum.($c.n).($c.p)
    if ($min -and ([version]$inst -lt [version]$min)) { $st = "FAIL"; $why += " below minimum $min" }
    elseif ($rel -and $rel[0].status -eq "blocked") { $st = "FAIL"; $why += " is blocked: $($rel[0].notes)" }
    elseif (-not $rel) { $st = "WARN"; $why += " not in the support matrix (untested)" }
    elseif ($rel[0].status -ne "supported") { $st = "WARN"; $why += " is $($rel[0].status)" }
    if ($st -ne "FAIL" -and -not $tgt) { $st = "WARN"; $why += ", no deployable target for policy $($vs.policy)" }
    elseif ($st -ne "FAIL" -and $tgt -ne $inst) { $st = "WARN"; $why += " -> $tgt pending (applied at next logon)" }
    if ((Rank $st) -gt (Rank $worst)) { $worst = $st }
    $notes += $why
  }
  if (@($vs.errors).Count) { $worst = "FAIL"; $notes += "errors: $(@($vs.errors) -join '; ')" }
  Write-Result $worst "V84" $t84 ("policy $($vs.policy), package $($mx.package): " + ($notes -join "; "))
}

# ---------------------------------------------------------------- V85 seat licence pinned (seat mode)
# persona settings pin gcp.project / gcp.location; the last CLI log of each persona shows the licence location and no
# fallback to Vertex AI pay-as-you-go (an unlicensed account silently calls aiplatform.*, blocked by the allowlist)
$t85 = "Seat licence pinned to the configured project and location; no global / Vertex fallback in persona sessions"
if ([string](Get-AgyParam "agy-client-mode" "gateway") -eq "seat") {
  $wantP = [string](Get-AgyParam "agy-seat-project" ""); $wantL = [string](Get-AgyParam "agy-seat-location" "eu")
  $res = "PASS"; $why = @()
  foreach ($kp in @(Get-AgyKnownProfiles)) {
    $p = $kp.Name; $sf = "$($kp.Home)\.gemini\antigravity-cli\settings.json"
    if (-not (Test-Path $sf)) { continue }
    $g = $(try { (Get-Content $sf -Raw | ConvertFrom-Json).gcp } catch { $null })
    if (-not $g -or $g.project -ne $wantP -or $g.location -ne $wantL) { $res = "FAIL"; $why += "$p settings not pinned ($($g.project)/$($g.location))"; continue }
    $log = Get-ChildItem "$($kp.Home)\.gemini\antigravity-cli\log\cli-*.log" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $log) { $why += "$p no session yet"; continue }
    $loc = (Select-String -Path $log.FullName -Pattern "Selecting license \(.*Location: (\w+)\)" | Select-Object -Last 1)
    if ($loc -and $loc.Matches[0].Groups[1].Value -ne $wantL) { $res = "FAIL"; $why += "$p licence location $($loc.Matches[0].Groups[1].Value)" }
    elseif (Select-String -Path $log.FullName -Pattern "https://aiplatform\.[a-z.]*googleapis\.com" -Quiet) {
      if ($res -ne "FAIL") { $res = "WARN" }; $why += "$p fell back to Vertex AI (no seat licence / role for this account?)"
    } else { $why += "$p ok" }
  }
  Write-Result $res "V85" $t85 ("pinned $wantP/$wantL; " + ($why -join "; "))
}

# ---------------------------------------------------------------- V86 personas: local accounts or directory groups
$t86 = "Personas: source configured and enforced (AppLocker, egress firewall and hook use the same groups)"
$src = Get-AgyPersonaSource; $ps = Get-AgyPersonaSids
if ($src -eq "local") {
  Write-Result "PASS" "V86" $t86 "local persona accounts (dev / contractor); set agy-persona-source = groups for directory accounts"
} else {
  $why = @(); $res = "PASS"
  $dirS = @($ps.Values | ForEach-Object { $_ } | Where-Object { $_ -match '^S-1-12-1-' -or ($_ -match '^S-1-5-21-' -and $_ -notin @((Get-LocalGroup -Name "AGY-Dev", "AGY-Contractor" -ErrorAction SilentlyContinue).SID.Value)) })
  # directory accounts may also be mapped through the local AGY-Dev / AGY-Contractor groups (local group SID in the token)
  $localMembers = @("AGY-Dev", "AGY-Contractor" | ForEach-Object { Get-LocalGroupMember -Group $_ -ErrorAction SilentlyContinue }).Count
  if (-not $dirS -and $localMembers -eq 0) { $res = "FAIL"; $why += "agy-persona-groups has no directory group SID and the local persona groups are empty" }
  elseif (-not $dirS) { $why += "mapped through the local persona groups ($localMembers member(s))" }
  if ([string](Get-AgyParam "agy-app-control" "on") -ne "off") {
    $al = (Get-AppLockerPolicy -Local -Xml)
    $miss = @($dirS | Where-Object { $al -notmatch [regex]::Escape($_) })
    if ($miss) { $res = "FAIL"; $why += "AppLocker lacks $($miss -join ',')" }
  }
  if (Get-AgyParam "agy-egress-allowlist" $null) {
    $fw = @(Get-NetFirewallRule -Group "AGY egress" -ErrorAction SilentlyContinue | Get-NetFirewallSecurityFilter | ForEach-Object { $_.LocalUser }) -join " "
    $miss = @($dirS | Where-Object { $fw -notmatch [regex]::Escape($_) })
    if ($miss) { $res = "FAIL"; $why += "egress firewall lacks $($miss -join ',')" }
  }
  if (-not (Test-Path "$Root\persona-groups.json")) { $res = "FAIL"; $why += "persona-groups.json missing (hook)" }
  $seen = $(try { @((Get-Content "$Root\persona-profiles.json" -Raw | ConvertFrom-Json).PSObject.Properties).Count } catch { 0 })
  Write-Result $res "V86" $t86 ("directory groups: dev $(@($ps['dev']).Count - 1), contractor $(@($ps['contractor']).Count - 1) SID(s); profiles managed: $seen" + $(if ($why) { "; " + ($why -join "; ") } else { "" }))
}

# ---------------------------------------------------------------- V87 gateway mode: local credential proxy + device cert
if ([string](Get-AgyParam "agy-client-mode" "gateway") -eq "gateway") {
  $t87 = "Gateway mode: credential proxy running and refusing non-personas; device certificate valid"
  $why = @(); $res = "PASS"
  $task = Get-ScheduledTask -TaskName "AGY-CredProxy" -ErrorAction SilentlyContinue
  if (-not $task -or $task.State -ne "Running") { $res = "FAIL"; $why += "proxy task not running" }
  # this check runs as SYSTEM / an administrator = not a persona: the proxy must refuse it (403)
  $code = $(try { (Invoke-WebRequest "http://127.0.0.1:8443/v1beta/models" -UseBasicParsing -TimeoutSec 10).StatusCode } catch { [int]$_.Exception.Response.StatusCode })
  if ($code -ne 403) { $res = "FAIL"; $why += "proxy answered $code to a non-persona (expected 403)" }
  $crt = "C:\ProgramData\Antigravity\credproxy\device.crt"
  # every gateway device needs its certificate (Google Cloud VMs enrol it; laptops get it pre-issued or by enrolment)
  if ((Get-AgyDeviceAuth) -eq "cert" -or (Test-AgyOnGce)) {
    if (-not (Test-Path $crt)) { $res = "FAIL"; $why += "no device certificate" }
    else {
      $c = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $crt
      if ($c.NotAfter -lt (Get-Date).AddDays(1)) { $res = "FAIL"; $why += "device certificate expires $($c.NotAfter.ToString('s'))" } else { $why += "certificate until $($c.NotAfter.ToString('yyyy-MM-dd'))" }
      $acl = (Get-Acl "C:\ProgramData\Antigravity\credproxy\device.key").Access | Where-Object { $_.IdentityReference -notmatch "SYSTEM|Administrators" }
      if ($acl) { $res = "FAIL"; $why += "device key readable by $($acl.IdentityReference -join ',')" }
    }
  }
  Write-Result $res "V87" $t87 ($why -join "; ")
}

# ---------------------------------------------------------------- V72 AppLocker: developer build roots, contractor workspace deny
$t72 = "AppLocker: developers run builds from the build root only; contractors nothing from the workspace"
try {
  $pol = [xml](Get-AppLockerPolicy -Effective -Xml)
  $exe = @($pol.AppLockerPolicy.RuleCollection | Where-Object Type -eq "Exe")[0]
  $paths = @($exe.FilePathRule | ForEach-Object { "$($_.Action)|$($_.Name)|$($_.Conditions.FilePathCondition.Path)" })
  $devBuild = $paths | Where-Object { $_ -like "Allow|AGY dev build/run|*\build\*" }
  $conWs = $paths | Where-Object { $_ -like "Deny|AGY contractor no exec from workspace|*\projects\*" }
  $devWs = $paths | Where-Object { $_ -like "Deny|AGY no exec from writable|*\projects\*" }
  $curl = $paths | Where-Object { $_ -like "*curl.exe" }
  $binDeny = @($exe.FilePublisherRule | Where-Object { $_.Action -eq "Deny" -and $_.Name -like "AGY deny binary *" })
  $appxCol = @($pol.AppLockerPolicy.RuleCollection | Where-Object Type -eq "Appx")[0]
  $appxOk = $appxCol -and $appxCol.EnforcementMode -eq "Enabled" -and @($appxCol.FilePublisherRule).Count -ge 1
  # agent only for personas: Administrators denied, Everyone's Program Files rule excludes Antigravity
  $agyAdminDeny = [bool]($paths | Where-Object { $_ -like "Deny|AGY no agent for administrators|*Antigravity*" })
  $agyEveryoneEx = [bool](@($exe.FilePathRule | Where-Object { $_.Name -eq "Program Files" -and $_.Exceptions.FilePathCondition.Path -like "*Antigravity*" }))
  if ($devBuild -and $conWs -and -not $devWs -and -not $curl -and $binDeny.Count -ge 10 -and $appxOk -and $agyAdminDeny -and $agyEveryoneEx -and $exe.EnforcementMode -eq "Enabled") {
    Write-Result "PASS" "V72" $t72 "dev build/cache roots allowed, contractor workspace deny, $($binDeny.Count) publisher+binary denies (renamed copies), enforced"
  } else {
    Write-Result "FAIL" "V72" $t72 "devBuild=$([bool]$devBuild) contractorWs=$([bool]$conWs) devWsDeny=$([bool]$devWs) curlDeny=$([bool]$curl) binaryDenies=$($binDeny.Count) packagedAppRules=$([bool]$appxOk) agentPersonaOnly=$($agyAdminDeny -and $agyEveryoneEx) mode=$($exe.EnforcementMode)"
  }
} catch { Write-Result "FAIL" "V72" $t72 "AppLocker policy unreadable: $($_.Exception.Message)" }

# ---------------------------------------------------------------- V73 build layout environment
$t73 = "Build output and package caches outside the workspace (<drive>:\build, <drive>:\caches)"
$envKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
$need = "UseArtifactsOutput", "ArtifactsPath", "NUGET_PACKAGES", "npm_config_cache", "GOCACHE", "GOTMPDIR",
        "npm_config_prefix", "GOBIN", "PIPX_BIN_DIR", "UV_TOOL_BIN_DIR", "WORKON_HOME"
$miss = $need | Where-Object { -not (Get-Item $envKey).GetValue($_, $null) }
$dd = $(try { (Get-Content "$Root\devdrive-state.txt" -Raw).Trim() } catch { "unknown" })
if (-not $miss) { Write-Result "PASS" "V73" $t73 "ArtifactsPath=$((Get-Item $envKey).GetValue('ArtifactsPath', $null, 'DoNotExpandEnvironmentNames')); Dev Drive: $dd" }
else { Write-Result "FAIL" "V73" $t73 "missing machine environment: $($miss -join ', ')" }

# ---------------------------------------------------------------- V74 WDAC base + build-root supplemental active
$t74 = "WDAC base and build-root supplemental policy active"
$suppId = "a6a0b11d-0000-4a67-8000-000000000018"
# the base must allow supplemental policies (rule option 17), otherwise Windows ignores the build-root supplemental
$baseXmlText = $(try { Get-Content "$Root\agy-wdac.xml" -Raw -ErrorAction Stop } catch { "" })
$allowSupp = $baseXmlText -match "Enabled:Allow Supplemental Policies"
if (-not (Get-Command CiTool.exe -ErrorAction SilentlyContinue)) {
  # Windows 10: no CiTool - policies are staged in the active-policy folder and load at the next reboot; activation is
  # read from CodeIntegrity event 3099 ("Refreshed and activated Code Integrity policy {GUID}") since the last boot
  $act = "$env:windir\System32\CodeIntegrity\CiPolicies\Active"
  $staged = @(Get-ChildItem "C:\ProgramData\Antigravity" -Filter "{*}.cip" -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $act $_.Name) })
  $suppCip = @($staged | Where-Object { $_.BaseName -match $suppId })
  $baseCip = @($staged | Where-Object { $_.BaseName -notmatch $suppId })
  if (-not $suppCip -or -not $baseCip) { Write-Result "FAIL" "V74" $t74 "staged policies: base $($baseCip.Count), supplemental $($suppCip.Count) in $act" }
  elseif (-not $allowSupp) { Write-Result "FAIL" "V74" $t74 "base policy lacks 'Enabled:Allow Supplemental Policies' - the supplemental is ignored" }
  else {
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-CodeIntegrity/Operational"; Id = 3099; StartTime = $boot } -ErrorAction SilentlyContinue)
    $on = @{}
    foreach ($c in @($baseCip[0], $suppCip[0])) {
      $g = $c.BaseName.Trim("{}")
      $on[$c.BaseName] = @($ev | Where-Object { $_.Message -match [regex]::Escape($g) }).Count -gt 0
    }
    $newer = @($baseCip[0], $suppCip[0] | Where-Object { $_.LastWriteTime -gt $boot }).Count -gt 0
    if ($on[$baseCip[0].BaseName] -and $on[$suppCip[0].BaseName] -and -not $newer) {
      Write-Result "PASS" "V74" $t74 "base $($baseCip[0].BaseName) + supplemental activated at boot (event 3099; no CiTool on this OS)"
    } else {
      Write-Result "WARN" "V74" $t74 ("staged in $act (no CiTool on this OS), active after a reboot - activated since boot: base " +
        "$($on[$baseCip[0].BaseName]), supplemental $($on[$suppCip[0].BaseName])$(if ($newer) { '; policy updated after the last boot' })")
    }
  }
} else {
try {
  $list = (& CiTool.exe --list-policies -json | ConvertFrom-Json).Policies
  $base = $list | Where-Object { $_.FriendlyName -eq "AGY workstation base" -and $_.IsEnforced }
  $supp = $list | Where-Object { $_.PolicyID -match $suppId -and $_.IsEnforced }
  $mode = $(try { (Get-Content "$Root\agy-wdac.mode" -Raw -ErrorAction Stop).Split("|")[0] } catch { "?" })
  if ($base -and $supp -and $allowSupp) { Write-Result "PASS" "V74" $t74 "base active ($mode mode, allows supplemental policies), supplemental active" }
  else { Write-Result "FAIL" "V74" $t74 "base=$([bool]$base) supplemental=$([bool]$supp) allowSupplemental=$allowSupp (CiTool --list-policies)" }
} catch { Write-Result "FAIL" "V74" $t74 "CiTool failed: $($_.Exception.Message)" }
}

# ---------------------------------------------------------------- V75 WSL / Docker only for AGY-ContainerDev
$t75 = "WSL / Docker Desktop blocked for personas outside AGY-ContainerDev"
$nc = @(Get-LocalGroupMember -Group "AGY-NoContainers" -ErrorAction SilentlyContinue).Count
$rule = $paths | Where-Object { $_ -like "Deny|AGY no WSL/Docker|*wsl.exe" }
if ($rule -and $nc -gt 0) { Write-Result "PASS" "V75" $t75 "deny rule present, $nc persona(s) in AGY-NoContainers" }
else { Write-Result "FAIL" "V75" $t75 "rule=$([bool]$rule) members=$nc" }

# ---------------------------------------------------------------- V76 package sources = corporate proxy (when configured)
$t76 = "Package managers use the corporate package proxy"
$pp = (Get-AgyParam "agy-package-proxy" $null)
if ($pp -is [string]) { $pp = $(try { $pp | ConvertFrom-Json } catch { $null }) }
if (-not $pp -or @($pp.PSObject.Properties).Count -eq 0) {
  Write-Result "WARN" "V76" $t76 "no package proxy configured (enable_package_proxy / nuget_feed_url): public registries via the egress allowlist"
} else {
  $bad = @()
  if ($pp.npm -and (Get-Item $envKey).GetValue("npm_config_registry", $null) -ne $pp.npm) { $bad += "npm" }
  if ($pp.python -and (Get-Item $envKey).GetValue("PIP_INDEX_URL", $null) -ne $pp.python) { $bad += "pip" }
  if ($pp.go -and (Get-Item $envKey).GetValue("GOPROXY", $null) -ne "$($pp.go),off") { $bad += "go" }
  if ($pp.nuget -and -not (Test-Path "${env:ProgramFiles(x86)}\NuGet\Config\agy-packages.config")) { $bad += "nuget" }
  $fmt = (@($pp.PSObject.Properties) | ForEach-Object Name) -join ","
  if (-not $bad) { Write-Result "PASS" "V76" $t76 "configured: $fmt" } else { Write-Result "FAIL" "V76" $t76 "not applied: $($bad -join ', ') (configured: $fmt)" }
}

# ---------------------------------------------------------------- V77 Sysmon running with the managed configuration
$t77 = "Sysmon running with the AGY configuration (process lineage for the SIEM)"
$svc = Get-Service Sysmon64 -ErrorAction SilentlyContinue
$want = $(try { (Get-FileHash "$Root\bundle\files\controls\agy-sysmon.xml" -Algorithm SHA256).Hash } catch { "" })
$have = $(try { (Get-Content "$Root\sysmon-config.sha256" -Raw -ErrorAction Stop).Trim() } catch { "" })
if ($svc.Status -eq "Running" -and $want -and $want -eq $have) { Write-Result "PASS" "V77" $t77 "Sysmon64 running, config $($have.Substring(0, 12))" }
else { Write-Result "FAIL" "V77" $t77 "service=$($svc.Status) config applied=$($have -eq $want)" }

# ---------------------------------------------------------------- V78 human review mandatory (no review-bypass sessions)
$t78 = "Human review mandatory: review-bypass options refused (launcher shim first on PATH, hook review guard on)"
$shimOk = Test-Path "C:\Program Files\Antigravity\bin\agy.cmd"
$first = (((Get-Item $envKey).GetValue("Path", "", "DoNotExpandEnvironmentNames")) -split ";")[0] -eq "C:\Program Files\Antigravity\bin"
$guard = $(try { (Get-Content "$Root\hooks\policy.json" -Raw | ConvertFrom-Json).default.deny_review_bypass -eq $true } catch { $false })
if ($shimOk -and $first -and $guard) { Write-Result "PASS" "V78" $t78 "shim first on the machine PATH, deny_review_bypass = true" }
else { Write-Result "FAIL" "V78" $t78 "shim=$shimOk first-on-PATH=$first hook-guard=$guard" }

# ---------------------------------------------------------------- V79-V81 standard users: elevation settings
$sysPol = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$cpbu = (Get-Item $sysPol).GetValue("ConsentPromptBehaviorUser", $null)
if ($cpbu -eq 0) { Write-Result "PASS" "V79" "UAC for standard users: automatically deny elevation requests" "ConsentPromptBehaviorUser=0" }
else { Write-Result "FAIL" "V79" "UAC for standard users: automatically deny elevation requests" "ConsentPromptBehaviorUser=$cpbu" }
$sudoPol = $(try { (Get-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sudo").GetValue("EnableSudo", $null) } catch { $null })
if ($sudoPol -eq 0) { Write-Result "PASS" "V80" "Windows sudo disabled" "policy EnableSudo=0" }
else { Write-Result "FAIL" "V80" "Windows sudo disabled" "policy EnableSudo=$sudoPol" }
$os = Get-CimInstance Win32_OperatingSystem
if ($os.ProductType -ne 1 -or [Environment]::OSVersion.Version.Build -lt 26100) {
  Write-Result "WARN" "V81" "Administrator protection on" "not supported on this OS (build $([Environment]::OSVersion.Version.Build), product type $($os.ProductType)); verify on Windows 11"
} else {
  $ap = (Get-Item $sysPol).GetValue("TypeOfAdminApprovalMode", $null)
  Write-Result $(if ($ap -eq 2) { "PASS" } else { "FAIL" }) "V81" "Administrator protection on" "TypeOfAdminApprovalMode=$ap (2 = on; active after reboot)"
}

# ---------------------------------------------------------------- V83 pre-provisioning (no admin needed for daily work)
$t83 = "Pre-provisioned developer rights: long paths, symlinks, user-mode ETW, URL ACLs, no firewall prompts, VS updates"
$bad = @()
if ((Get-Item "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem").GetValue("LongPathsEnabled", 0) -ne 1) { $bad += "long paths" }
$devSid = (Get-LocalGroup -Name "AGY-Dev").SID.Value
$inf = "$env:TEMP\agy-v83.inf"; & secedit /export /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
if (-not (Select-String -Path $inf -Pattern ("^SeCreateSymbolicLinkPrivilege.*(\*" + [regex]::Escape($devSid) + "\b|[=,]\s*AGY-Dev\s*(,|$))") -Quiet)) { $bad += "symlink right" }
Remove-Item $inf -Force -ErrorAction SilentlyContinue
$plu = @(Get-LocalGroupMember -SID "S-1-5-32-559" -ErrorAction SilentlyContinue | ForEach-Object { $_.SID.Value })
$devs = @(Get-LocalGroupMember -Group "AGY-Dev" -ErrorAction SilentlyContinue | ForEach-Object { $_.SID.Value })
if (@($devs | Where-Object { $plu -notcontains $_ }).Count) { $bad += "Performance Log Users" }
if (((& netsh http show urlacl url=http://+:5000/) -join " ") -notmatch "AGY-Dev|$([regex]::Escape($devSid))") { $bad += "URL ACL 5000" }
if (@(Get-NetFirewallProfile | Where-Object NotifyOnListen -ne "False").Count) { $bad += "firewall prompts" }
$vs = $(try { (Get-Item "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Setup").GetValue("AllowStandardUserControl", 0) } catch { 0 })
if ($vs -ne 1) { $bad += "VS AllowStandardUserControl" }
$cmd = $(try { (Get-Item "$sysPol\Audit").GetValue("ProcessCreationIncludeCmdLine_Enabled", 0) } catch { 0 })
if ($cmd -ne 1) { $bad += "4688 command line" }
if (-not $bad) { Write-Result "PASS" "V83" $t83 "all present ($($devs.Count) developer account(s))" }
else { Write-Result "FAIL" "V83" $t83 "missing: $($bad -join ', ')" }

# ---------------------------------------------------------------- V98 telemetry shipper (package-managed devices)
$t98 = "Telemetry shipper sends AGY events with the device identity (last successful send < 30 min)"
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\AGY\Modules") -or -not (Test-AgyModule "telemetry-shipper")) {
  Write-Result "SKIP" "V98" $t98 "telemetry package not installed"
} else {
  $tst = $(try { Get-Content "C:\ProgramData\AntigravityTelemetry\state.json" -Raw -ErrorAction Stop | ConvertFrom-Json } catch { $null })
  $task = Get-ScheduledTask -TaskName "AGY-Telemetry" -ErrorAction SilentlyContinue
  if (-not $task) { Write-Result "FAIL" "V98" $t98 "scheduled task AGY-Telemetry missing" }
  elseif (-not $tst -or -not $tst.last_success) { Write-Result "WARN" "V98" $t98 "no successful send yet$(if ($tst.last_error) { ': ' + $tst.last_error })" }
  else {
    $age = ((Get-Date).ToUniversalTime() - [datetime]::Parse($tst.last_success).ToUniversalTime()).TotalMinutes
    if ($age -le 30) { Write-Result "PASS" "V98" $t98 ("last send {0:n0} min ago, sent today {1} bytes" -f $age, $tst.bytes_today) }
    else { Write-Result "FAIL" "V98" $t98 ("last send {0:n0} min ago$(if ($tst.last_error) { '; last error: ' + $tst.last_error })" -f $age) }
  }
}
# ---------------------------------------------------------------- V99 device certificate from the customer PKI
$t99 = "Device certificate from your PKI present and valid (client authentication, > 7 days left)"
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\AGY\Modules") -or -not (Test-AgyModule "pki-byo")) {
  Write-Result "SKIP" "V99" $t99 "device identity package not installed"
} else {
  $src = [string](Get-AgyParam "agy-device-cert-source" "store"); $iss = [string](Get-AgyParam "agy-device-cert-issuer" "")
  $c = $null
  if ($src -eq "file") { $f = [string](Get-AgyParam "agy-device-cert-file" ""); if ($f -and (Test-Path $f)) { $c = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $f } }
  else { $c = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.HasPrivateKey -and ($_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.2") -and (-not $iss -or $_.Issuer -match [regex]::Escape("CN=$iss")) } | Sort-Object NotAfter -Descending | Select-Object -First 1 }
  if (-not $c) { Write-Result "FAIL" "V99" $t99 "no device certificate ($src$(if ($iss) { ", issuer $iss" }))" }
  elseif ($c.NotAfter -lt (Get-Date).AddDays(7)) { Write-Result "WARN" "V99" $t99 "$($c.Subject) expires $($c.NotAfter.ToString('yyyy-MM-dd'))" }
  else { Write-Result "PASS" "V99" $t99 "$($c.Subject) from $($c.Issuer), until $($c.NotAfter.ToString('yyyy-MM-dd'))" }
}
# ---------------------------------------------------------------- V100 customer EDR present (bring your own)
$t100 = "Your EDR agent is running (operating-system telemetry stays with your EDR)"
$edr = [string](Get-AgyParam "agy-edr-service" "")
if (-not $edr) { Write-Result "SKIP" "V100" $t100 "no EDR service configured (agy-edr-service)" }
else {
  $svc = Get-Service -Name $edr -ErrorAction SilentlyContinue
  if ($svc -and $svc.Status -eq "Running") { Write-Result "PASS" "V100" $t100 "$edr running" }
  else { Write-Result "FAIL" "V100" $t100 "$edr $(if ($svc) { $svc.Status } else { 'not installed' })" }
}
