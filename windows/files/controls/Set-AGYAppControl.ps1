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

# AGY Windows application control (EDR / app-control stand-in; same intent as the Linux AppArmor agent profile).
#   AppLocker (per persona group, enforced): no remote-access / download / script-host tools, no executables or
#     scripts from user-writable folders; contractors also lose robocopy / net / ftp (egress, not an exe deny, is the
#     control for HTTP clients). Script rules put the personas' PowerShell into Constrained Language Mode, except
#     Microsoft- or corporate-signed scripts for developers (FullLanguage: VS Package Manager Console, Az / Google
#     modules). Administrators and SYSTEM keep the default allow rules.
#   Developers build and run their own code: executables / scripts are allowed from the build-output root
#     (D:\build\<user>), the package caches (D:\caches\<user>), node_modules and dotnet global tools - not from the
#     rest of the workspace. Contractors: nothing from the workspace (agentic work belongs on Cloud Workstations).
#   WSL / Docker Desktop: only for members of AGY-ContainerDev (they bypass AppLocker, CLM and the per-user firewall).
#   WDAC (device-wide baseline): Microsoft-signed + Program Files, AUDIT mode by default (events 3076 -> SIEM), and a
#     supplemental policy for the build / cache roots (option 18 only there).
param([ValidateSet("Audit", "Enforce")][string]$WdacMode = "Audit", [string]$Workspace = "D:\projects",
      [string]$BuildRoot = "D:\build", [string]$CacheRoot = "D:\caches", [string]$CorpScriptPublisher = "")
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "AGYConfig.ps1")   # persona SIDs: local groups and / or directory (Entra / AD) group SIDs
function Audit([string]$m, [string]$type = "Information") { Write-EventLog -LogName Application -Source "agy-mdm" -EventId 1002 -EntryType $type -Message $m }
# CiTool.exe ships with Windows 11 22H2 and later. Without it (Windows 10) the multiple-policy-format .cip is staged in
# the CodeIntegrity active-policy folder instead; Windows loads it at the next reboot.
$HasCiTool = [bool](Get-Command CiTool.exe -ErrorAction SilentlyContinue)
function Install-AgyCiPolicy([string]$cip, [string]$label) {
  if ($HasCiTool) { & CiTool.exe --update-policy $cip -json | Out-Null; return }
  $active = "$env:windir\System32\CodeIntegrity\CiPolicies\Active"
  New-Item -ItemType Directory -Force -Path $active | Out-Null
  Copy-Item $cip (Join-Path $active (Split-Path $cip -Leaf)) -Force
  Audit "WDAC_PENDING_REBOOT: $label staged in $active (no CiTool on this OS) - active after the next reboot" "Warning"
}

# AGY-NoContainers = (AGY-Dev + AGY-Contractor) minus AGY-ContainerDev: AppLocker has no per-user exceptions and
# deny wins over allow, so the WSL / Docker deny targets this derived group (kept in sync every drift run)
foreach ($g in "AGY-ContainerDev", "AGY-NoContainers") {
  if (-not (Get-LocalGroup -Name $g -ErrorAction SilentlyContinue)) { New-LocalGroup -Name $g -Description "AGY managed" | Out-Null }
}
$containerDev = @(Get-LocalGroupMember -Group "AGY-ContainerDev" -ErrorAction SilentlyContinue | ForEach-Object { $_.SID.Value })
# members: local persona accounts + (persona source = groups) the directory accounts of persona profiles on this device
$ncWant = @(@("AGY-Dev", "AGY-Contractor" | ForEach-Object { Get-LocalGroupMember -Group $_ -ErrorAction SilentlyContinue } | ForEach-Object { $_.SID.Value }) +
            @(Get-AgyPersonaProfiles | ForEach-Object { $_.Sid }) |
          Where-Object { $_ -notin $containerDev } | Sort-Object -Unique)
$have = @(Get-LocalGroupMember -Group "AGY-NoContainers" -ErrorAction SilentlyContinue | ForEach-Object { $_.SID.Value })
foreach ($m in $ncWant | Where-Object { $_ -notin $have }) { Add-LocalGroupMember -Group "AGY-NoContainers" -Member $m }
foreach ($m in $have | Where-Object { $_ -notin $ncWant }) { Remove-LocalGroupMember -Group "AGY-NoContainers" -Member $m }

$sid = @{}
foreach ($g in "AGY-Dev", "AGY-Contractor", "AGY-NoContainers") { $sid[$g] = (Get-LocalGroup -Name $g).SID.Value }
# every persona rule is written once per SID: the local group (local personas) and each directory group SID
$ps = Get-AgyPersonaSids; $devS = @($ps["dev"]); $conS = @($ps["contractor"]); $allS = @($devS + $conS)
$everyone = "S-1-1-0"; $admins = "S-1-5-32-544"
$script:n = 0
function New-RuleId { $script:n++; "a6a00000-0000-4a67-8000-{0:x12}" -f $script:n }
function PublisherRule([string]$user, [string]$name, [string]$publisher) {
  "<FilePublisherRule Id=""$(New-RuleId)"" Name=""$name"" Description=""AGY"" UserOrGroupSid=""$user"" Action=""Allow""><Conditions><FilePublisherCondition PublisherName=""$publisher"" ProductName=""*"" BinaryName=""*""><BinaryVersionRange LowSection=""*"" HighSection=""*"" /></FilePublisherCondition></Conditions></FilePublisherRule>"
}
function BinaryDenyRule([string]$user, [string]$name, $pub) {
  # publisher + original file name, any path / version: a renamed or copied system tool is still blocked
  "<FilePublisherRule Id=""$(New-RuleId)"" Name=""$name"" Description=""AGY"" UserOrGroupSid=""$user"" Action=""Deny""><Conditions><FilePublisherCondition PublisherName=""$([Security.SecurityElement]::Escape($pub.PublisherName))"" ProductName=""*"" BinaryName=""$([Security.SecurityElement]::Escape($pub.BinaryName))""><BinaryVersionRange LowSection=""*"" HighSection=""*"" /></FilePublisherCondition></Conditions></FilePublisherRule>"
}
function Get-BinaryPublishers([string[]]$paths) {
  # resolve the deny list (env vars, folder wildcards) to the signed files on this device and read their publisher
  # and original file name; unsigned files or files without version resources are skipped (path rules still apply)
  $seen = @{}
  foreach ($p in $paths) {
    $full = [Environment]::ExpandEnvironmentVariables(($p -replace "%OSDRIVE%", $env:SystemDrive -replace "%SYSTEM32%", "$env:WINDIR\System32" `
             -replace "%PROGRAMFILES%", $env:ProgramFiles -replace "%PROGRAMFILES\(X86\)%", ${env:ProgramFiles(x86)}))
    # folder wildcards only under Windows (e.g. System32\OpenSSH): a vendor folder such as the Cloud SDK bundles
    # third-party binaries (python.exe) whose publisher rule would block them everywhere
    if ($full.EndsWith("*") -and -not $full.StartsWith($env:WINDIR, [StringComparison]::OrdinalIgnoreCase)) { continue }
    $files = if ($full.EndsWith("*")) { Get-ChildItem (Split-Path $full) -Filter *.exe -File -ErrorAction SilentlyContinue } else { Get-Item $full -ErrorAction SilentlyContinue }
    foreach ($f in @($files)) {
      $info = $(try { Get-AppLockerFileInformation -Path $f.FullName -ErrorAction Stop } catch { $null })
      if ($info -and $info.Publisher -and $info.Publisher.BinaryName) { $seen["$($info.Publisher.PublisherName)|$($info.Publisher.BinaryName)"] = $info.Publisher }
    }
  }
  $seen.Values
}
function PathRuleEx([string]$action, [string]$user, [string]$name, [string]$path, [string[]]$except) {
  $ex = ($except | ForEach-Object { "<FilePathCondition Path=""$_"" />" }) -join ""
  "<FilePathRule Id=""$(New-RuleId)"" Name=""$name"" Description=""AGY"" UserOrGroupSid=""$user"" Action=""$action""><Conditions><FilePathCondition Path=""$path"" /></Conditions><Exceptions>$ex</Exceptions></FilePathRule>"
}
function PathRule([string]$action, [string]$user, [string]$name, [string]$path) {
  "<FilePathRule Id=""$(New-RuleId)"" Name=""$name"" Description=""AGY"" UserOrGroupSid=""$user"" Action=""$action""><Conditions><FilePathCondition Path=""$path"" /></Conditions></FilePathRule>"
}

# tools the personas must not run (the hook denies the command forms; AppLocker blocks every launch path)
$denyAll = @(
  "%SYSTEM32%\OpenSSH\*", "%SYSTEM32%\mstsc.exe", "%SYSTEM32%\certutil.exe", "%SYSTEM32%\bitsadmin.exe",
  "%SYSTEM32%\mshta.exe", "%SYSTEM32%\wscript.exe", "%SYSTEM32%\cscript.exe", "%SYSTEM32%\runas.exe",
  "%SYSTEM32%\cipher.exe", "%SYSTEM32%\vssadmin.exe", "%SYSTEM32%\wbadmin.exe", "%SYSTEM32%\reg.exe",
  "%SYSTEM32%\schtasks.exe", "%SYSTEM32%\sc.exe", "%SYSTEM32%\netsh.exe", "%SYSTEM32%\WindowsPowerShell\v1.0\powershell_ise.exe",
  "%PROGRAMFILES%\CorpTools\*"
)
# developers build on Google Cloud and keep the Cloud SDK (own identity, IAM floor + PAM for elevation; the hook forces
# the agent onto its agent service account and denies token / key / config verbs). Contractors: no Cloud SDK.
$denyContractor = @("%PROGRAMFILES%\Google\Cloud SDK\*", "%PROGRAMFILES(X86)%\Google\Cloud SDK\*", "%SYSTEM32%\robocopy.exe", "%SYSTEM32%\net.exe", "%SYSTEM32%\net1.exe",
                    "%SYSTEM32%\ftp.exe", "%SYSTEM32%\tftp.exe")
# user-writable locations: nothing executes from there (copied / downloaded / built binaries, staged scripts)
$writable = @("%OSDRIVE%\Users\*\Downloads\*", "%OSDRIVE%\Users\*\AppData\Local\Temp\*", "%OSDRIVE%\Users\*\Desktop\*",
              "%OSDRIVE%\Users\Public\*")
$writableContractor = @("$Workspace\*", "$BuildRoot\*", "$CacheRoot\*")
# developers: own build output, package caches, node_modules (native tools such as esbuild), dotnet global tools
$devExe = @("$BuildRoot\*", "$CacheRoot\*", "$Workspace\*\node_modules\*", "%OSDRIVE%\Users\*\.dotnet\tools\*",
            "$Workspace\*\.venv\Scripts\*")
$devScript = @("$BuildRoot\*", "$Workspace\*\node_modules\.bin\*", "$Workspace\*\.venv\Scripts\*")
$containerTools = @("%SYSTEM32%\wsl.exe", "%SYSTEM32%\wslhost.exe", "%SYSTEM32%\wslconfig.exe", "%SYSTEM32%\bash.exe",
                    "%PROGRAMFILES%\WSL\*", "%PROGRAMFILES%\Docker\*")
$msPublisher = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"

$exe = @(); $scr = @()
# defaults (as the AppLocker default rules): Windows + Program Files for everyone, everything for administrators
$exe += PathRule "Allow" $everyone "Windows" "%WINDIR%\*"
# Antigravity runs only for the managed personas: excluded from the Everyone rule, allowed for AGY-Dev / AGY-Contractor,
# denied for Administrators (their allow-all rule would otherwise cover it). Any other account - local or domain -
# has no rule that allows it (Windows 11 test: an unmanaged admin ran agy without hook / settings and bypassed the sandbox)
$agyPath = "%PROGRAMFILES%\Antigravity\*"
$exe += PathRuleEx "Allow" $everyone "Program Files" "%PROGRAMFILES%\*" @($agyPath)
$exe += PathRule "Allow" $everyone "Program Files (x86)" "%PROGRAMFILES(X86)%\*"
$exe += PathRule "Allow" $admins "Administrators" "*"
$exe += PathRule "Deny" $admins "AGY no agent for administrators" $agyPath
# Microsoft Defender platform binaries live under ProgramData (Microsoft-signed, admin-only writable)
$exe += PathRule "Allow" $everyone "Microsoft Defender platform" "%OSDRIVE%\ProgramData\Microsoft\Windows Defender\Platform\*"
# corporate hook launcher + policy (admin-only writable): must run for every persona, else every tool call fails closed
$exe += PathRule "Allow" $everyone "AGY hook" "%OSDRIVE%\ProgramData\Antigravity\hooks\*"
$scr += PathRule "Allow" $everyone "AGY hook launcher" "%OSDRIVE%\ProgramData\Antigravity\hooks\*"
$scr += PathRule "Allow" $everyone "Windows scripts" "%WINDIR%\*"
$scr += PathRuleEx "Allow" $everyone "Program Files scripts" "%PROGRAMFILES%\*" @($agyPath)
$scr += PathRule "Allow" $admins "Administrators scripts" "*"
$scr += PathRule "Deny" $admins "AGY no agent launcher for administrators" $agyPath
foreach ($x in $allS) {
  foreach ($p in $denyAll) { $exe += PathRule "Deny" $x "AGY deny $([IO.Path]::GetFileName($p.TrimEnd('*','\')))" $p }
  foreach ($p in $writable) { $exe += PathRule "Deny" $x "AGY no exec from writable" $p; $scr += PathRule "Deny" $x "AGY no scripts from writable" $p }
}
foreach ($x in $conS) { foreach ($p in $denyContractor) { $exe += PathRule "Deny" $x "AGY contractor deny $([IO.Path]::GetFileName($p))" $p } }
# the same tools by publisher + original file name (renamed copies, e.g. reg.exe copied into D:\build, stay blocked)
$pubAll = @(Get-BinaryPublishers $denyAll); $pubContractor = @(Get-BinaryPublishers $denyContractor)
foreach ($x in $allS) { foreach ($pb in $pubAll) { $exe += BinaryDenyRule $x "AGY deny binary $($pb.BinaryName)" $pb } }
foreach ($x in $conS) { foreach ($pb in $pubContractor) { $exe += BinaryDenyRule $x "AGY contractor deny binary $($pb.BinaryName)" $pb } }
foreach ($x in $conS) {
  foreach ($p in $writableContractor) {
    $exe += PathRule "Deny" $x "AGY contractor no exec from workspace" $p
    $scr += PathRule "Deny" $x "AGY contractor no scripts from workspace" $p
  }
}
foreach ($x in $allS) {
  $exe += PathRule "Allow" $x "AGY agent for personas" $agyPath
  $scr += PathRule "Allow" $x "AGY agent launcher for personas" $agyPath
}
foreach ($x in $devS) {
  foreach ($p in $devExe) { $exe += PathRule "Allow" $x "AGY dev build/run" $p }
  foreach ($p in $devScript) { $scr += PathRule "Allow" $x "AGY dev build scripts" $p }
}
foreach ($p in $containerTools) { $exe += PathRule "Deny" $sid["AGY-NoContainers"] "AGY no WSL/Docker" $p }
# signed scripts / modules run in FullLanguage for developers (CLM for everything else); contractors: path rules only
foreach ($x in $devS) {
  $scr += PublisherRule $x "AGY dev Microsoft-signed scripts" $msPublisher
  if ($CorpScriptPublisher) { $scr += PublisherRule $x "AGY dev corporate-signed scripts" $CorpScriptPublisher }
}

# packaged (MSIX / Store) apps: with Exe rules enforced and no Appx collection, AppLocker blocks EVERY packaged app for
# every user (event 8027: Notepad, Calculator, App Installer, parts of Settings) - found on the Windows 11 test device.
# Default rule: all signed packaged apps for Everyone; unsigned packages stay blocked; Store installs are governed by
# Intune / Store policy.
$appx = @("<FilePublisherRule Id=""$(New-RuleId)"" Name=""AGY all signed packaged apps"" Description=""AGY"" UserOrGroupSid=""$everyone"" Action=""Allow""><Conditions><FilePublisherCondition PublisherName=""*"" ProductName=""*"" BinaryName=""*""><BinaryVersionRange LowSection=""0.0.0.0"" HighSection=""*"" /></FilePublisherCondition></Conditions></FilePublisherRule>")
$xml = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">$($exe -join "")</RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="Enabled">$($scr -join "")</RuleCollection>
  <RuleCollection Type="Appx" EnforcementMode="Enabled">$($appx -join "")</RuleCollection>
</AppLockerPolicy>
"@
$xmlFile = "C:\ProgramData\Antigravity\agy-applocker.xml"
$changed = -not (Test-Path $xmlFile) -or ([IO.File]::ReadAllText($xmlFile) -ne $xml)
# drift / tamper: the live policy is what counts - re-apply if any collection is no longer enforced (e.g. switched to
# AuditOnly or cleared by an administrator), even when our saved copy is unchanged (found on the Windows 11 test device)
$live = $(try { @(([xml](Get-AppLockerPolicy -Effective -Xml)).AppLockerPolicy.RuleCollection) } catch { @() })
$notEnforced = @("Exe", "Script", "Appx" | Where-Object { $t = $_; -not ($live | Where-Object { $_.Type -eq $t -and $_.EnforcementMode -eq "Enabled" }) })
if ($notEnforced -and -not $changed) { $changed = $true; Audit "APPLOCKER_DRIFT corrected: not enforced: $($notEnforced -join ', ')" "Warning" }
# rule content: the local policy must hold exactly our rules - a removed deny (e.g. "AGY no agent for administrators")
# or an added allow keeps every collection enforced, so compare a per-rule fingerprint (Windows 11 tamper test)
function RuleSet([xml]$doc) {
  $set = @()
  foreach ($rc in @($doc.AppLockerPolicy.RuleCollection)) {
    foreach ($r in @($rc.ChildNodes | Where-Object { $_.NodeType -eq "Element" -and $_.LocalName -like "*Rule" })) {
      $attrs = @($r.SelectNodes(".//*[local-name()!='Conditions' and local-name()!='Exceptions']") | ForEach-Object {
        $e = $_; $e.LocalName + "(" + ((@($e.Attributes | ForEach-Object { "$($_.Name)=$($_.Value)" }) | Sort-Object) -join ",") + ")" })
      $set += ("$($rc.Type)|$($r.LocalName)|$($r.Id)|$($r.Action)|$($r.UserOrGroupSid)|" + ($attrs -join ";")).ToLowerInvariant()
    }
  }
  @($set | Sort-Object)
}
if (-not $changed) {
  $local = $(try { RuleSet ([xml](Get-AppLockerPolicy -Local -Xml)) } catch { @() })
  $diff = @(Compare-Object -ReferenceObject (RuleSet ([xml]$xml)) -DifferenceObject $local)
  if ($diff.Count) {
    $changed = $true
    $missing = @($diff | Where-Object SideIndicator -eq "<=").Count; $extra = @($diff | Where-Object SideIndicator -eq "=>").Count
    Audit "APPLOCKER_DRIFT corrected: rules changed ($missing missing, $extra unexpected)" "Warning"
  }
}
if ($changed) {
  [IO.File]::WriteAllText($xmlFile, $xml, (New-Object Text.UTF8Encoding $false))
  Set-AppLockerPolicy -XmlPolicy $xmlFile          # replaces the local AppLocker policy
  Audit "AppLocker policy applied ($($exe.Count) exe rules, $($scr.Count) script rules)"
}
Set-Service AppIDSvc -StartupType Automatic -ErrorAction SilentlyContinue
if ((Get-Service AppIDSvc).Status -ne "Running") { Start-Service AppIDSvc }

# ---------------------------------------------------------------- WDAC base policy (device-wide), audit by default
$wdacXml = "C:\ProgramData\Antigravity\agy-wdac.xml"; $marker = "C:\ProgramData\Antigravity\agy-wdac.mode"
$want = "$WdacMode|$((Get-FileHash $PSCommandPath -Algorithm SHA256).Hash)"
if (-not (Test-Path $marker) -or (Get-Content $marker -Raw).Trim() -ne $want) {
  Copy-Item "$env:WINDIR\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml" $wdacXml -Force
  # admin-writable install locations as file-path rules, in a separate policy file merged into the base
  $rules = New-Object System.Collections.Generic.List[object]
  # + admin-only ProgramData locations found by v_wdac_enforce_readiness on the reference VM: GCE package agent
  #   (GooGet) and packaged-app COM proxies (Windows Terminal)
  foreach ($pth in "%OSDRIVE%\Program Files\*", "%OSDRIVE%\Program Files (x86)\*", "%OSDRIVE%\ProgramData\Antigravity\*",
                   "%OSDRIVE%\ProgramData\GooGet\*", "%OSDRIVE%\ProgramData\Microsoft\Windows\AppRepository\Packages\*") {
    foreach ($r in (New-CIPolicyRule -FilePathRule $pth)) { $rules.Add($r) }
  }
  $extra = "C:\ProgramData\Antigravity\agy-wdac-paths.xml"
  New-CIPolicy -Rules $rules.ToArray() -FilePath $extra -UserPEs | Out-Null
  Merge-CIPolicy -PolicyPaths $wdacXml, $extra -OutputFilePath $wdacXml | Out-Null
  Set-CIPolicyIdInfo -FilePath $wdacXml -PolicyName "AGY workstation base" -PolicyId "AGY-$((Get-Date).ToString('yyyyMMdd'))" | Out-Null
  Set-RuleOption -FilePath $wdacXml -Option 0           # user-mode code integrity
  Set-RuleOption -FilePath $wdacXml -Option 16          # update policy without reboot
  Set-RuleOption -FilePath $wdacXml -Option 17          # allow supplemental policies (else the build-root supplemental is ignored)
  if ($WdacMode -eq "Audit") { Set-RuleOption -FilePath $wdacXml -Option 3 } else { Set-RuleOption -FilePath $wdacXml -Option 3 -Delete }
  $guid = ([xml](Get-Content $wdacXml)).SiPolicy.PolicyID
  $cip = "C:\ProgramData\Antigravity\$guid.cip"
  ConvertFrom-CIPolicy -XmlFilePath $wdacXml -BinaryFilePath $cip | Out-Null
  Install-AgyCiPolicy $cip "WDAC base policy"
  $want | Set-Content $marker -Encoding ascii
  Audit "WDAC base policy $guid applied in $WdacMode mode"
}
# ---------------------------------------------------------------- WDAC supplemental: developer build / cache roots
# Path rules to user-writable folders are ignored at runtime unless option 18 is set; set it only in this small
# supplemental policy (stable GUID, so re-runs replace it). Mid-path wildcards (node_modules) need Windows 11:
# there AppLocker (per group) carries them; WDAC stays device-wide on the two roots.
$suppGuid = "{A6A0B11D-0000-4A67-8000-000000000018}"
$suppMarker = "C:\ProgramData\Antigravity\agy-wdac-supp.mode"
$suppWant = "$BuildRoot|$CacheRoot|$((Get-FileHash $PSCommandPath -Algorithm SHA256).Hash)"
if (-not (Test-Path $suppMarker) -or (Get-Content $suppMarker -Raw).Trim() -ne $suppWant) {
  $baseGuid = ([xml](Get-Content $wdacXml)).SiPolicy.PolicyID
  $supp = "C:\ProgramData\Antigravity\agy-wdac-supp.xml"
  $srules = New-Object System.Collections.Generic.List[object]
  foreach ($pth in "$BuildRoot\*", "$CacheRoot\*") { foreach ($r in (New-CIPolicyRule -FilePathRule $pth)) { $srules.Add($r) } }
  New-CIPolicy -Rules $srules.ToArray() -FilePath $supp -UserPEs -MultiplePolicyFormat | Out-Null
  Set-CIPolicyIdInfo -FilePath $supp -SupplementsBasePolicyID $baseGuid -PolicyName "AGY developer build roots" | Out-Null
  $sx = [xml](Get-Content $supp)
  $sx.SiPolicy.PolicyID = $suppGuid
  $rulesNode = $sx.SiPolicy.Rules
  # supplemental options: unsigned policy (else "signed policy required") + option 18; mode comes from the base
  foreach ($r in @($rulesNode.Rule)) { if ($r.Option -ne "Enabled:Unsigned System Integrity Policy") { [void]$rulesNode.RemoveChild($r) } }
  $opt = $sx.CreateElement("Rule", $sx.SiPolicy.NamespaceURI); $o = $sx.CreateElement("Option", $sx.SiPolicy.NamespaceURI)
  $o.InnerText = "Disabled:Runtime FilePath Rule Protection"; [void]$opt.AppendChild($o); [void]$rulesNode.AppendChild($opt)
  $sx.Save($supp)
  $scip = "C:\ProgramData\Antigravity\$suppGuid.cip"
  ConvertFrom-CIPolicy -XmlFilePath $supp -BinaryFilePath $scip | Out-Null
  Install-AgyCiPolicy $scip "WDAC supplemental policy"
  $suppWant | Set-Content $suppMarker -Encoding ascii
  Audit "WDAC supplemental $suppGuid (build roots $BuildRoot, $CacheRoot) applied to base $baseGuid"
}
Write-Host "app control applied (AppLocker enforced, WDAC $WdacMode + build-root supplemental)"
