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

# AGY device settings source (dot-source this file). One lookup, three sources, first hit wins:
#   1. HKLM\SOFTWARE\Policies\AGY  (value name = setting name; set by Intune / GPO / ConfigMgr - production)
#   2. C:\ProgramData\Antigravity\params.json  (offline installer / any non-Google-Cloud device)
#   3. GCE instance metadata attributes  (Google Cloud reference VMs, written by Terraform)
# Setting names are the metadata attribute names (agy-egress-allowlist, agy-hosts-pin, agy-wdac-mode, ...).
# Complex values (allowlists, maps) are JSON strings in the registry / metadata, objects or strings in params.json.

$script:AgyParamsFile = "C:\ProgramData\Antigravity\params.json"
$script:AgyPolicyKey = "HKLM:\SOFTWARE\Policies\AGY"
$script:AgyOnGce = $null
$script:AgyParams = $null

function Test-AgyOnGce {
  if ($null -eq $script:AgyOnGce) {
    $script:AgyOnGce = $(try { [bool]([System.Net.Dns]::GetHostAddresses("metadata.google.internal")) } catch { $false })
  }
  $script:AgyOnGce
}

# Module markers (device packages): HKLM\SOFTWARE\Policies\AGY\Modules\<module> = "<version>|<policy hash>", written by
# each SCCM / script package. No Modules key = classic install (Google Cloud VM, offline bundle): every module is on.
function Test-AgyModule([string]$Id) {
  $k = "$script:AgyPolicyKey\Modules"
  if (-not (Test-Path $k)) { return $true }
  return ("" + (Get-Item $k).GetValue($Id, "")) -ne ""
}

# Device proof the credential proxy adds: agy-device-auth = auto (Compute Engine identity on Google Cloud, device
# certificate elsewhere) | cert (always the device certificate, e.g. a certificate-only gateway) | gce
function Get-AgyDeviceAuth {
  $m = [string](Get-AgyParam "agy-device-auth" "auto")
  if ($m -in "cert", "gce") { return $m }
  if (Test-AgyOnGce) { "gce" } else { "cert" }
}
function Get-AgyParam([string]$Name, $Default = $null) {
  # 1. MDM policy (registry)
  if (Test-Path $script:AgyPolicyKey) {
    $v = (Get-Item $script:AgyPolicyKey).GetValue($Name, $null)
    if ($null -ne $v -and "$v" -ne "") { return $v }
  }
  # 2. local params file (admin-owned, read-only for users)
  if ($null -eq $script:AgyParams) {
    $script:AgyParams = if (Test-Path $script:AgyParamsFile) {
      $(try { Get-Content $script:AgyParamsFile -Raw -ErrorAction Stop | ConvertFrom-Json } catch { [pscustomobject]@{} })
    } else { [pscustomobject]@{} }
  }
  $p = $script:AgyParams.PSObject.Properties[$Name]
  if ($p -and $null -ne $p.Value -and "$($p.Value)" -ne "") {
    $v = $p.Value
    if ($v -is [array] -and -not ($v | Where-Object { $_ -is [psobject] -and $_ -isnot [string] -and $_.PSObject.Properties.Count })) { return ($v -join ",") }
    return $v
  }
  # 3. GCE metadata (Google Cloud VMs only; skipped quickly elsewhere)
  if (Test-AgyOnGce) {
    $v = $(try { Invoke-RestMethod -Headers @{ "Metadata-Flavor" = "Google" } -TimeoutSec 5 `
                   -Uri "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$Name" } catch { $null })
    if ($null -ne $v -and "$v" -ne "") { return $v }
  }
  return $Default
}

# ---------------------------------------------------------------- personas: local accounts or directory groups
#   agy-persona-source = local  (default): local accounts dev / contractor in the local groups AGY-Dev / AGY-Contractor
#                        groups : the developers' own (Entra ID / AD) accounts; the persona comes from directory groups
#   agy-persona-groups = {"agy-dev": ["S-1-12-1-..."], "agy-contractor": ["S-1-12-1-..."]}  (group SIDs, set by SCCM)
# Windows evaluates Entra group SIDs only inside the built-in local groups, so a directory group nested into AGY-Dev is
# NOT in the user's token: controls target the directory group SIDs directly (plus the local group, for local personas).
$script:AgyPersonaKeys = [ordered]@{ "dev" = @{ grp = "agy-dev"; local = "AGY-Dev" }; "contractor" = @{ grp = "agy-contractor"; local = "AGY-Contractor" } }
$script:AgyProfileState = "C:\ProgramData\Antigravity\persona-profiles.json"   # SID -> persona seen at logon (admin-only)

function Get-AgyPersonaSource { $s = [string](Get-AgyParam "agy-persona-source" "local"); if ($s -eq "groups") { "groups" } else { "local" } }

function Get-AgyPersonaSids {
  # persona key (dev / contractor) -> SIDs whose members are that persona
  $cfg = Get-AgyParam "agy-persona-groups" $null
  if ($cfg -is [string]) { $cfg = $(try { $cfg | ConvertFrom-Json } catch { $null }) }
  $out = [ordered]@{}
  foreach ($k in $script:AgyPersonaKeys.Keys) {
    $p = $script:AgyPersonaKeys[$k]; $sids = @()
    $lg = Get-LocalGroup -Name $p.local -ErrorAction SilentlyContinue
    if ($lg) { $sids += $lg.SID.Value }
    if ((Get-AgyPersonaSource) -eq "groups" -and $cfg -and $cfg.PSObject.Properties[$p.grp]) {
      $sids += @($cfg.($p.grp) | Where-Object { $_ -match '^S-1-(12-1|5-21)-[0-9-]+$' })
    }
    $out[$k] = @($sids | Select-Object -Unique)
  }
  $out
}

if (-not ("AgyWts" -as [type])) {
  Add-Type -TypeDefinition @"
using System; using System.Collections.Generic; using System.Runtime.InteropServices; using System.Security.Principal;
public static class AgyWts {
  [DllImport("wtsapi32.dll", SetLastError = true)] static extern bool WTSEnumerateSessions(IntPtr h, int r, int v, out IntPtr p, out int c);
  [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr p);
  [DllImport("wtsapi32.dll", SetLastError = true)] static extern bool WTSQueryUserToken(int s, out IntPtr t);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [StructLayout(LayoutKind.Sequential)] struct SI { public int Id; public IntPtr Name; public int State; }
  // signed-in users (SYSTEM only): "sid|domain\\user|group-sid,group-sid,..." per session
  public static List<string> Users() {
    var res = new List<string>(); IntPtr p; int c;
    if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out p, out c)) return res;
    int sz = Marshal.SizeOf(typeof(SI));
    for (int i = 0; i < c; i++) {
      var si = (SI)Marshal.PtrToStructure(new IntPtr(p.ToInt64() + i * sz), typeof(SI));
      IntPtr t; if (!WTSQueryUserToken(si.Id, out t)) continue;
      try { using (var id = new WindowsIdentity(t)) {
        var g = new List<string>(); foreach (var x in id.Groups) g.Add(x.Value);
        res.Add(id.User.Value + "|" + id.Name + "|" + string.Join(",", g)); } }
      finally { CloseHandle(t); }
    }
    WTSFreeMemory(p); return res;
  }
}
"@
}

function Get-AgyPersonaProfiles {
  # persona accounts with a profile on this device: Name (%USERNAME%), Sid, Home, Persona (dev / contractor), Group
  $list = @()
  if ((Get-AgyPersonaSource) -eq "local") {
    # local accounts in AGY-Dev / AGY-Contractor: the dev / contractor accounts of the reference workstations, or
    # accounts added through agy-persona-members (e.g. Google Credential Provider for Windows accounts on a
    # Google-only customer: Windows creates a local account per Google user). Contractor wins if in both.
    Sync-AgyPersonaMembers
    $byPersona = [ordered]@{}
    foreach ($k in "dev", "contractor") {
      foreach ($m in @(Get-LocalGroupMember -Group $script:AgyPersonaKeys[$k].local -ErrorAction SilentlyContinue | Where-Object { $_.PrincipalSource -eq "Local" -and $_.ObjectClass -eq "User" })) {
        $byPersona[$m.SID.Value] = @{ k = $k; name = ($m.Name -split "\\")[-1] }
      }
    }
    foreach ($sid in $byPersona.Keys) {
      $home_ = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -ErrorAction SilentlyContinue).ProfileImagePath
      if ($home_ -and (Test-Path $home_)) {
        $k = $byPersona[$sid].k
        $list += [pscustomobject]@{ Name = $byPersona[$sid].name; Sid = $sid; Home = $home_; Persona = $k; Group = $script:AgyPersonaKeys[$k].grp }
      }
    }
    return $list
  }
  # groups: personas seen in the session token of signed-in users (contractor wins if both match), remembered per SID
  $seen = $(try { Get-Content $script:AgyProfileState -Raw -ErrorAction Stop | ConvertFrom-Json } catch { [pscustomobject]@{} })
  $map = Get-AgyPersonaSids
  foreach ($line in [AgyWts]::Users()) {
    $sid, $name, $groups = $line -split "\|", 3; $gs = $groups -split ","
    $persona = if (@($map["contractor"] | Where-Object { $gs -contains $_ }).Count) { "contractor" } elseif (@($map["dev"] | Where-Object { $gs -contains $_ }).Count) { "dev" } else { "" }
    if ($persona) { $seen | Add-Member -NotePropertyName $sid -NotePropertyValue ([pscustomobject]@{ persona = $persona; name = ($name -split "\\")[-1] }) -Force }
    elseif ($seen.PSObject.Properties[$sid]) { $seen.PSObject.Properties.Remove($sid) }   # left the groups: no longer managed
  }
  # directory accounts mapped through the local AGY-Dev / AGY-Contractor groups are personas even before their first
  # interactive session is seen (e.g. the device owner added by the installer): their settings are managed right away
  foreach ($k in "dev", "contractor") {
    foreach ($m in @(Get-LocalGroupMember -Group $script:AgyPersonaKeys[$k].local -ErrorAction SilentlyContinue | Where-Object { $_.ObjectClass -eq "User" })) {
      $msid = $m.SID.Value
      if ($k -eq "dev" -and $seen.PSObject.Properties[$msid] -and $seen.$msid.persona -eq "contractor") { continue }   # contractor wins
      $seen | Add-Member -NotePropertyName $msid -NotePropertyValue ([pscustomobject]@{ persona = $k; name = ($m.Name -split "\\")[-1] }) -Force
    }
  }
  New-Item -ItemType Directory -Force -Path (Split-Path $script:AgyProfileState) | Out-Null
  [IO.File]::WriteAllText($script:AgyProfileState, ($seen | ConvertTo-Json -Compress))
  foreach ($pr in $seen.PSObject.Properties) {
    $home_ = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($pr.Name)" -ErrorAction SilentlyContinue).ProfileImagePath
    if ($home_ -and (Test-Path $home_)) {
      $list += [pscustomobject]@{ Name = $pr.Value.name; Sid = $pr.Name; Home = $home_; Persona = $pr.Value.persona; Group = $script:AgyPersonaKeys[$pr.Value.persona].grp }
    }
  }
  $list
}

function Write-AgyPersonaGroupsFile {
  # for the hook (runs as the persona): which group SIDs mean which persona (admin-only write, users read)
  $map = Get-AgyPersonaSids; $f = "C:\ProgramData\Antigravity\persona-groups.json"
  $json = (@{ "agy-dev" = @($map["dev"]); "agy-contractor" = @($map["contractor"]) } | ConvertTo-Json -Compress)
  if (-not (Test-Path $f) -or [IO.File]::ReadAllText($f) -ne $json) { [IO.File]::WriteAllText($f, $json) }
}

function Sync-AgyPersonaMembers {
  # agy-persona-members = {"agy-dev": ["alice", "bob"], "agy-contractor": ["carol"]}  (local account names, set by MDM
  # or params.json). Adds them to the local persona groups (and removes them from the other one); accounts that don't
  # exist yet (Google sign-in creates them at first logon) are added on a later run. Never adds administrators.
  $cfg = Get-AgyParam "agy-persona-members" $null
  if ($cfg -is [string]) { $cfg = $(try { $cfg | ConvertFrom-Json } catch { $null }) }
  if (-not $cfg) { return }
  $admins = @(Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction SilentlyContinue | ForEach-Object { ($_.Name -split "\\")[-1] })
  foreach ($k in "dev", "contractor") {
    $grp = $script:AgyPersonaKeys[$k].local; $other = $script:AgyPersonaKeys[$(if ($k -eq "dev") { "contractor" } else { "dev" })].local
    foreach ($n in @($cfg.($script:AgyPersonaKeys[$k].grp))) {
      if ($n -notmatch '^[A-Za-z0-9._-]{1,64}$' -or $admins -contains $n) { continue }
      if (-not (Get-LocalUser -Name $n -ErrorAction SilentlyContinue)) { continue }
      if (-not (Get-LocalGroupMember -Group $grp -Member $n -ErrorAction SilentlyContinue)) { Add-LocalGroupMember -Group $grp -Member $n }
      if ($k -eq "contractor" -and (Get-LocalGroupMember -Group $other -Member $n -ErrorAction SilentlyContinue)) { Remove-LocalGroupMember -Group $other -Member $n }
    }
  }
}

function Get-AgyKnownProfiles {
  # read-only view for validation (no token scan, no state change): local persona members + remembered directory users
  $out = @()
  foreach ($k in "dev", "contractor") {
    foreach ($m in @(Get-LocalGroupMember -Group $script:AgyPersonaKeys[$k].local -ErrorAction SilentlyContinue | Where-Object { $_.ObjectClass -eq "User" })) {
      $h = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($m.SID.Value)" -ErrorAction SilentlyContinue).ProfileImagePath
      if ($h) { $out += [pscustomobject]@{ Name = ($m.Name -split "\\")[-1]; Sid = $m.SID.Value; Home = $h; Persona = $k } }
    }
  }
  $seen = $(try { Get-Content $script:AgyProfileState -Raw -ErrorAction Stop | ConvertFrom-Json } catch { $null })
  if ($seen) {
    foreach ($pr in $seen.PSObject.Properties) {
      if ($out.Sid -contains $pr.Name) { continue }
      $h = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($pr.Name)" -ErrorAction SilentlyContinue).ProfileImagePath
      if ($h) { $out += [pscustomobject]@{ Name = $pr.Value.name; Sid = $pr.Name; Home = $h; Persona = $pr.Value.persona } }
    }
  }
  $out
}
