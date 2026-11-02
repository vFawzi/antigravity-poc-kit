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

# AGY Windows egress policy (SSE / host-firewall stand-in; same intent as endpoint/files/nftables/agy_policy.nft).
# Personas (dev, contractor) may reach only their group's allowlisted FQDNs over HTTP(S); everything else from a
# persona is dropped. Windows Firewall evaluates block before allow, so "deny all but the allowlist" is built as
# per-user BLOCK rules over the complement of the allowlisted addresses. Runs as SYSTEM every minute (AGY-EgressSync).
# Operator sign-in window (seat mode): C:\ProgramData\Antigravity\signin-window.json {"until": <unix>, "ranges": [...]}.
$ErrorActionPreference = "Stop"
$Root = "C:\ProgramData\Antigravity"; $StateFile = "$Root\egress-state.json"; $WindowFile = "$Root\signin-window.json"
$Groups = @{ "dev" = @{ grp = "agy-dev"; ports = @(80, 443) }; "contractor" = @{ grp = "agy-contractor"; ports = @(443) } }
$TtlSeconds = 3600   # resolved addresses kept 1 h (CDN rotation), like the Linux sets

function Audit([string]$m, [string]$type = "Information") { Write-EventLog -LogName Application -Source "agy-mdm" -EventId 1001 -EntryType $type -Message $m }
. (Join-Path $PSScriptRoot "AGYConfig.ps1")   # settings: MDM registry > params.json > GCE metadata
function Get-AgyMeta([string]$k) { Get-AgyParam $k $null }
function ToUInt([string]$ip) { $b = ([Net.IPAddress]::Parse($ip)).GetAddressBytes(); [uint32]$b[0] * 16777216 + [uint32]$b[1] * 65536 + [uint32]$b[2] * 256 + [uint32]$b[3] }
function ToIp([uint64]$n) { "{0}.{1}.{2}.{3}" -f (($n -shr 24) -band 255), (($n -shr 16) -band 255), (($n -shr 8) -band 255), ($n -band 255) }
function CidrToRange([string]$c) {
  $ip, $len = $c.Split("/"); $len = [int]$len; $start = [uint64](ToUInt $ip)
  $size = [uint64][math]::Pow(2, 32 - $len); $start = $start - ($start % $size)
  return [pscustomobject]@{ S = $start; E = ($start + $size - 1) }
}
function NewRange([uint64]$s, [uint64]$e) { [pscustomobject]@{ S = $s; E = $e } }
function Complement($ranges) {
  # ranges: objects {S, E} (uint64). Objects, not nested arrays: the pipeline would unroll 2-element arrays.
  $sorted = @($ranges | Sort-Object -Property S); $out = New-Object System.Collections.Generic.List[string]; [uint64]$next = 0
  foreach ($r in $sorted) {
    if ($r.S -gt $next) { $out.Add("$(ToIp $next)-$(ToIp ($r.S - 1))") }
    if ($r.E + 1 -gt $next) { $next = $r.E + 1 }
  }
  if ($next -le 4294967295) { $out.Add("$(ToIp $next)-255.255.255.255") }
  return , $out
}
function PortComplement([int[]]$allowed) {
  $out = @(); $p = 1
  foreach ($a in ($allowed | Sort-Object)) { if ($a -gt $p) { $out += "$p-$($a - 1)" }; $p = $a + 1 }
  if ($p -le 65535) { $out += "$p-65535" }; return , $out
}
function Set-Rule([string]$name, [hashtable]$p) {
  $r = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
  if ($r) { Remove-NetFirewallRule -Name $name }
  New-NetFirewallRule -Name $name -DisplayName $name -Group "AGY egress" -Direction Outbound -Action Block -Enabled True @p | Out-Null
}

# ---------------------------------------------------------------- resolve the allowlist (+ keep entries for 1 h)
$raw = Get-AgyMeta "agy-egress-allowlist"   # Invoke-RestMethod may already have parsed the JSON
$allow = if ($raw -is [string]) { try { $raw | ConvertFrom-Json } catch { $null } } else { $raw }
if (-not $allow) { Write-Host "no egress allowlist in metadata - nothing to do"; exit 0 }
$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$state = if (Test-Path $StateFile) { try { Get-Content $StateFile -Raw -ErrorAction Stop | ConvertFrom-Json } catch { $null } } else { $null }
$win = if (Test-Path $WindowFile) { try { Get-Content $WindowFile -Raw -ErrorAction Stop | ConvertFrom-Json } catch { $null } } else { $null }
$winRanges = if ($win -and [int64]$win.until -gt $now) { @($win.ranges) } else { @() }
$newState = @{}; $sig = ""
foreach ($u in $Groups.Keys) {
  $g = $Groups[$u]; $known = @{}
  if ($state -and $state.($g.grp)) { foreach ($p in $state.($g.grp).PSObject.Properties) { if ([int64]$p.Value -gt $now - $TtlSeconds) { $known[$p.Name] = [int64]$p.Value } } }
  foreach ($h in @($allow.($g.grp))) {
    if ($h -notmatch '^[A-Za-z0-9.-]+$') { continue }
    try { Resolve-DnsName -Name $h -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.IPAddress } | ForEach-Object { $known[$_.IPAddress] = $now } } catch { }
  }
  $newState[$g.grp] = $known
  $allowedIps = @($known.Keys) + $winRanges
  $sig += "$u|$(($allowedIps | Sort-Object) -join ',')|$($g.ports -join ',');"
}
$newState | ConvertTo-Json -Depth 4 | Set-Content $StateFile -Encoding ascii
$sig += "script=" + (Get-FileHash $PSCommandPath -Algorithm SHA256).Hash   # logic change -> rebuild
$sig += ";personas=" + ((@((Get-AgyPersonaSids).Values) | ForEach-Object { $_ -join "," }) -join "|")   # group SIDs changed -> rebuild
$sigFile = "$Root\egress-sig.txt"; $old = if (Test-Path $sigFile) { (Get-Content $sigFile -Raw).Trim() } else { "" }
$missing = @(Get-NetFirewallRule -Group "AGY egress" -ErrorAction SilentlyContinue).Count -lt 11
if ($sig -ne $old -or $missing) {
  # rebuild all rules (cheap; only when the address set changed or a rule was removed)
  foreach ($u in $Groups.Keys) {
    # principals: the local persona account and (persona source = groups) the directory group SIDs - the firewall
    # matches -LocalUser against the logon token, which carries directory group SIDs (nested local groups don't work)
    $sids = @(); $lu = Get-LocalUser -Name $u -ErrorAction SilentlyContinue; if ($lu) { $sids += $lu.SID.Value }
    if ((Get-AgyPersonaSource) -eq "groups") { $sids += @((Get-AgyPersonaSids)[$u] | Where-Object { $_ -match '^S-1-(12-1|5-21)-' -and $_ -notin @((Get-LocalGroup -Name "AGY-Dev", "AGY-Contractor" -ErrorAction SilentlyContinue).SID.Value) }) }
    if (-not $sids) { continue }
    $g = $Groups[$u]; $sddl = "D:" + (($sids | Select-Object -Unique | ForEach-Object { "(A;;CC;;;$_)" }) -join "")
    $known = $newState[$g.grp]; $ranges = New-Object System.Collections.Generic.List[object]
    foreach ($ip in $known.Keys) { $n = [uint64](ToUInt $ip); $ranges.Add((NewRange $n $n)) }
    foreach ($c in $winRanges) { $ranges.Add((CidrToRange $c)) }
    $ranges.Add((NewRange (ToUInt "127.0.0.0") (ToUInt "127.255.255.255")))
    $allowedIps = @($known.Keys) + $winRanges
    Set-Rule "AGY-Egress-$u-NotAllowlisted" @{ RemoteAddress = (Complement $ranges); LocalUser = $sddl }
    Set-Rule "AGY-Egress-$u-Ports" @{ RemoteAddress = $(if ($allowedIps) { $allowedIps } else { "255.255.255.255" }); Protocol = "TCP"; RemotePort = (PortComplement $g.ports); LocalUser = $sddl }
    Set-Rule "AGY-Egress-$u-UDP" @{ Protocol = "UDP"; LocalUser = $sddl }
    Set-Rule "AGY-Egress-$u-ICMP" @{ Protocol = "ICMPv4"; LocalUser = $sddl }
    Set-Rule "AGY-Egress-$u-IPv6" @{ RemoteAddress = @("::/1", "8000::/1"); LocalUser = $sddl }
  }
  # ICMP echo is sent by the kernel without the caller's user context, so per-user ICMP rules never match:
  # block outbound echo requests machine-wide (no system service needs them on the workstation)
  Set-Rule "AGY-Egress-ICMP-Echo-All" @{ Protocol = "ICMPv4"; IcmpType = "8" }
  $sig | Set-Content $sigFile -Encoding ascii
  $cnt = ($newState.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
  Audit "egress allowlist synced: $cnt addresses$(if ($winRanges) { ", SIGNIN-WINDOW open ($($winRanges.Count) ranges)" })"
}
Write-Host "egress sync done"
