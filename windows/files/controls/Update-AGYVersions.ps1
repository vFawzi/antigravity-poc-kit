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

# AGY version management (called by Apply-AGYControls.ps1 as SYSTEM: every 5 min and at every logon).
# Brings the Antigravity CLI and Desktop app to the version the deployment policy selects from the support matrix
# (bundle\files\compat\agy-versions.json):
#   agy-version-policy = latest-tested (default: highest "supported" release) | pinned:<x.y.z> | latest (CLI manifest,
#                        if not blocked / below minimum; untested versions are reported by V84)
#   agy-artifact-base  = optional customer mirror (same object paths as storage.googleapis.com/antigravity-public/)
# Every binary is verified (sha512 / sha256 from the matrix or manifest + Authenticode signer Google LLC) before use.
# The swap happens only while the program is not running (in practice at the next logon); the previous version is
# kept (agy.exe.prev, Desktop.prev) and restored if the new one does not report the expected version.
# Self-update of both programs stays off: only this package changes versions (audit trail).
# Returns an object with the installed / target versions; writes versions-state.json for V84 and the SIEM.
param(
  [Parameter(Mandatory)][string]$Bundle,
  [string]$Root = "C:\ProgramData\Antigravity"
)
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "AGYConfig.ps1")

$PublicBase = "https://storage.googleapis.com/antigravity-public/"
$Dir = "C:\Program Files\Antigravity"; $CliExe = Join-Path $Dir "agy.exe"; $DeskDir = Join-Path $Dir "Desktop"
$Stage = Join-Path $Root "staging"
function Audit([string]$m, [string]$type = "Information") {
  Write-EventLog -LogName Application -Source "agy-mdm" -EventId 1000 -EntryType $type -Message $m -ErrorAction SilentlyContinue
}
function VKey([string]$v) { if ($v -match '^(\d+)\.(\d+)\.(\d+)') { [version]"$($Matches[1]).$($Matches[2]).$($Matches[3])" } else { $null } }

$policy = [string](Get-AgyParam "agy-version-policy" "latest-tested")
$mirror = [string](Get-AgyParam "agy-artifact-base" "")
$matrix = Get-Content (Join-Path $Bundle "compat\agy-versions.json") -Raw | ConvertFrom-Json

function Test-Allowed([string]$comp, [string]$plat, [string]$ver) {
  $v = VKey $ver; if (-not $v) { return $false }
  $min = $matrix.minimum.$comp.$plat
  if ($min -and $v -lt (VKey $min)) { return $false }
  -not @($matrix.releases | Where-Object { $_.component -eq $comp -and $_.platform -eq $plat -and $_.version -eq $ver -and $_.status -eq "blocked" }).Count
}

function Resolve-Target([string]$comp, [string]$plat) {
  $rel = @($matrix.releases | Where-Object { $_.component -eq $comp -and $_.platform -eq $plat -and $_.url })
  if ($policy -like "pinned:*") {
    $want = $policy.Substring(7)
    $hit = @($rel | Where-Object { $_.version -eq $want })
    if ($hit -and (Test-Allowed $comp $plat $want)) { return $hit[0] }
    return $null
  }
  if ($policy -eq "latest" -and $comp -eq "cli") {
    $m = $(try { Invoke-RestMethod (Get-AgyParam "agy-cli-manifest-url" "") -TimeoutSec 20 } catch { $null })
    if ($m -and $m.version -and $m.url -and $m.sha512 -and (Test-Allowed $comp $plat $m.version)) {
      return [pscustomobject]@{ version = $m.version; url = $m.url; sha512 = $m.sha512; status = "untested" }
    }
  }
  # latest-tested (also the fallback for 'latest' on the Desktop app, which has no public manifest)
  $ok = @($rel | Where-Object { $_.status -eq "supported" })
  if ($ok) { return ($ok | Sort-Object { VKey $_.version } -Descending | Select-Object -First 1) }
  return $null
}

function Get-Source([string]$url) {
  if (-not $url.StartsWith($PublicBase)) { throw "download URL outside $PublicBase : $url" }
  if ($mirror) { return $mirror.TrimEnd("/") + "/" + $url.Substring($PublicBase.Length) }
  $url
}

function Get-Verified([string]$url, [string]$out, [string]$algo, [string]$digest) {
  New-Item -ItemType Directory -Force -Path (Split-Path $out) | Out-Null
  & curl.exe -fsSL --retry 3 -o $out (Get-Source $url)
  if ($LASTEXITCODE -ne 0) { throw "download failed: $url" }
  $h = (Get-FileHash $out -Algorithm $algo).Hash.ToLower()
  if ($h -ne $digest.ToLower()) { Remove-Item $out -Force; throw "$algo mismatch for $url" }
  $sig = Get-AuthenticodeSignature $out
  if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "O=Google LLC") {
    Remove-Item $out -Force; throw "signature check failed for $url ($($sig.Status))"
  }
}

function Get-CliVersion {
  if (-not (Test-Path $CliExe)) { return "" }
  $fi = Get-Item $CliExe; $key = "$($fi.Length)|$($fi.LastWriteTimeUtc.Ticks)"
  $cache = $(try { Get-Content "$Root\cli-version.json" -Raw -ErrorAction Stop | ConvertFrom-Json } catch { $null })
  if ($cache -and $cache.key -eq $key) { return [string]$cache.version }
  $raw = ([string](& $CliExe --version 2>$null | Select-Object -First 1)).Trim()
  $v = if ($raw -match '(\d+\.\d+\.\d+)') { $Matches[1] } else { $raw }
  [IO.File]::WriteAllText("$Root\cli-version.json", (@{ key = $key; version = $v } | ConvertTo-Json -Compress))
  $v
}
function Get-DesktopVersion {
  # ProductVersion is 4-part (2.24.0.0); the matrix uses x.y.z
  $e = Join-Path $DeskDir "Antigravity.exe"
  if ((Test-Path $e) -and ((Get-Item $e).VersionInfo.ProductVersion -match '^(\d+\.\d+\.\d+)')) { $Matches[1] } else { "" }
}

# pending-state de-duplication: one audit event per pending target, not one every 5 minutes
$pendFile = "$Root\versions-pending.json"
$pend = $(try { Get-Content $pendFile -Raw -ErrorAction Stop | ConvertFrom-Json } catch { [pscustomobject]@{} })
function Set-Pending([string]$comp, [string]$ver, [string]$msg = "") {
  if ($pend.PSObject.Properties[$comp] -and $pend.$comp -eq $ver) { return }
  $pend | Add-Member -NotePropertyName $comp -NotePropertyValue $ver -Force
  if (-not $msg) { $msg = "AGY_$($comp.ToUpper())_UPGRADE_PENDING: $ver staged, applied when the program is not running (next logon)" }
  Audit $msg $(if ($msg -match "NO_TARGET") { "Warning" } else { "Information" })
}
function Clear-Pending([string]$comp) { if ($pend.PSObject.Properties[$comp]) { $pend.PSObject.Properties.Remove($comp) } }

$Managed = @{ cli = $false; desktop = $false }   # set when this run swapped the binary
$result = [ordered]@{ policy = $policy; mirror = [bool]$mirror; cli = ""; cli_target = ""; cli_target_status = "";
                      desktop = ""; desktop_target = ""; desktop_target_status = ""; errors = @() }

# ---------------------------------------------------------------- CLI
try {
  $cur = Get-CliVersion; $t = Resolve-Target "cli" "windows_amd64"
  $result.cli = $cur
  if ($t) {
    $result.cli_target = $t.version; $result.cli_target_status = $t.status
    if ($cur -ne $t.version) {
      $staged = Join-Path $Stage "agy-$($t.version).exe"
      if (-not (Test-Path $staged) -or (Get-FileHash $staged -Algorithm SHA512).Hash.ToLower() -ne $t.sha512.ToLower()) {
        Get-Verified $t.url $staged "SHA512" $t.sha512
      }
      if (Get-Process -Name agy -ErrorAction SilentlyContinue) {
        Set-Pending "cli" $t.version
      } else {
        if (Test-Path $CliExe) { Move-Item $CliExe "$CliExe.prev" -Force }
        Copy-Item $staged $CliExe -Force
        $now = Get-CliVersion
        if ($now -ne $t.version) {
          if (Test-Path "$CliExe.prev") { Move-Item "$CliExe.prev" $CliExe -Force }
          throw "new CLI reports '$now', expected $($t.version) - rolled back to $cur"
        }
        Remove-Item $staged -Force
        Clear-Pending "cli"; $result.cli = $now; $Managed.cli = $true
        Audit "AGY_CLI_UPGRADED: $cur -> $now (policy $policy, $($t.status))"
      }
    }
  } elseif ($cur) {
    Set-Pending "cli_no_target" $policy "AGY_CLI_NO_TARGET: policy $policy selects no deployable CLI release for windows_amd64 - keeping $cur"
  }
} catch { $result.errors += "cli: $($_.Exception.Message)"; Audit "AGY_CLI_UPGRADE_FAILED: $($_.Exception.Message)" "Warning" }

# ---------------------------------------------------------------- Desktop app
try {
  $cur = Get-DesktopVersion; $t = Resolve-Target "desktop" "windows_x64"
  $result.desktop = $cur
  if ($t -and $cur) {   # first install is done by the installer / image; this keeps it on the target version
    $result.desktop_target = $t.version; $result.desktop_target_status = $t.status
    if ($cur -ne $t.version) {
      $inst = Join-Path $Stage "Antigravity-$($t.version)-x64.exe"
      if (-not (Test-Path $inst) -or (Get-FileHash $inst -Algorithm SHA256).Hash.ToLower() -ne $t.sha256.ToLower()) {
        Get-Verified $t.url $inst "SHA256" $t.sha256
      }
      if (Get-Process -Name Antigravity -ErrorAction SilentlyContinue) {
        Set-Pending "desktop" $t.version
      } else {
        # official per-user installer, run as SYSTEM with an explicit target (/D=, must be last): without it the
        # installer installs nowhere under SYSTEM (seen on Windows 11 / SCCM context); then swapped in, read-only for users
        $new = "$DeskDir.new"
        if (Test-Path $new) { Remove-Item $new -Recurse -Force }
        Start-Process $inst -ArgumentList "/S", "/D=$new" -Wait
        if (-not (Test-Path (Join-Path $new "Antigravity.exe"))) { throw "Desktop app not found after install ($new)" }
        if (Test-Path "$DeskDir.prev") { Remove-Item "$DeskDir.prev" -Recurse -Force }
        Rename-Item $DeskDir "$DeskDir.prev"; Rename-Item $new $DeskDir
        & icacls $DeskDir /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" /q | Out-Null
        $now = Get-DesktopVersion
        if ($now -ne $t.version) {
          Remove-Item $DeskDir -Recurse -Force; Rename-Item "$DeskDir.prev" $DeskDir
          throw "new Desktop app reports '$now', expected $($t.version) - rolled back to $cur"
        }
        Remove-Item $inst -Force
        Clear-Pending "desktop"; $result.desktop = $now; $Managed.desktop = $true
        Audit "AGY_DESKTOP_UPGRADED: $cur -> $now (policy $policy)"
      }
    }
  }
  # the Desktop app's own updater stays off: without app-update.yml electron-updater does not check or download
  $feed = Join-Path $DeskDir "resources\app-update.yml"
  if (Test-Path $feed) { Move-Item $feed "$feed.disabled" -Force; Audit "AGY_DESKTOP_AUTOUPDATE disabled (app-update.yml)" }
  # per-user installers it may have downloaded earlier (they can't run: AppLocker) - remove them
  Get-ChildItem "C:\Users\*\AppData\Local\antigravity-updater\pending" -Directory -ErrorAction SilentlyContinue |
    ForEach-Object { Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
} catch { $result.errors += "desktop: $($_.Exception.Message)"; Audit "AGY_DESKTOP_UPGRADE_FAILED: $($_.Exception.Message)" "Warning" }

[IO.File]::WriteAllText($pendFile, ($pend | ConvertTo-Json -Compress))
# unmanaged change: the binary changed (size / write time) without an upgrade by this script -> SIEM (D21)
function FileKey([string]$p) { if (Test-Path $p) { $f = Get-Item $p; "$($f.Length)|$($f.LastWriteTimeUtc.Ticks)" } else { "" } }
$prev = $(try { Get-Content "$Root\versions-state.json" -Raw -ErrorAction Stop | ConvertFrom-Json } catch { $null })
$result.cli_key = FileKey $CliExe
$result.desktop_key = FileKey (Join-Path $DeskDir "Antigravity.exe")
foreach ($c in "cli", "desktop") {
  $was = if ($prev) { [string]$prev.("${c}_key") } else { "" }
  if ($was -and $result."${c}_key" -and $was -ne $result."${c}_key" -and -not $Managed[$c]) {
    Audit "AGY_$($c.ToUpper())_UNMANAGED_CHANGE: binary changed outside version management (was $($prev.$c), now $($result.$c))" "Warning"
  }
}
$state = [pscustomobject]$result
[IO.File]::WriteAllText("$Root\versions-state.json", ($state | ConvertTo-Json -Compress))
# one event per change of the version picture (installed / target / policy) -> fleet view v_agy_versions
$sig = "cli=$($result.cli) cli_target=$($result.cli_target) desktop=$($result.desktop) desktop_target=$($result.desktop_target) policy=$policy"
$oldSig = if ($prev) { "cli=$($prev.cli) cli_target=$($prev.cli_target) desktop=$($prev.desktop) desktop_target=$($prev.desktop_target) policy=$($prev.policy)" } else { "" }
$last = if ($prev -and $prev.reported_at) { [datetime]::Parse($prev.reported_at).ToUniversalTime() } else { [datetime]::MinValue }
if ($sig -ne $oldSig -or $last -lt (Get-Date).ToUniversalTime().AddHours(-24)) {   # on change + daily heartbeat
  Audit "AGY_VERSIONS: $sig package=$($matrix.package)"
  $state | Add-Member -NotePropertyName reported_at -NotePropertyValue (Get-Date).ToUniversalTime().ToString("o") -Force
} elseif ($prev -and $prev.reported_at) { $state | Add-Member -NotePropertyName reported_at -NotePropertyValue $prev.reported_at -Force }
[IO.File]::WriteAllText("$Root\versions-state.json", ($state | ConvertTo-Json -Compress))
$state
