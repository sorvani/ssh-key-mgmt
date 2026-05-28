<#
.SYNOPSIS
  Audit live authorized_keys on one or many hosts against the canonical set.

.DESCRIPTION
  Read-only. For each selected host, pulls ~/.ssh/authorized_keys and diffs
  the key material (compared by SHA256 fingerprint, ignoring comments and
  options) against the canonical file:

    MISSING - in canonical but not on the host (host is behind; needs sync)
    STALE   - on the host but not in canonical (a sync would remove it)
    OK      - present in both

  Host selection mirrors sync-keys.ps1: positional / -Only and -Exclude take
  -like wildcards, -Jump selects a jump box plus everything behind it, and the
  same untracked skip-patterns.local list is honored. With no selection, every
  host in the ssh config (minus the skip-list) is audited.

  Output: a single selected host shows the full per-key table; multiple hosts
  show a one-line-per-host summary (use -Detailed to expand every host).

.PARAMETER Only
  Audit only host aliases matching these patterns (-like wildcards; an exact
  alias also works). Positional, so: .\audit-host.ps1 daerma-*

.PARAMETER Exclude
  Skip host aliases matching these patterns (in addition to the skip-list).

.PARAMETER Jump
  Audit every host that routes through these jump boxes (whose ProxyJump
  references them), plus the jump boxes themselves.

.PARAMETER Detailed
  Print the full per-key table for every host. Default: detailed only when a
  single host is selected; otherwise a per-host summary.

.PARAMETER KeysFile
  Canonical authorized_keys. Defaults to the repo copy beside this script.

.EXAMPLE
  .\audit-host.ps1 jump-daerma          # one host, full per-key table
  .\audit-host.ps1 daerma-*             # every daerma-named host, summary
  .\audit-host.ps1 -Jump jump-jj        # a jump box + everything behind it
  .\audit-host.ps1                      # the whole fleet
#>
param(
  [Parameter(Position = 0)]
  [string[]] $Only,
  [string[]] $Exclude,
  [string[]] $Jump,
  [switch]   $Detailed,
  [string]   $KeysFile  = (Join-Path $PSScriptRoot 'canonical_authorized_keys'),
  [string]   $SshConfig = "$HOME\.ssh\config",
  [string]   $SkipFile  = (Join-Path $PSScriptRoot 'skip-patterns.local')
)

$ErrorActionPreference = 'Stop'

# Standard SSH fingerprint: SHA256 of the raw key blob, base64 (no padding).
# Matches `ssh-keygen -lf`. Returned truncated for a compact, unique-enough id.
function Get-KeyFingerprint {
  param([string] $Body)
  try {
    $bytes = [Convert]::FromBase64String($Body)
    $hash  = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    return 'SHA256:' + [Convert]::ToBase64String($hash).TrimEnd('=').Substring(0, 16)
  } catch { return '(unparseable)' }
}

# Parse an authorized_keys line into a comparable record. Returns $null for
# blank/comment lines. Identity = the key body (2nd whitespace token of the
# key proper), which is stable regardless of comment or leading options.
function Get-KeyRecord {
  param([string] $Line)
  $t = $Line.Trim()
  if (-not $t -or $t.StartsWith('#')) { return $null }
  # Find "<type> <body>" anywhere in the line (skips any options prefix).
  $m = [regex]::Match(
    $t,
    '(?<type>ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-\S+|sk-(?:ssh-ed25519|ecdsa-sha2-\S+))\s+(?<body>[A-Za-z0-9+/]+={0,3})(?:\s+(?<comment>.*))?'
  )
  if (-not $m.Success) { return $null }
  [pscustomobject]@{
    Type        = $m.Groups['type'].Value
    Body        = $m.Groups['body'].Value
    Comment     = $m.Groups['comment'].Value.Trim()
    Fingerprint = Get-KeyFingerprint $m.Groups['body'].Value
  }
}

# --- Canonical side (load once) --------------------------------------------
if (-not (Test-Path $KeysFile)) { throw "Canonical key file not found: $KeysFile" }
$canon = @{}
Get-Content -Path $KeysFile | ForEach-Object {
  $r = Get-KeyRecord $_
  if ($r) { $canon[$r.Body] = $r }
}

# --- Skip-list (same untracked file as sync-keys.ps1) ----------------------
$SkipPatterns = @(
  if (Test-Path $SkipFile) {
    Get-Content -Path $SkipFile |
      ForEach-Object { ($_ -replace '#.*$', '').Trim() } |
      Where-Object { $_ }
  }
)

# --- Resolve hosts from ssh config (mirrors sync-keys.ps1) -----------------
$hostProxy = [ordered]@{}
$curHost = $null
foreach ($line in (Get-Content -Path $SshConfig)) {
  if ($line -match '^\s*Host\s+(?!\*)(\S+)\s*$') {
    $curHost = $Matches[1]
    if (-not $hostProxy.Contains($curHost)) { $hostProxy[$curHost] = $null }
  }
  elseif ($curHost -and $line -match '^\s*ProxyJump\s+(.+?)\s*$') {
    $hostProxy[$curHost] = $Matches[1]
  }
}
$hosts = @($hostProxy.Keys)

$hosts = $hosts | Where-Object {
  $name = $_
  -not ($SkipPatterns | Where-Object { $name -like $_ })
}

if ($Jump) {
  $behind = foreach ($name in $hosts) {
    $proxy = $hostProxy[$name]
    if (-not $proxy) { continue }
    $hops = $proxy -split ',' | ForEach-Object { (($_ -replace '.*@','') -replace ':.*','').Trim() }
    if ($hops | Where-Object { $Jump -contains $_ }) { $name }
  }
  $jumpSet = @($behind) + @($Jump) | Select-Object -Unique
  $hosts = $hosts | Where-Object { $jumpSet -contains $_ }
}

if ($Only)    { $hosts = $hosts | Where-Object { $n = $_;       $Only    | Where-Object { $n -like $_ } } }
if ($Exclude) { $hosts = $hosts | Where-Object { $n = $_; -not ($Exclude | Where-Object { $n -like $_ }) } }

$hosts = @($hosts)
if (-not $hosts) {
  Write-Host "No hosts matched the selection. Nothing to audit." -ForegroundColor Yellow
  return
}

$showDetail = $Detailed -or ($hosts.Count -eq 1)

# ssh writes to stderr for benign things too (e.g. the accept-new host-key
# warning on first contact). With 2>&1 capture, a script-wide 'Stop' would
# wrap that stderr in a terminating NativeCommandError and abort the loop, so
# we relax to 'Continue' here and rely on $LASTEXITCODE to judge each host.
$ErrorActionPreference = 'Continue'

# --- Audit each host --------------------------------------------------------
$results = foreach ($h in $hosts) {
  Write-Host ("Auditing {0,-22}" -f $h) -NoNewline
  $remoteRaw = & ssh -o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=accept-new `
                     $h 'cat ~/.ssh/authorized_keys 2>/dev/null || true' 2>&1
  $code = $LASTEXITCODE
  # Captured stderr arrives as ErrorRecord objects; .ToString() gives the raw
  # ssh line without PowerShell's NativeCommandError call-site decoration.
  $text = (@($remoteRaw | ForEach-Object { $_.ToString() }) -join ' ').Trim()

  if ($code -ne 0) {
    $status =
      if     ($text -match 'Permission denied|Authentication failed') { 'NO_KEY_AUTH' }
      elseif ($text -match 'Could not resolve|Connection timed out|No route to host|Connection refused|Operation timed out|timed out|Connection closed|reset by peer') { 'UNREACHABLE' }
      else   { 'ERROR' }
    Write-Host " $status" -ForegroundColor Red
    [pscustomobject]@{
      Host = $h; Status = $status; InSync = $null; Missing = $null; Stale = $null
      Detail = ($text -replace '\s+', ' '); Rows = @()
    }
    continue
  }

  # Connected: diff the host's keys against canonical.
  $remote = @{}
  ($remoteRaw -split "`n") | ForEach-Object {
    $r = Get-KeyRecord $_
    if ($r) { $remote[$r.Body] = $r }
  }
  $rows = foreach ($body in (($canon.Keys + $remote.Keys) | Select-Object -Unique)) {
    $inCanon  = $canon.ContainsKey($body)
    $inRemote = $remote.ContainsKey($body)
    $st = if ($inCanon -and $inRemote) { 'OK' } elseif ($inCanon) { 'MISSING' } else { 'STALE' }
    $rec = if ($inCanon) { $canon[$body] } else { $remote[$body] }
    [pscustomobject]@{
      Status      = $st
      Type        = $rec.Type
      Comment     = if ($rec.Comment) { $rec.Comment } else { '(no comment)' }
      Fingerprint = $rec.Fingerprint
    }
  }
  $ok      = @($rows | Where-Object Status -eq 'OK').Count
  $missing = @($rows | Where-Object Status -eq 'MISSING').Count
  $stale   = @($rows | Where-Object Status -eq 'STALE').Count
  $status  = if ($missing -or $stale) { 'DRIFT' } else { 'IN_SYNC' }
  Write-Host " $status" -ForegroundColor $(if ($status -eq 'IN_SYNC') { 'Green' } else { 'Yellow' })

  $rec = [pscustomobject]@{
    Host = $h; Status = $status; InSync = $ok; Missing = $missing; Stale = $stale
    Detail = ''; Rows = @($rows)
  }

  if ($showDetail) {
    Write-Host ""
    $rec.Rows | Sort-Object @{e={ @('STALE','MISSING','OK').IndexOf($_.Status) }}, Comment |
                Format-Table Status, Type, Comment, Fingerprint -AutoSize | Out-Host
  }
  $rec
}

# --- Summary ----------------------------------------------------------------
Write-Host ""
if (-not $showDetail) {
  $results | Format-Table Host, Status, InSync, Missing, Stale -AutoSize
}

$failed = $results | Where-Object Status -in 'NO_KEY_AUTH','UNREACHABLE','ERROR'
if ($failed) {
  Write-Host "Could not audit:" -ForegroundColor Red
  $failed | Format-Table Host, Status, Detail -AutoSize -Wrap
}

$drift = @($results | Where-Object Status -eq 'DRIFT')
$insync = @($results | Where-Object Status -eq 'IN_SYNC').Count
$totalStale   = ($results | Measure-Object -Property Stale   -Sum).Sum
$totalMissing = ($results | Measure-Object -Property Missing -Sum).Sum

Write-Host ""
Write-Host ("Audited {0} host(s): {1} in sync, {2} with drift, {3} unreachable/failed." -f `
  @($results).Count, $insync, $drift.Count, @($failed).Count) -ForegroundColor Cyan
if ($drift) {
  Write-Host ("Fleet drift: {0} stale key(s) a sync would remove, {1} missing key(s) it would add." -f `
    $totalStale, $totalMissing) -ForegroundColor Yellow
  $names = ($drift.Host) -join ','
  Write-Host "  Converge with: .\sync-keys.ps1 -Only $names" -ForegroundColor Cyan
} elseif (-not $failed) {
  Write-Host "No drift anywhere. Fleet matches canonical." -ForegroundColor Green
}

# NO_KEY_AUTH hosts are reachable but reject key auth -> first-time bootstrap
# over password (the Windows-friendly ssh-copy-id replacement).
$bootstrap = @($results | Where-Object Status -eq 'NO_KEY_AUTH')
if ($bootstrap) {
  Write-Host ("Needs bootstrap (password auth): {0}" -f (($bootstrap.Host) -join ', ')) -ForegroundColor Yellow
  Write-Host ("  Run: .\sync-keys.ps1 -Interactive -Only {0}" -f (($bootstrap.Host) -join ',')) -ForegroundColor Cyan
}
