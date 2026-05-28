<#
.SYNOPSIS
  Dump one host's live authorized_keys and diff it against the canonical set.

.DESCRIPTION
  Read-only. Pulls ~/.ssh/authorized_keys from a single host and compares the
  actual key material (the base64 key body, ignoring comments and options)
  against the canonical file, so you can spot drift before/without syncing:

    MISSING  - in canonical but not on the host (host is behind; needs sync)
    STALE    - on the host but not in canonical (a key sync would remove)
    OK       - present in both

.PARAMETER Host
  The ssh config host alias to audit.

.PARAMETER KeysFile
  Canonical authorized_keys. Defaults to the repo copy beside this script.

.EXAMPLE
  .\audit-host.ps1 <host-alias>
  .\audit-host.ps1 -Host <host-alias>
#>
param(
  [Parameter(Mandatory, Position = 0)]
  [Alias('Host')]
  [string] $Target,
  [string] $KeysFile = (Join-Path $PSScriptRoot 'canonical_authorized_keys')
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

if (-not (Test-Path $KeysFile)) { throw "Canonical key file not found: $KeysFile" }

# --- Canonical side ---------------------------------------------------------
$canon = @{}
Get-Content -Path $KeysFile | ForEach-Object {
  $r = Get-KeyRecord $_
  if ($r) { $canon[$r.Body] = $r }
}

# --- Remote side ------------------------------------------------------------
Write-Host "Fetching authorized_keys from $Target ..." -ForegroundColor Cyan
$remoteRaw = & ssh -o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=accept-new `
                   $Target 'cat ~/.ssh/authorized_keys 2>/dev/null' 2>&1
$code = $LASTEXITCODE
if ($code -ne 0) {
  throw "Could not read authorized_keys from ${Target}: $(( $remoteRaw | Out-String ).Trim())"
}

$remote = @{}
($remoteRaw -split "`n") | ForEach-Object {
  $r = Get-KeyRecord $_
  if ($r) { $remote[$r.Body] = $r }
}

# --- Diff -------------------------------------------------------------------
$rows = foreach ($body in (($canon.Keys + $remote.Keys) | Select-Object -Unique)) {
  $inCanon  = $canon.ContainsKey($body)
  $inRemote = $remote.ContainsKey($body)
  $status = if ($inCanon -and $inRemote) { 'OK' }
            elseif ($inCanon)            { 'MISSING' }   # canonical only
            else                         { 'STALE' }     # remote only
  $rec = if ($inCanon) { $canon[$body] } else { $remote[$body] }
  [pscustomobject]@{
    Status      = $status
    Type        = $rec.Type
    Comment     = if ($rec.Comment) { $rec.Comment } else { '(no comment)' }
    Fingerprint = $rec.Fingerprint
  }
}

Write-Host ""
$rows | Sort-Object @{e={ @('STALE','MISSING','OK').IndexOf($_.Status) }}, Comment |
        Format-Table Status, Type, Comment, Fingerprint -AutoSize

$missing = @($rows | Where-Object Status -eq 'MISSING').Count
$stale   = @($rows | Where-Object Status -eq 'STALE').Count
$ok      = @($rows | Where-Object Status -eq 'OK').Count

Write-Host ""
if ($stale -or $missing) {
  Write-Host "DRIFT: $ok in sync, $missing missing, $stale stale on $Target." -ForegroundColor Yellow
  if ($stale)   { Write-Host "  -> A sync would REMOVE $stale stale key(s)." -ForegroundColor Yellow }
  if ($missing) { Write-Host "  -> A sync would ADD $missing missing key(s)."  -ForegroundColor Yellow }
  Write-Host "  Run: .\sync-keys.ps1 -Only $Target" -ForegroundColor Cyan
} else {
  Write-Host "IN SYNC: $ok key(s), no drift on $Target." -ForegroundColor Green
}
