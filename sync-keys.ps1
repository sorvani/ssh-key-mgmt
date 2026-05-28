<#
.SYNOPSIS
  Declaratively sync your canonical SSH public keys to every managed host.

.DESCRIPTION
  Every push REPLACES the remote ~/.ssh/authorized_keys with the exact
  contents of the canonical file. Stale keys cannot accumulate: to retire a
  key, delete its line from the canonical file and re-sync.

  Transport is base64-over-SSH-argument (not stdin piping), which sidesteps
  all Windows CRLF / console-encoding mangling. The remote write is atomic
  (write .new, verify it contains >=1 valid key, then mv over the live file),
  so a dropped connection or empty transfer can never lock you out.

.PARAMETER KeysFile
  Path to the canonical authorized_keys. Defaults to the copy that lives
  alongside this script in the repo.

.PARAMETER SshConfig
  Path to the ssh config to parse hosts from. Defaults to ~/.ssh/config.

.PARAMETER Only
  Sync only these host aliases (exact match).

.PARAMETER Exclude
  Skip these host aliases (in addition to the built-in skip-list).

.PARAMETER DryRun
  Print the resolved target list and exit without contacting any host.

.PARAMETER Only
  Sync only host aliases matching these patterns. Supports -like wildcards
  (e.g. 'daerma-*'); an exact alias also works. Applied as a narrowing filter.

.PARAMETER Exclude
  Skip host aliases matching these patterns (in addition to the skip-list).
  Supports -like wildcards.

.PARAMETER Jump
  Sync every host that routes through these jump boxes (i.e. whose ProxyJump
  references them), PLUS the jump boxes themselves. Combine with -Exclude to
  drop the jump box, or with -Only to further narrow within the group.

.PARAMETER DryRun
  Print the resolved target list and exit without contacting any host.

.PARAMETER Interactive
  Allow password prompts (BatchMode=no) for first-time bootstrap on hosts
  that still accept password auth. Default is BatchMode=yes (fail fast).

.EXAMPLE
  .\sync-keys.ps1 -DryRun
  .\sync-keys.ps1
  .\sync-keys.ps1 -Only <client>-*            # all hosts named <client>-...
  .\sync-keys.ps1 -Jump <jump-box>            # the jump box + everything behind it
  .\sync-keys.ps1 -Jump <jump-box> -Exclude <jump-box>   # only what's behind it
#>
param(
  [string]   $KeysFile  = (Join-Path $PSScriptRoot 'canonical_authorized_keys'),
  [string]   $SshConfig = "$HOME\.ssh\config",
  [string]   $SkipFile  = (Join-Path $PSScriptRoot 'skip-patterns.local'),
  [string[]] $Only,
  [string[]] $Exclude,
  [string[]] $Jump,
  [switch]   $DryRun,
  [switch]   $Interactive
)

$ErrorActionPreference = 'Stop'

# --- Hosts that are NOT standard POSIX/OpenSSH authorized_keys targets ------
# Wildcard (-like) patterns are loaded from an UNTRACKED local file
# (skip-patterns.local) so real host aliases never enter git history.
# One pattern per line; '#' comments and blank lines ignored. If the file is
# absent, nothing is skipped (see skip-patterns.example for the format).
$SkipPatterns = @(
  if (Test-Path $SkipFile) {
    Get-Content -Path $SkipFile |
      ForEach-Object { ($_ -replace '#.*$', '').Trim() } |
      Where-Object { $_ }
  } else {
    Write-Host "Note: no skip-list found at $SkipFile - no hosts will be skipped." -ForegroundColor DarkYellow
  }
)

# --- Load + normalize the canonical key file -------------------------------
if (-not (Test-Path $KeysFile)) {
  throw "Canonical key file not found: $KeysFile"
}
$raw = Get-Content -Path $KeysFile -Raw
# Force LF endings and a trailing newline; the file is then encoded as
# UTF-8 (no BOM) and base64'd, so what lands on the remote is byte-exact.
$normalized = ($raw -replace "`r`n", "`n") -replace "`r", "`n"
if (-not $normalized.EndsWith("`n")) { $normalized += "`n" }

# Sanity: refuse to run if the canonical file itself has no valid key line.
$keyLineRegex = '^(ssh-(ed25519|rsa|dss)|ecdsa-sha2-\S+|sk-(ssh-ed25519|ecdsa-sha2-\S+))\s'
$localKeyCount = ($normalized -split "`n" | Where-Object { $_ -match $keyLineRegex }).Count
if ($localKeyCount -lt 1) {
  throw "Canonical file contains no valid public key lines: $KeysFile"
}

$bytes = [System.Text.Encoding]::UTF8.GetBytes($normalized)   # no BOM
$b64   = [Convert]::ToBase64String($bytes)

# --- Build the remote command (single line; base64 carried as an arg) ------
# Atomic + guarded: only mv if the decoded .new file has >=1 real key line.
$remoteCmd = @(
  'umask 077'
  'mkdir -p ~/.ssh'
  'chmod 700 ~/.ssh'
  "printf '%s' '$b64' | base64 -d > ~/.ssh/authorized_keys.new"
  "grep -Eq '^(ssh-(ed25519|rsa|dss)|ecdsa-sha2-|sk-)' ~/.ssh/authorized_keys.new || { echo 'REFUSED: transfer had no valid keys' >&2; rm -f ~/.ssh/authorized_keys.new; exit 3; }"
  'chmod 600 ~/.ssh/authorized_keys.new'
  'mv ~/.ssh/authorized_keys.new ~/.ssh/authorized_keys'
) -join ' && '

# --- Parse ssh config into (Host -> ProxyJump) so we can resolve -Jump ------
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
$hosts = @($hostProxy.Keys)            # already deduped (a host may appear twice)

# Built-in skip-list
$hosts = $hosts | Where-Object {
  $name = $_
  -not ($SkipPatterns | Where-Object { $name -like $_ })
}

# -Jump: hosts whose ProxyJump routes through any named jump box, + the jump
# boxes themselves. ProxyJump values may be 'user@host:port' or a 'a,b' chain.
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

# -Only / -Exclude: wildcard (-like) patterns; exact names also match.
if ($Only)    { $hosts = $hosts | Where-Object { $n = $_;       $Only    | Where-Object { $n -like $_ } } }
if ($Exclude) { $hosts = $hosts | Where-Object { $n = $_; -not ($Exclude | Where-Object { $n -like $_ }) } }

if (-not $hosts) {
  Write-Host "No target hosts after filtering. Nothing to do." -ForegroundColor Yellow
  return
}

# --- Dry run ----------------------------------------------------------------
if ($DryRun) {
  Write-Host "Canonical: $KeysFile  ($localKeyCount key(s))" -ForegroundColor Cyan
  Write-Host "Would sync $($hosts.Count) host(s):" -ForegroundColor Cyan
  $hosts | ForEach-Object { Write-Host "  $_" }
  return
}

# --- Sync -------------------------------------------------------------------
$batchFlag = if ($Interactive) { 'BatchMode=no' } else { 'BatchMode=yes' }
$sshOpts = @(
  '-o', 'ConnectTimeout=10'
  '-o', $batchFlag
  '-o', 'StrictHostKeyChecking=accept-new'
)

# ssh writes to stderr for benign things too (e.g. the accept-new host-key
# warning on first contact). With 2>&1 capture, a script-wide 'Stop' would
# wrap that stderr in a terminating NativeCommandError and abort the loop, so
# we relax to 'Continue' here and rely on $LASTEXITCODE to judge each host.
$ErrorActionPreference = 'Continue'

$results = foreach ($h in $hosts) {
  Write-Host ("Syncing {0,-22}" -f $h) -NoNewline
  $output = & ssh @sshOpts $h $remoteCmd 2>&1
  $code   = $LASTEXITCODE
  # Captured stderr arrives as ErrorRecord objects; .ToString() gives the raw
  # ssh line without PowerShell's NativeCommandError call-site decoration.
  $text   = (@($output | ForEach-Object { $_.ToString() }) -join ' ').Trim()

  $status =
    if     ($code -eq 0)                                   { 'OK' }
    elseif ($code -eq 3)                                   { 'REFUSED_EMPTY' }
    elseif ($text -match 'Permission denied|Authentication failed') { 'NO_KEY_AUTH' }
    elseif ($text -match 'Could not resolve|Connection timed out|No route to host|Connection refused|Operation timed out|timed out') { 'UNREACHABLE' }
    elseif ($code -eq 127)                                 { 'NO_BASE64' }
    else                                                   { 'ERROR' }

  $color = switch ($status) {
    'OK'          { 'Green' }
    'NO_KEY_AUTH' { 'Yellow' }
    default       { 'Red' }
  }
  Write-Host " $status" -ForegroundColor $color

  [pscustomobject]@{
    Host   = $h
    Status = $status
    Detail = if ($status -in 'OK','NO_KEY_AUTH') { '' } else { ($text -replace '\s+', ' ') }
  }
}

# --- Report -----------------------------------------------------------------
Write-Host ""
$results | Format-Table Host, Status -AutoSize

$ok = @($results | Where-Object Status -eq 'OK').Count
Write-Host "$ok/$($results.Count) host(s) synced OK." -ForegroundColor Cyan

$failed = $results | Where-Object { $_.Status -notin 'OK','NO_KEY_AUTH' }
if ($failed) {
  Write-Host "`nFailures (see detail):" -ForegroundColor Red
  $failed | Format-Table Host, Status, Detail -AutoSize -Wrap
}

$needsBootstrap = $results | Where-Object Status -eq 'NO_KEY_AUTH'
if ($needsBootstrap) {
  Write-Host "`nThese hosts rejected key auth - likely need first-time bootstrap:" -ForegroundColor Yellow
  $needsBootstrap.Host | ForEach-Object { Write-Host "  $_" }
  Write-Host ("`nBootstrap with: .\sync-keys.ps1 -Interactive -Only {0}" -f ($needsBootstrap.Host -join ',')) -ForegroundColor Cyan
}
