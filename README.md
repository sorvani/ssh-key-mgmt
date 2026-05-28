# ssh-key-mgmt

Personal toolkit for managing my SSH **public** keys across ~100 hosts (6
clients, each with a jump box and a fleet behind it) from a Windows
workstation.

## The idea

One file — [`canonical_authorized_keys`](canonical_authorized_keys) — is the
single source of truth for which keys may log in as me. Every sync
**replaces** the remote `~/.ssh/authorized_keys` with that exact set. There is
no merge step, so stale keys can't quietly accumulate: a key is authorized
*everywhere* or *nowhere*, depending solely on whether its line exists in the
canonical file.

Because the canonical file is plain public keys, it lives in this git repo
(not in `~/.ssh`). That gives you a full history of every key added and
retired — which is exactly the audit trail the "which keys do I still need?"
problem was missing.

```
ssh-key-mgmt/
  canonical_authorized_keys   <- source of truth (edit this)
  sync-keys.ps1               <- push canonical set to all/some hosts
  audit-host.ps1              <- read-only drift check for one host
  README.md
```

## How it works under the hood

- **Hosts come from `~/.ssh/config`.** `sync-keys.ps1` parses every `Host`
  alias (skipping `Host *` wildcards) and treats each as a target. Your
  existing `ProxyJump` directives mean hosts behind a jump box are addressed
  directly from Windows — no fan-out scripts on the jump boxes.
- **Skip-list.** Hosts that aren't POSIX `authorized_keys` targets (network
  gear, git hosts, appliances) are excluded via patterns in an **untracked**
  `skip-patterns.local` file, so real host aliases never enter git history.
  Copy `skip-patterns.example` to `skip-patterns.local` and edit it; if the
  file is absent, nothing is skipped.
- **Byte-exact transport.** The canonical file is normalized to LF, encoded
  UTF-8 (no BOM), base64'd, and carried as an SSH command argument (not piped
  through stdin). This avoids the classic Windows failure where CRLF or a BOM
  corrupts the remote key file.
- **Atomic, guarded write.** On the remote: write to `authorized_keys.new`,
  verify it decoded to **at least one valid key line**, then `mv` it over the
  live file. A dropped connection or empty/truncated transfer can never
  replace a good file with a broken one — you cannot lock yourself out.
- **`BatchMode=yes` by default** so password-only hosts fail fast instead of
  hanging. `StrictHostKeyChecking=accept-new` trusts a host on first contact
  but still fails loudly if a *known* host key changes.

## Daily workflow

```powershell
# 1. See what would happen (no connections made)
.\sync-keys.ps1 -DryRun

# 2. Push the canonical set everywhere
.\sync-keys.ps1
```

The run prints a status per host and a summary. Statuses:

| Status         | Meaning                                                        |
|----------------|----------------------------------------------------------------|
| `OK`           | authorized_keys replaced with the canonical set                |
| `NO_KEY_AUTH`  | reachable but key auth was refused -> needs bootstrap          |
| `UNREACHABLE`  | DNS/timeout/refused — host down or wrong address               |
| `REFUSED_EMPTY`| safety guard tripped (transfer had no valid keys) — file left untouched |
| `NO_BASE64`    | remote has no `base64` (e.g. not a normal Linux box)           |
| `ERROR`        | other remote failure (see Detail column)                       |

Scope a run with `-Only`, `-Exclude`, or `-Jump`:

```powershell
# -Only / -Exclude take -like wildcards (exact aliases also work)
.\sync-keys.ps1 -Only <client>-*           # every host named <client>-...
.\sync-keys.ps1 -Exclude *-pve*            # skip anything matching the pattern

# -Jump selects a jump box AND every host that proxies through it
.\sync-keys.ps1 -Jump <jump-box>                       # jump + everything behind it
.\sync-keys.ps1 -Jump <jump-box> -Exclude <jump-box>   # only what's behind it
```

`-Only`/`-Exclude`/`-Jump` combine as narrowing filters (e.g.
`-Jump <jump-box> -Only *-pbs` = just the PBS hosts behind that jump). Note
`-Jump` resolves membership from each host's `ProxyJump` line, so a host on the
same network that's addressed directly (no `ProxyJump`) won't be included by
`-Jump` — use a name wildcard with `-Only` to catch those.

## Retiring a key

1. Delete the key's line from `canonical_authorized_keys`.
2. Commit (`git commit -am "retire laptop key"`) — this is your audit record.
3. `.\sync-keys.ps1` — the key is gone from every reachable host on next push.

To confirm a specific host actually dropped it, run an audit (below).

## Bootstrapping a NEW host (first-time key install)

Hosts that don't have your key yet — typically internal boxes behind a jump
box that still accept password auth — will report `NO_KEY_AUTH` on a normal
run. Bootstrap them with `-Interactive` (allows the password prompt):

```powershell
.\sync-keys.ps1 -Interactive -Only new-host-alias
```

After the first successful push, key auth works and you never need
`-Interactive` for that host again. The end-of-run report prints the exact
bootstrap command for any host that needs it.

> New hosts are auto-trusted on first contact (`accept-new`). That's
> intentional for this fleet, but it does mean the *first* connection to a
> brand-new host implicitly trusts whatever host key it presents.

## Bootstrapping a NEW workstation

When you set up a new computer that should be allowed to log in as you:

1. Generate a key there: `ssh-keygen -t ed25519 -C "jbusch@new-box"`.
2. Add its **public** key as a new line in `canonical_authorized_keys`, with a
   `user@device-context` comment.
3. Commit and `.\sync-keys.ps1` from any workstation that already has access.

The new machine can log in everywhere as soon as the sync reaches each host.
(Clone this repo on the new box too, so it can drive syncs itself.)

## Auditing / spotting drift

`audit-host.ps1` is read-only — it fetches one host's live `authorized_keys`
and diffs the key material against the canonical file:

```powershell
.\audit-host.ps1 <host-alias>
```

Per-key status: `OK` (in both), `MISSING` (in canonical, not on host — host is
behind), `STALE` (on host, not in canonical — a sync would remove it). Use
this to verify a retirement actually propagated, or to inspect a host before
syncing.

## Comment convention

Each key line's comment (3rd field) is `user@device-context`, e.g.
`jbusch@win-workstation`. It's free-form to sshd but it's what you read when
auditing, so keep it meaningful. Lines starting with `#` are ignored.

## Known host caveats

Some classes of host in the config behave differently — watch for these:

- **Legacy-crypto boxes.** Hosts whose config forces `ssh-rsa`/`ssh-dss` +
  `3des-cbc` run an OpenSSH old enough that it may **not understand ed25519
  keys at all**. If one rejects the sync, add an RSA key to the canonical file
  for it (it'll just be ignored by modern hosts that prefer ed25519).
- **Typo'd addresses.** A host whose `Hostname` has an invalid octet (e.g. a
  mistyped IP) will show `UNREACHABLE` until corrected in `~/.ssh/config`.
- **User-in-hostname.** A `Hostname user@1.2.3.4` form is non-standard; if such
  a host misbehaves, move the user to its own `User` line.
- **Appliances (NAS, etc.).** These have `authorized_keys` but some lock down
  the home directory or disable key auth by default. If one reports
  `NO_KEY_AUTH` or `ERROR`, check its key-auth settings.

## Scope / non-goals

- Manages **only your own user's** `authorized_keys` (including the few hosts
  where "you" log in as `root`). Never touches shared or other users' files.
- No Ansible / orchestration — these aren't systems you own end-to-end.
- Private keys never enter this repo. Public keys only.
