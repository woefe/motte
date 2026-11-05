# Motte

Motte provides profiles for isolated development environments for agentic development with the [OpenCode](https://opencode.ai) coding agent.
Environments are isolated using [microsandbox](https://docs.microsandbox.dev) microVMs.

Motte is under active development.
Expect breaking changes in its commandline interface without a smooth migration path.

## Prerequisites

A `motte` binary (see [Releases](https://github.com/woefe/motte/releases), or build one yourself with [Go](https://go.dev) 1.26 or newer).
Motte reuses an already-installed microsandbox runtime and otherwise downloads its pinned `msb`/`libkrunfw` pair to `~/.microsandbox` on first start.
The microsandbox CLI (`msb`) itself is only needed for the one-offs below and for `task build-images`.
Building images locally also needs `podman` and [Task](https://taskfile.dev).

## Usage

```sh
motte opencode base # start the base profile
motte oc golang     # start the golang profile. `oc` is an alias of `opencode`
```

This pulls the CI-built image, starts a microsandbox microVM, and launches the OpenCode TUI with the directory you launched motte from mounted read-write at `/workspace`.
Each directory has its own VM, named after a hash of that directory; the launcher prints the name it uses.
A directory's VM is reused across runs, so sessions and config on its root disk are kept; pass `--replace` to recreate the VM from scratch.
Add `--no-pull` to skip the registry pull so a locally loaded image can win.
The profiles are compiled into the binary; a profile image change therefore goes through a rebuild rather than a config edit.

Useful one-offs (substitute the VM name the launcher printed):

```sh
# List microsandbox VMs
msb ls

# Verify the agent is installed
msb exec <vm-name> -- check

# Continue a previous session
msb exec -t <vm-name> -- opencode

# Clean up
msb rm -f <vm-name>
```

## User network policies

Egress is deny-by-default with the built-in allow list; user config can widen it.
Policies live in `~/.config/motte/policies`, one file per scope:

- `global.yaml` — applies to every profile
- `<profile>.yaml` — applies to that profile only
- `<hash>.yaml` — applies to the current directory, in every profile

```yaml
network:
  allow:
    - "*.example.com"
```

Entries use the same [microsandbox CLI rule](https://docs.microsandbox.dev/cli/configuration) `TARGET[:PROTO[:PORTS]]` grammar as the built-in profiles and are appended (deduplicated) to them.
User config can only widen egress, never narrow it.
Only `network.allow` is accepted; unknown keys or invalid entries fail the launch, with the file path in the error.

```sh
motte policies ls                    # list the policy files grouped by scope
motte policies configure global      # edit a scope's policy in $VISUAL/$EDITOR
motte policies configure golang      # a profile scope
motte policies configure project     # the current directory
motte policies configure <dir-hash>  # another directory's project policy
```

A missing scope file is created from a commented template before the editor opens.
The scope is `global`, `project`, a profile name, or a directory hash.

The network policy is part of the sandbox config, so it only lands on a newly created VM.
When a reused VM runs an older policy, the launch prints a notice; `--replace` recreates the VM with the current policy.

## Images

CI rebuilds all images every Monday 04:00 UTC and on pushes touching `docker/**`.
Tags: `ghcr.io/woefe/motte/{base,golang,rails,web}:{latest,YYYY-MM-DD}` — pin a specific weekly build via the date tag; `latest` is the rolling tag.

**adopting a new weekly image**: images rebuild on schedule; run `motte oc <profile> --replace` to re-pull `:latest` and recreate the VM.

**building locally**: `task build-images` builds all images and loads them into the msb cache under the same `latest` refs the profiles reference; `task build-images name=golang` builds the base plus one variant.
Boot the local image with `motte oc <profile> --no-pull --replace`.
The local image shadows `latest` in the msb cache only until the next plain `motte oc <profile>` re-pulls GHCR, which restores the CI image.

## OpenCode config

Motte mounts `~/.config/motte/opencode` read-only at `/etc/opencode` in every VM, so its `opencode.json` is the OpenCode config of all your sandboxes.
On the first launch, motte creates a minimal `opencode.json` there.
Edits apply the next time OpenCode starts in the VM.
VMs created before motte mounted this directory need a one-time `--replace`.

Reference API keys in `opencode.json` as `{env:NAME}` and store their values with `motte secrets add` (see [Secrets](#secrets)).
[docs/PROVIDERS.md](docs/PROVIDERS.md) shows how to connect a providers without placing API keys into the VM.

## Secrets

Secret values live in the OS keychain, while motte's YAML configs and microsandbox's durable sandbox configs on the host only carry references.
Secret names are path-like with scopes, and the settings of a scope live in one file under `~/.config/motte/secrets`:

- `EXAMPLE_API_KEY` — global, injected into every profile's VM
- `golang/EXAMPLE_API_KEY` — profile-scoped, injected only into golang VMs
- `<dir-hash>/EXAMPLE_API_KEY` — project scope, injected into every profile's VM in this directory

The scope files are `global.yaml`, `<profile>.yaml`, and `<dir-hash>.yaml`:

```yaml
secrets:
  EXAMPLE_API_KEY:
    allow:
      - "api.example.com"
```

Both `ls` commands list only the scopes that have a file, and mark the current directory's project scope.
More specific configs shadow less specific ones by env var name, in project > profile > global precedence.

```sh
motte secrets add               # create or change a secret; prompts for name, scope, hosts, value
motte secrets set <name>        # (re)set the value; reads one line from stdin when piped
motte secrets configure <scope> # edit a scope's YAML in $VISUAL/$EDITOR (or nano/vi)
motte secrets rm <name> [-f]    # delete the secret's config and keychain value
motte secrets ls                # list secrets grouped by scope, with keychain presence
```

A missing scope file is created from a commented template before the editor opens.
The scope is `global`, `project`, a profile name, or a directory hash.
Running `motte secrets add` on an existing secret keeps its settings as prompt defaults and asks whether to replace the keychain value.

A launch fails when a configured secret has no keychain value, with a hint to run `motte secrets set <name>`.
Launching with no secrets configured at all prints a hint to `motte secrets add` instead.
The secrets' allowed hosts automatically extend the profile's egress allow list.
On the first launch after updating, existing VMs get their formerly built-in inline secret migrated to a keychain-backed reference, replacing the stored plaintext copy — a notice is printed.

Linux needs a Secret Service provider (gnome-keyring/KWallet, usually preinstalled on desktop environments); on headless setups or WSL without one, the launch fails when reading the keychain.
Keychain value sizes are limited (~4 KiB on macOS, ~2560 bytes on Windows Credential Manager), which `motte secrets add` and `set` warn about.
Values are never accepted as command-line arguments, since argv can be world-readable via `/proc`.

The alternative is the interactive `/connect` flow inside the TUI (credential stored in the sandbox's own root disk); the secret is preferred here because it keeps the key on the host — in the OS keychain, not in any host config.
