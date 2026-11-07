# Motte

Motte provides isolated development environments for agentic development with the [OpenCode](https://opencode.ai) coding agent.
Environments are isolated using [microsandbox](https://docs.microsandbox.dev) microVMs.

Motte is under active development.
Expect breaking changes in its commandline interface without a smooth migration path.

## Prerequisites

A `motte` binary (see [Releases](https://github.com/woefe/motte/releases), or build one yourself with [Go](https://go.dev) 1.26 or newer).
Motte reuses an already-installed microsandbox runtime and otherwise downloads its pinned `msb`/`libkrunfw` pair to `~/.microsandbox` on first start.
The microsandbox CLI (`msb`) itself is only needed for the one-offs below and for `task build-images`.
Building images locally also needs `podman` and [Task](https://taskfile.dev).

## Usage

Initialize a project in your repository directory and launch OpenCode:

```sh
motte init # configure this directory's image, policy groups, and secrets
motte oc   # start the sandbox and attach the OpenCode TUI (`oc` is an alias of `opencode`)
```

`motte init` prompts for an image preset (`base`, `golang`, `rails`, `web` — defaulting to the detected toolchain in the directory), the user policy groups to include, and the secrets to inject, then writes `~/.config/motte/projects/<dir-hash>.yaml`:

```yaml
# motte project
# Project path: /home/you/src/motte
image: ghcr.io/woefe/motte/golang:latest
network:
  allow:
    - "*.internal.example.com"
  allowGroups:
    - work-vpn
secrets:
  - EXAMPLE_API_KEY
```

Re-running `motte init` pre-fills its prompts from the existing project config.
You can also hand-edit the project YAML to set a custom image reference or add project-specific `network.allow` entries.

`motte opencode` (or `motte oc`) pulls the configured image, starts a microsandbox microVM, and launches the OpenCode TUI with the current directory mounted read-write at `/workspace`.
Each directory has its own VM named `motte-<dir-hash>`; the launcher prints the name it uses.
A directory's VM is reused across runs, so sessions and packages on its root disk are kept; pass `--replace` to recreate the VM from scratch.
Add `--no-pull` to skip the registry pull so a locally loaded image can win.

Useful one-offs (substitute the VM name `motte-<dir-hash>` the launcher printed):

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

Egress is deny-by-default with the always-on base allow list; user policy groups and project `network.allow` entries widen it.
Reusable policy groups live in `~/.config/motte/policies/<group>.yaml`, one file per group:

```yaml
# motte policy group — work-vpn
allow:
  - "*.corp.example.com"
```

Entries use the [microsandbox CLI rule](https://docs.microsandbox.dev/cli/configuration) `TARGET[:PROTO[:PORTS]]` grammar.
The effective egress allow list for a project is the always-on base policy plus the entries of every group in `network.allowGroups` plus the project's `network.allow`, deduplicated.
User config can only widen egress, never narrow the base policy.
Unknown keys, missing groups, or invalid entries fail the launch with the file path in the error.

```sh
motte policies ls                   # list the policy groups and this project's effective network policy
motte policies configure work-vpn   # create or edit a user policy group in $VISUAL/$EDITOR
```

A missing group file is created from a commented template before the editor opens.
The group name is a slug (lowercase letters, digits, and dashes).

The image and network policy are part of the sandbox config, so changes only land on a newly created VM.
When a reused VM runs an older image or policy, the launch prints a warning; `--replace` recreates the VM with the current configuration.

## Images

CI rebuilds all built-in preset images every Monday 04:00 UTC and on pushes touching `docker/**`.
Tags: `ghcr.io/woefe/motte/{base,golang,rails,web}:{latest,YYYY-MM-DD}` — pin a specific weekly build via the date tag; `latest` is the rolling tag.

**adopting a new weekly image**: images rebuild on schedule; run `motte oc --replace` to re-pull `:latest` and recreate the VM.

**building locally**: `task build-images` builds all images and loads them into the msb cache under the same `latest` refs the presets reference; `task build-images name=golang` builds the base plus one variant.
Boot the local image with `motte oc --no-pull --replace`.
The local image shadows `latest` in the msb cache only until the next plain `motte oc` re-pulls GHCR, which restores the CI image.

## OpenCode config

Motte mounts `~/.config/motte/opencode` read-only at `/etc/opencode` in every VM, so its `opencode.json` is the OpenCode config of all your sandboxes.
On the first launch, motte creates a minimal `opencode.json` there.
Edits apply the next time OpenCode starts in the VM.

Reference API keys in `opencode.json` as `{env:NAME}` and store their values with `motte secrets add` (see [Secrets](#secrets)).
[docs/PROVIDERS.md](docs/PROVIDERS.md) shows how to connect providers without placing API keys into the VM.

## Secrets

Secret values live in the OS keychain, while motte's YAML configs and microsandbox's durable sandbox configs on the host only carry references.
Each secret's settings live in `~/.config/motte/secrets/<NAME>.yaml`:

```yaml
# motte secret — EXAMPLE_API_KEY
# Value lives in the OS keychain; set it with `motte secrets set EXAMPLE_API_KEY`.
allow:
  - "api.example.com"
header_fields:
  - "authorization"
  - "x-api-key"
```

The secret name must be a valid environment variable name and is used as the filename and keychain account.
Projects select which secrets to inject via the `secrets` list in `~/.config/motte/projects/<dir-hash>.yaml` (`motte init` defaults to all configured secrets).

```sh
motte secrets add               # create or change a secret; prompts for name, hosts, and value
motte secrets set <name>        # (re)set a secret's keychain value; reads one line from stdin when piped
motte secrets configure <name>  # create or edit one secret's settings in $VISUAL/$EDITOR
motte secrets rm <name> [-f]    # delete a secret's settings file and keychain value
motte secrets ls                # list the secrets with keychain presence
```

Running `motte secrets add` on an existing secret keeps its settings as prompt defaults and asks whether to replace the keychain value.

A launch fails when a selected secret has no settings file (with a hint to run `motte secrets add`) or no keychain value (with a hint to run `motte secrets set <name>`).
A secret's `allow` hosts only govern credential substitution into HTTP headers (`authorization` and `x-api-key` by default) and do not automatically widen the network egress allow list; allow egress separately via the base policy, a policy group, or the project's `network.allow`.

Linux needs a Secret Service provider (gnome-keyring/KWallet, usually preinstalled on desktop environments); on headless setups or WSL without one, the launch fails when reading the keychain.
Keychain value sizes are limited (~4 KiB on macOS, ~2560 bytes on Windows Credential Manager), which `motte secrets add` and `set` warn about.
Values are never accepted as command-line arguments, since argv can be world-readable via `/proc`.

The (not recommended) alternative is the interactive `/connect` flow inside the OpenCode TUI, which will store the credential *inside* sandbox.
