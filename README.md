# Motte

Motte provides profiles for isolated development environments for agentic development with the [OpenCode](https://opencode.ai) coding agent.
Environments are isolated using [microsandbox](https://docs.microsandbox.dev) microVMs.

## Prerequisites

A `motte` binary (see [Releases](https://github.com/woefe/motte/releases), or build one yourself with [Go](https://go.dev) 1.26 or newer).
Motte reuses an already-installed microsandbox runtime and otherwise downloads its pinned `msb`/`libkrunfw` pair to `~/.microsandbox` on first start.
The microsandbox CLI (`msb`) itself is only needed for the one-offs below and for `task build-images`.
Building images locally also needs `podman` and [Task](https://taskfile.dev).

## Usage

```sh
motte base     # base profile
motte golang   # golang profile
motte rails    # rails profile
motte web      # web profile
```

This pulls the CI-built image, starts a microsandbox microVM, and launches the OpenCode TUI with the directory you launched motte from mounted read-write at `/workspace`.
Each directory has its own VM, named after a hash of that directory; the launcher prints the name it uses.
A directory's VM is reused across runs, so sessions and config on its root disk are kept; pass `--replace` to recreate the VM from scratch.
Add `--no-pull` to skip the registry pull so a locally loaded image can win.
The profiles are compiled into the binary; a profile image or egress policy change therefore goes through a rebuild rather than a config edit.

Useful one-offs (substitute the VM name the launcher printed):

```sh
# Verify the sandbox can reach everything it should (agent + llama /health)
msb exec <vm-name> -- check

# Continue a previous session
msb exec -t <vm-name> -- opencode

# Clean up
msb rm -f <vm-name>
```

## User network policies

Egress is deny-by-default with the built-in allow list; user config can widen it.
To allow additional hosts, create `~/.config/motte/<profile>.yaml`, or `~/.config/motte/common.yaml` to apply to every profile:

```yaml
network:
  allow:
    - "*.example.com"
```

Entries use the same [microsandbox CLI rule](https://docs.microsandbox.dev/cli/configuration) `TARGET[:PROTO[:PORTS]]` grammar as the built-in profiles and are appended (deduplicated) to them.
User config can only widen egress, never narrow it.
Only `network.allow` is accepted; unknown keys or invalid entries fail the launch, with the file path in the error.

## Images

CI rebuilds all images every Monday 04:00 UTC and on pushes touching `docker/**`.
Tags: `ghcr.io/woefe/motte/{base,golang,rails,web}:{latest,YYYY-MM-DD}` — pin a specific weekly build via the date tag; `latest` is the rolling tag.

**adopting a new weekly image**: images rebuild on schedule; run `motte <profile> --replace` to re-pull `:latest` and recreate the VM.

**building locally**: `task build-images` builds all images and loads them into the msb cache under the same `latest` refs the profiles reference; `task build-images name=golang` builds the base plus one variant.
Boot the local image with `motte <profile> --no-pull --replace`.
The local image shadows `latest` in the msb cache only until the next plain `motte <profile>` re-pulls GHCR, which restores the CI image.

## Default OpenCode inference providers
The default opencode config sets up a llama.cpp and OpenCode Go inference providers

### Local llama.cpp

A llama.cpp server on the host listening on port **9931
Make sure it is bound to an interface the sandbox gateway can reach, e.g. `--host 0.0.0.0`:

```sh
llama-server -m ./model.gguf --host 0.0.0.0 --port 9931
```

### OpenCode Go
The API key is injected via a **microsandbox secret** — the key's value never enters the VM, and it is never stored in plain by motte or microsandbox on the host.
Create the key at https://opencode.ai/console, then store it with:

```sh
motte secrets add
```

Enter `OPENCODE_GO_KEY` as the secret name; the prompts then ask for the scope, the allowed hosts, and the value (input hidden).
Allowed hosts default to `*.opencode.ai` for `OPENCODE_GO_KEY`.
Finally, launch the sandbox with `motte <profile>`.

## Secrets

Secret values live in the OS keychain, while motte's YAML configs and microsandbox's durable sandbox configs on the host only carry references.
Secret names are path-like with scopes, mirroring `~/.config/motte/secrets` on disk:

- `OPENCODE_GO_KEY` — global, injected into every profile's VM
- `golang/OPENCODE_GO_KEY` — profile-scoped, injected only into golang VMs
- `golang/<dir-hash>/OPENCODE_GO_KEY` — project scope, injected only in this directory's golang VMs

`motte secrets ls` prints the project hash of the current directory.
More specific configs shadow less specific ones by env var name, in project > profile > global precedence.

```sh
motte secrets add               # create a secret; prompts for name, scope, hosts, value
motte secrets set <name>        # (re)set the value; reads one line from stdin when piped
motte secrets configure <name>  # edit the secret's YAML in $VISUAL/$EDITOR (or nano/vi)
motte secrets rm <name> [-f]    # delete a secret's config and keychain value
motte secrets ls                # list secrets grouped by scope, with keychain presence
motte secrets mv <old> <new>    # rename; moves the config and re-keys the keychain value
```

A launch fails when a configured secret has no keychain value, with a hint to run `motte secrets set <name>`.
Launching with no secrets configured at all prints a hint to `motte secrets add OPENCODE_GO_KEY` instead.
The secrets' allowed hosts automatically extend the profile's egress allow list.
On the first launch after updating, existing VMs get their formerly built-in inline secret migrated to a keychain-backed reference, replacing the stored plaintext copy — a notice is printed.

Linux needs a Secret Service provider (gnome-keyring/KWallet, usually preinstalled on desktop environments); on headless setups or WSL without one, the launch fails when reading the keychain.
Keychain value sizes are limited (~4 KiB on macOS, ~2560 bytes on Windows Credential Manager), which `motte secrets add` and `set` warn about.
Values are never accepted as command-line arguments, since argv can be world-readable via `/proc`.

The alternative is the interactive `/connect` flow inside the TUI (credential stored in the sandbox's own root disk); the secret is preferred here because it keeps the key on the host — in the OS keychain, not in any host config.
